"""Gateway / backend: recebe telemetria assinada dos ESP32, decide comandos, monitora o tráfego
e serve o dashboard.

Endpoints
  POST /telemetry        corpo JSON + cabeçalho X-Signature (HMAC-SHA256 hex).
                         401 assinatura inválida, 409 replay, 429 IP bloqueado pelo monitor.
  GET  /control?node=S1  comando assinado para o nó (relé do ventilador).
  GET  /api/telemetry    últimas leituras e contadores de segurança (somente leitura).
  GET  /api/alerts       alertas do monitor de tráfego, IPs bloqueados e maiores emissores.
  GET  /api/results      resultados do experimento (results/results.json).
  GET  /healthz          verificação de saúde (nuvem).
  GET  /                 dashboard.
Não existe endpoint sem autenticação que acione o atuador (ver ADR-0004).

Uso local : PURA_SECRET=<16+ caracteres> python -m pura.server --port 8000
Anti-replay temporal (VULN-006): PURA_REQUIRE_TS=1 exige o campo `ts` assinado (epoch) dentro de
            PURA_TS_WINDOW_S segundos (padrão 120). Use na nuvem, onde o firmware tem NTP (modo https).
Na nuvem  : a porta vem de $PORT; atrás de proxy TLS defina TRUST_PROXY=1 e PROXY_HOPS (nº de proxies
            confiáveis, padrão 1). O IP do cliente é o PROXY_HOPS-ésimo valor de X-Forwarded-For a partir do fim.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from .monitor import TrafficMonitor
from .security import DEFAULT_TS_WINDOW_S, ReplayGuard, WeakSecretError, load_secret, sign, timestamp_ok, verify

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_BODY = 2048
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": ("default-src 'self'; style-src 'unsafe-inline'; "
                                "script-src 'unsafe-inline'; img-src 'self' data:"),
}


class FanPolicy:
    """Política com histerese executada no gateway (o ESP32 tem fail-safe local)."""

    def __init__(self, ppm_on=1000.0, ppm_off=800.0, t_on=30.0, t_off=28.0) -> None:
        self.ppm_on, self.ppm_off, self.t_on, self.t_off = ppm_on, ppm_off, t_on, t_off
        self.fan: Dict[str, bool] = {}
        self.cseq: Dict[str, int] = {}

    def update(self, node: str, ppm, temp) -> None:
        cur = self.fan.get(node, False)
        hi = (ppm is not None and ppm >= self.ppm_on) or (temp is not None and temp >= self.t_on)
        lo = (ppm is None or ppm <= self.ppm_off) and (temp is None or temp <= self.t_off)
        new = True if (not cur and hi) else (False if (cur and lo) else cur)
        if new != cur or node not in self.cseq:
            self.cseq[node] = max(self.cseq.get(node, 0) + 1, int(time.time()))
        self.fan[node] = new


class State:
    def __init__(self, secret: Optional[bytes] = None, monitor: Optional[TrafficMonitor] = None,
                 traffic_log: Optional[str] = None) -> None:
        self.secret = secret or load_secret()
        self.replay = ReplayGuard()
        self.policy = FanPolicy()
        self.monitor = monitor or TrafficMonitor()
        self.samples = deque(maxlen=600)
        self.counters = {"accepted": 0, "bad_signature": 0, "replay": 0, "bad_request": 0}
        self.traffic_log = traffic_log
        self.lock = threading.Lock()

    def log_traffic(self, ip: str, outcome: str, node: str, size: int) -> None:
        self.monitor.record(ip, outcome, node, size)
        if self.traffic_log:
            with open(self.traffic_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": time.time(), "ip": ip, "outcome": outcome,
                                     "node": node, "size": size}) + "\n")


def make_handler(state: State):
    trust_proxy = os.environ.get("TRUST_PROXY") == "1"
    try:
        proxy_hops = max(1, int(os.environ.get("PROXY_HOPS", "1")))
    except ValueError:
        proxy_hops = 1

    require_ts = os.environ.get("PURA_REQUIRE_TS") == "1"
    try:
        ts_window = float(os.environ.get("PURA_TS_WINDOW_S", DEFAULT_TS_WINDOW_S))
    except ValueError:
        ts_window = float(DEFAULT_TS_WINDOW_S)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silencioso
            pass

        def _ip(self) -> str:
            # VULN-005: o proxy ACRESCENTA o IP real ao fim de X-Forwarded-For; o início da lista é
            # controlado pelo cliente e pode ser forjado. Por isso usamos o N-ésimo valor a partir do fim.
            if trust_proxy:
                parts = [p.strip() for p in self.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
                if len(parts) >= proxy_hops:
                    return parts[-proxy_hops]
            return self.client_address[0]

        def _send(self, code: int, body: bytes, ctype="application/json", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj, extra=None):
            self._send(code, json.dumps(obj).encode(), extra=extra)

        def _reject(self, code: int, outcome: str, msg: str, ip: str, size: int = 0, node: str = ""):
            with state.lock:
                state.counters[outcome] = state.counters.get(outcome, 0) + 1
            state.log_traffic(ip, outcome, node, size)
            self._json(code, {"error": msg})

        def do_POST(self):
            ip = self._ip()
            if state.monitor.is_blocked(ip):                     # mitigação automática
                state.monitor.record(ip, "blocked")
                return self._json(429, {"error": "ip bloqueado temporariamente"})
            if urlparse(self.path).path != "/telemetry":
                return self._json(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n <= 0 or n > MAX_BODY:
                return self._reject(400, "bad_request", "tamanho invalido", ip)
            body = self.rfile.read(n)
            if not verify(state.secret, body, self.headers.get("X-Signature", "")):
                return self._reject(401, "bad_signature", "assinatura invalida", ip, n)
            try:
                d = json.loads(body)
                node, boot, seq = str(d["node"]), int(d["boot"]), int(d["seq"])
            except (ValueError, KeyError, TypeError):
                return self._reject(400, "bad_request", "json invalido", ip, n)
            if not timestamp_ok(d.get("ts"), time.time(), require_ts, ts_window):
                return self._reject(409, "replay", "timestamp ausente ou fora da janela", ip, n, node)
            if not state.replay.accept(node, boot, seq):
                return self._reject(409, "replay", "replay", ip, n, node)
            with state.lock:
                state.counters["accepted"] += 1
                d["rx"] = time.time()
                state.samples.append(d)
                state.policy.update(node, d.get("ppm"), d.get("t"))
            state.log_traffic(ip, "accepted", node, n)
            self._json(200, {"ok": True})

        def do_GET(self):
            ip = self._ip()
            u = urlparse(self.path)
            if u.path == "/healthz":
                return self._json(200, {"status": "ok"})
            if state.monitor.is_blocked(ip):
                state.monitor.record(ip, "blocked")
                return self._json(429, {"error": "ip bloqueado temporariamente"})
            if u.path == "/control":
                node = parse_qs(u.query).get("node", [""])[0]
                state.monitor.record(ip, "control", node)
                with state.lock:
                    cmd = {"node": node, "fan": state.policy.fan.get(node, False),
                           "cseq": state.policy.cseq.get(node, 0)}
                body = json.dumps(cmd, separators=(",", ":")).encode()
                return self._send(200, body, extra={"X-Signature": sign(state.secret, body)})
            if u.path == "/api/telemetry":
                with state.lock:
                    return self._json(200, {"samples": list(state.samples)[-300:],
                                            "counters": dict(state.counters),
                                            "fan": dict(state.policy.fan)})
            if u.path == "/api/alerts":
                state.monitor.check_silence()
                return self._json(200, state.monitor.snapshot())
            if u.path == "/api/results":
                p = os.path.join(ROOT, "results", "results.json")
                if os.path.exists(p):
                    with open(p, "rb") as fh:
                        return self._send(200, fh.read())
                return self._json(404, {"error": "rode: python -m pura.experiments"})
            if u.path in ("/", "/index.html"):
                with open(os.path.join(ROOT, "web", "index.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            if u.path in ("/comparacao.png", "/serie_temporal.png"):
                with open(os.path.join(ROOT, "results", u.path[1:]), "rb") as fh:
                    return self._send(200, fh.read(), "image/png")
            self._json(404, {"error": "not found"})

    return Handler


def make_server(host="localhost", port=8000, state: Optional[State] = None):
    state = state or State()
    return ThreadingHTTPServer((host, port), make_handler(state)), state


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--traffic-log", default=None, help="grava eventos de tráfego em JSONL")
    a = ap.parse_args()
    try:
        state = State(traffic_log=a.traffic_log)
    except WeakSecretError as exc:
        raise SystemExit(f"ERRO: {exc}")
    srv, _ = make_server(a.host, a.port, state)
    print(f"Gateway em http://{a.host}:{a.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")

if __name__ == "__main__":
    main()
