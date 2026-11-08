"""Gateway do P.U.R.A.: telemetria HMAC, comando autenticado e dashboard protegido."""
from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import hmac
import json
import math
import os
import re
import socket
import sys
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .monitor import TrafficMonitor
from .security import (DEFAULT_TS_WINDOW_S, ReplayCapacityError, ReplayGuard, WeakSecretError,
                       load_secret, sign, timestamp_ok, verify)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_BODY = 2048
MAX_UINT32 = (1 << 32) - 1
MAX_NODE_ID = 64
MAX_CONCURRENT_REQUESTS = 32
REQUEST_TIMEOUT_S = 5.0
DEFAULT_TRAFFIC_LOG_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_TRAFFIC_LOG_BACKUPS = 3
MAX_TRAFFIC_LOG_BACKUPS = 10
MAX_POLICY_NODES = 1024
NODE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
NONCE_RE = re.compile(r"^[0-9a-fA-F]{16}$")
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": ("default-src 'self'; style-src 'unsafe-inline'; "
                                "script-src 'unsafe-inline'; img-src 'self' data:"),
}


class FanPolicy:
    """Armazena o estado físico reportado e os overrides remotos por nó.

    A decisão automática pertence ao ESP32. O gateway apenas guarda comandos
    manuais solicitados pelo dashboard e os devolve autenticados ao dispositivo.
    """

    def __init__(self, max_nodes: int = MAX_POLICY_NODES) -> None:
        if max_nodes < 1:
            raise ValueError("max_nodes deve ser >= 1")
        self.max_nodes = max_nodes
        self.fan: OrderedDict[str, bool] = OrderedDict()  # último estado físico reportado
        self.cseq: OrderedDict[str, int] = OrderedDict()
        self.overrides: OrderedDict[str, bool] = OrderedDict()  # nó presente = modo manual

    def update(self, node: str, ppm=None, temp=None, reported_fan=None) -> None:
        """Registra o estado físico recebido; não calcula política automática no servidor."""
        if node not in self.fan and len(self.fan) >= self.max_nodes:
            old_node, _ = self.fan.popitem(last=False)
            self.cseq.pop(old_node, None)
            self.overrides.pop(old_node, None)
        elif node in self.fan:
            self.fan.move_to_end(node)
            self.cseq.move_to_end(node, last=True)

        if isinstance(reported_fan, bool):
            self.fan[node] = reported_fan
        else:
            self.fan.setdefault(node, False)
        self.fan.move_to_end(node)
        self.cseq.setdefault(node, 0)
        self.cseq.move_to_end(node)
        if node in self.overrides:
            self.overrides.move_to_end(node)

    def set_manual(self, node: str, fan_on: bool) -> None:
        if node not in self.fan:
            raise KeyError(node)
        self.overrides[node] = bool(fan_on)
        self.overrides.move_to_end(node)

    def set_auto(self, node: str) -> None:
        if node not in self.fan:
            raise KeyError(node)
        self.overrides.pop(node, None)

    def mode(self, node: str) -> str:
        return "manual" if node in self.overrides else "auto"

    def target(self, node: str) -> bool:
        """Comando efetivo: override manual ou estado físico atual em modo automático."""
        return self.overrides[node] if node in self.overrides else self.fan.get(node, False)

    def modes(self) -> dict[str, str]:
        return {node: self.mode(node) for node in self.fan}

    def targets(self) -> dict[str, bool]:
        return {node: self.target(node) for node in self.fan}

    def next_command_seq(self, node: str) -> Optional[int]:
        """Incrementa a versão da resposta autenticada entregue ao nó."""
        if node not in self.fan:
            return None
        value = self.cseq.get(node, 0) + 1
        self.cseq[node] = value
        self.cseq.move_to_end(node)
        return value


class State:
    def __init__(self, secret: Optional[bytes] = None, monitor: Optional[TrafficMonitor] = None,
                 traffic_log: Optional[str] = None,
                 traffic_log_max_bytes: int = DEFAULT_TRAFFIC_LOG_MAX_BYTES,
                 traffic_log_backups: int = DEFAULT_TRAFFIC_LOG_BACKUPS) -> None:
        if traffic_log_max_bytes < 1024:
            raise ValueError("traffic_log_max_bytes deve ser >= 1024")
        if not 0 <= traffic_log_backups <= MAX_TRAFFIC_LOG_BACKUPS:
            raise ValueError(f"traffic_log_backups deve estar entre 0 e {MAX_TRAFFIC_LOG_BACKUPS}")
        self.secret = secret or load_secret()
        self.replay = ReplayGuard()
        self.policy = FanPolicy()
        self.monitor = monitor or TrafficMonitor()
        self.samples = deque(maxlen=600)
        self.counters = {"accepted": 0, "bad_signature": 0, "replay": 0,
                         "bad_request": 0, "capacity_rejected": 0}
        self.traffic_log = traffic_log
        self.traffic_log_max_bytes = traffic_log_max_bytes
        self.traffic_log_backups = traffic_log_backups
        self._traffic_log_lock = threading.Lock()
        self._traffic_log_failed = False
        self.lock = threading.Lock()

    def _trim_rotated_log(self, path: str) -> None:
        """Mantém somente registros completos do fim de um log legado acima do limite."""
        size = os.path.getsize(path)
        if size <= self.traffic_log_max_bytes:
            return
        with open(path, "rb") as fh:
            fh.seek(-self.traffic_log_max_bytes, os.SEEK_END)
            tail = fh.read(self.traffic_log_max_bytes)
        newline = tail.find(b"\n")
        tail = tail[newline + 1:] if newline >= 0 else b""
        with open(path, "wb") as fh:
            fh.write(tail)

    def _rotate_traffic_log(self) -> None:
        path = self.traffic_log
        if not path or not os.path.exists(path):
            return
        if self.traffic_log_backups == 0:
            os.remove(path)
            return
        for index in range(self.traffic_log_backups, 0, -1):
            source = path if index == 1 else f"{path}.{index - 1}"
            destination = f"{path}.{index}"
            if os.path.exists(destination):
                os.remove(destination)
            if os.path.exists(source):
                os.replace(source, destination)
                self._trim_rotated_log(destination)

    def log_traffic(self, ip: str, outcome: str, node: str = "", size: int = 0) -> None:
        self.monitor.record(ip, outcome, node, size)
        if not self.traffic_log or self._traffic_log_failed:
            return
        record = {
            "ts": time.time(), "ip": str(ip)[:64], "outcome": str(outcome)[:32],
            "node": str(node)[:64], "size": min(MAX_BODY, max(0, int(size))),
        }
        payload = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        with self._traffic_log_lock:
            if self._traffic_log_failed:
                return
            try:
                folder = os.path.dirname(os.path.abspath(self.traffic_log))
                os.makedirs(folder, exist_ok=True)
                current_size = os.path.getsize(self.traffic_log) if os.path.exists(self.traffic_log) else 0
                if current_size + len(payload) > self.traffic_log_max_bytes:
                    self._rotate_traffic_log()
                with open(self.traffic_log, "ab") as fh:
                    fh.write(payload)
            except OSError as exc:
                self._traffic_log_failed = True
                print(f"AVISO: logging de tráfego desativado após erro de I/O: {exc}", file=sys.stderr)


def _is_loopback_bind(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _numeric(value, minimum: float, maximum: float, *, nullable: bool = True) -> bool:
    if value is None:
        return nullable
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(float(value)) and minimum <= float(value) <= maximum


def _validate_telemetry(data) -> tuple[str, int, int]:
    if not isinstance(data, dict):
        raise ValueError("corpo deve ser um objeto JSON")
    node = data.get("node")
    boot = data.get("boot")
    seq = data.get("seq")
    if not isinstance(node, str) or not NODE_ID_RE.fullmatch(node):
        raise ValueError("node inválido")
    for name, value in (("boot", boot), ("seq", seq)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_UINT32:
            raise ValueError(f"{name} deve ser inteiro uint32")
    if seq == 0:
        raise ValueError("seq deve ser maior que zero")
    if not _numeric(data.get("t"), -40.0, 125.0):
        raise ValueError("t fora do tipo ou intervalo permitido")
    if not _numeric(data.get("h"), 0.0, 100.0):
        raise ValueError("h fora do tipo ou intervalo permitido")
    if not _numeric(data.get("ppm"), 0.0, 10000.0):
        raise ValueError("ppm fora do tipo ou intervalo permitido")
    if "fan" in data and not isinstance(data["fan"], bool):
        raise ValueError("fan deve ser booleano")
    if "rssi" in data and not _numeric(data["rssi"], -127.0, 0.0, nullable=False):
        raise ValueError("rssi fora do tipo ou intervalo permitido")
    return node, boot, seq


def make_handler(state: State):
    trust_proxy = os.environ.get("TRUST_PROXY") == "1"
    proxy_hops = max(1, int(os.environ.get("PROXY_HOPS", "1")))
    trusted_proxy_nets = []
    if trust_proxy:
        cidrs = os.environ.get("PURA_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
        try:
            trusted_proxy_nets = [ipaddress.ip_network(item.strip(), strict=False)
                                  for item in cidrs.split(",") if item.strip()]
        except ValueError as exc:
            raise ValueError(f"PURA_TRUSTED_PROXY_CIDRS inválido: {exc}") from exc
        if not trusted_proxy_nets:
            raise ValueError("TRUST_PROXY=1 exige PURA_TRUSTED_PROXY_CIDRS")

    require_ts = os.environ.get("PURA_REQUIRE_TS") == "1"
    try:
        ts_window = float(os.environ.get("PURA_TS_WINDOW_S", DEFAULT_TS_WINDOW_S))
    except ValueError:
        ts_window = float(DEFAULT_TS_WINDOW_S)
    if not math.isfinite(ts_window) or ts_window <= 0:
        raise ValueError("PURA_TS_WINDOW_S deve ser positivo e finito")

    dashboard_user = os.environ.get("PURA_DASHBOARD_USER", "pura")
    dashboard_password = os.environ.get("PURA_DASHBOARD_PASSWORD", "")
    if dashboard_password and len(dashboard_password) < 16:
        raise ValueError("PURA_DASHBOARD_PASSWORD deve ter pelo menos 16 caracteres")
    if not dashboard_user or ":" in dashboard_user:
        raise ValueError("PURA_DASHBOARD_USER deve ser não vazio e não pode conter ':'")
    dashboard_paths = ("/", "/index.html", "/api/telemetry", "/api/alerts", "/api/results", "/api/fan",
                       "/comparacao.png", "/serie_temporal.png")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(REQUEST_TIMEOUT_S)

        def log_message(self, *args):
            pass

        def _ip(self) -> str:
            peer = self.client_address[0]
            if not trust_proxy:
                return peer[:64]
            try:
                peer_ip = ipaddress.ip_address(peer.split("%", 1)[0])
            except ValueError:
                return peer[:64]
            if not any(peer_ip in net for net in trusted_proxy_nets):
                return peer[:64]
            raw = self.headers.get("X-Forwarded-For", "")
            parts = [part.strip() for part in raw.split(",") if part.strip()]
            if len(parts) < proxy_hops or len(parts) > 10:
                return peer[:64]
            try:
                parsed = [ipaddress.ip_address(part) for part in parts]
            except ValueError:
                return peer[:64]
            return str(parsed[-proxy_hops])[:64]

        def _send(self, code: int, body: bytes, ctype="application/json", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                self.close_connection = True

        def _json(self, code: int, obj, extra=None):
            self._send(code, json.dumps(obj, allow_nan=False).encode(), extra=extra)

        def _record(self, ip: str, outcome: str, node: str = "", size: int = 0):
            state.log_traffic(ip, outcome, node, size)

        def _dashboard_authorized(self) -> bool:
            if not dashboard_password:
                return True
            raw = self.headers.get("Authorization", "")
            try:
                scheme, encoded = raw.split(" ", 1)
                if scheme.lower() != "basic":
                    return False
                decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
                username, password = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError, binascii.Error):
                return False
            return bool(password and
                        hmac.compare_digest(username.encode(), dashboard_user.encode()) and
                        hmac.compare_digest(password.encode(), dashboard_password.encode()))

        def _require_dashboard_auth(self) -> bool:
            if self._dashboard_authorized():
                return True
            self._json(401, {"error": "autenticação necessária"},
                       extra={"WWW-Authenticate": 'Basic realm="PURA Dashboard", charset="UTF-8"'})
            return False

        def _reject(self, code: int, outcome: str, msg: str, ip: str, size: int = 0, node: str = ""):
            with state.lock:
                state.counters[outcome] = state.counters.get(outcome, 0) + 1
            self._record(ip, outcome, node, size)
            self._json(code, {"error": msg}, extra={"Connection": "close"} if code == 400 else None)
            if code == 400:
                self.close_connection = True

        def _post_fan_command(self, ip: str):
            """Recebe comando do dashboard autenticado; o ESP32 continua dono do controle local."""
            if not self._require_dashboard_auth():
                self._record(ip, "unauthorized")
                return

            # Duas proteções contra CSRF: cabeçalho não permitido em formulários simples
            # e Origin obrigatório com o mesmo host que serviu o dashboard.
            origin = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            parsed_origin = urlparse(origin)
            if (self.headers.get("X-PURA-Action") != "fan-control" or
                    parsed_origin.netloc.lower() != host.lower() or
                    parsed_origin.scheme not in ("http", "https")):
                self._record(ip, "bad_request")
                return self._json(403, {"error": "origem ou cabeçalho de ação inválido"})

            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                self._record(ip, "bad_request")
                return self._json(415, {"error": "Content-Type deve ser application/json"})
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                self._record(ip, "bad_request")
                return self._json(400, {"error": "Content-Length inválido"})
            try:
                size = int(lengths[0])
            except (ValueError, TypeError):
                size = 0
            if size <= 0 or size > 512:
                self._record(ip, "bad_request")
                return self._json(400, {"error": "tamanho inválido"})
            try:
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("corpo incompleto")
                data = json.loads(raw)
            except (OSError, socket.timeout, ValueError, json.JSONDecodeError):
                self.close_connection = True
                self._record(ip, "bad_request")
                return self._json(400, {"error": "JSON inválido ou incompleto"})

            if not isinstance(data, dict):
                self._record(ip, "bad_request")
                return self._json(400, {"error": "corpo deve ser um objeto JSON"})
            node = data.get("node")
            mode = data.get("mode")
            if not isinstance(node, str) or not NODE_ID_RE.fullmatch(node):
                self._record(ip, "bad_request")
                return self._json(400, {"error": "node inválido"})
            if mode == "manual":
                fan_on = data.get("fan")
                if not isinstance(fan_on, bool):
                    self._record(ip, "bad_request", node)
                    return self._json(400, {"error": "modo manual exige fan booleano"})
            elif mode == "auto":
                if "fan" in data:
                    self._record(ip, "bad_request", node)
                    return self._json(400, {"error": "modo automático não aceita fan"})
                fan_on = None
            else:
                self._record(ip, "bad_request", node)
                return self._json(400, {"error": "mode deve ser manual ou auto"})

            with state.lock:
                if node not in state.policy.fan:
                    self._record(ip, "unknown_node", node, size)
                    return self._json(404, {"error": "ESP32 ainda não enviou telemetria"})
                if mode == "manual":
                    state.policy.set_manual(node, fan_on)
                else:
                    state.policy.set_auto(node)
                response = {"ok": True, "node": node, "mode": state.policy.mode(node),
                            "fan": state.policy.target(node)}
            self._record(ip, "command_accepted", node, size)
            return self._json(200, response, extra={"Cache-Control": "no-store"})

        def do_POST(self):
            ip = self._ip()
            if state.monitor.is_blocked(ip):
                self._record(ip, "blocked")
                self.close_connection = True
                return self._json(429, {"error": "ip bloqueado temporariamente"},
                                  extra={"Connection": "close"})
            if urlparse(self.path).path == "/api/fan":
                return self._post_fan_command(ip)
            if urlparse(self.path).path != "/telemetry":
                self._record(ip, "other")
                self.close_connection = True
                return self._json(404, {"error": "not found"}, extra={"Connection": "close"})
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                return self._reject(400, "bad_request", "Content-Length inválido", ip)
            try:
                n = int(lengths[0])
            except (ValueError, TypeError):
                n = 0
            if n <= 0 or n > MAX_BODY:
                return self._reject(400, "bad_request", "tamanho inválido", ip)
            try:
                body = self.rfile.read(n)
            except (OSError, socket.timeout):
                self.close_connection = True
                return self._reject(400, "bad_request", "corpo incompleto", ip, n)
            if len(body) != n:
                self.close_connection = True
                return self._reject(400, "bad_request", "corpo incompleto", ip, n)
            if not verify(state.secret, body, self.headers.get("X-Signature", "")):
                return self._reject(401, "bad_signature", "assinatura inválida", ip, n)
            try:
                data = json.loads(body)
                node, boot, seq = _validate_telemetry(data)
            except (ValueError, TypeError, json.JSONDecodeError):
                return self._reject(400, "bad_request", "JSON ou campos inválidos", ip, n)
            if not timestamp_ok(data.get("ts"), time.time(), require_ts, ts_window):
                return self._reject(409, "replay", "timestamp ausente ou fora da janela", ip, n, node)
            try:
                accepted = state.replay.accept(node, boot, seq)
            except ReplayCapacityError:
                return self._reject(503, "capacity_rejected",
                                    "limite de identidades anti-replay atingido", ip, n, node)
            if not accepted:
                return self._reject(409, "replay", "replay", ip, n, node)
            with state.lock:
                state.counters["accepted"] += 1
                data["rx"] = time.time()
                state.samples.append(data)
                state.policy.update(node, data.get("ppm"), data.get("t"), data.get("fan"))
            self._record(ip, "accepted", node, n)
            self._json(200, {"ok": True})

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/healthz":
                return self._json(200, {"status": "ok"})

            ip = self._ip()
            if state.monitor.is_blocked(ip):
                self._record(ip, "blocked")
                return self._json(429, {"error": "ip bloqueado temporariamente"})

            node_for_log = ""
            outcome = "other"
            try:
                if path in dashboard_paths and not self._require_dashboard_auth():
                    outcome = "unauthorized"
                    return
                if path == "/control":
                    outcome = "control"
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    node = query.get("node", [""])[0]
                    nonce = query.get("nonce", [""])[0]
                    node_for_log = node[:MAX_NODE_ID]
                    if not NODE_ID_RE.fullmatch(node) or not NONCE_RE.fullmatch(nonce):
                        return self._json(400, {"error": "node ou nonce inválido"})
                    request_message = f"GET\n/control\n{node}\n{nonce}".encode("utf-8")
                    if not verify(state.secret, request_message, self.headers.get("X-Request-Signature", "")):
                        outcome = "unauthorized"
                        return self._json(401, {"error": "assinatura da requisição inválida"})
                    with state.lock:
                        cseq = state.policy.next_command_seq(node)
                        if cseq is None:
                            return self._json(404, {"error": "nó ainda não registrado"})
                        cmd = {"node": node, "mode": state.policy.mode(node),
                               "fan": state.policy.target(node), "cseq": cseq, "nonce": nonce}
                    body = json.dumps(cmd, separators=(",", ":")).encode()
                    return self._send(200, body, extra={"X-Signature": sign(state.secret, body),
                                                        "Cache-Control": "no-store"})
                if path == "/api/telemetry":
                    with state.lock:
                        return self._json(200, {"samples": list(state.samples)[-300:],
                                                "counters": dict(state.counters),
                                                "fan": dict(state.policy.fan),
                                                "mode": state.policy.modes(),
                                                "command_fan": state.policy.targets()},
                                      extra={"Cache-Control": "no-store"})
                if path == "/api/alerts":
                    state.monitor.check_silence()
                    return self._json(200, state.monitor.snapshot(), extra={"Cache-Control": "no-store"})
                if path == "/api/results":
                    file_path = os.path.join(ROOT, "results", "results.json")
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as fh:
                            return self._send(200, fh.read(), extra={"Cache-Control": "no-store"})
                    return self._json(404, {"error": "rode: python -m pura.experiments"})
                if path in ("/", "/index.html"):
                    with open(os.path.join(ROOT, "web", "index.html"), "rb") as fh:
                        return self._send(200, fh.read(), "text/html; charset=utf-8", {"Cache-Control": "no-store"})
                if path in ("/comparacao.png", "/serie_temporal.png"):
                    image_path = os.path.join(ROOT, "results", path[1:])
                    if not os.path.isfile(image_path):
                        return self._json(404, {"error": "imagem não encontrada"})
                    with open(image_path, "rb") as fh:
                        return self._send(200, fh.read(), "image/png")
                return self._json(404, {"error": "not found"})
            except (OSError, ValueError):
                return self._json(500, {"error": "erro interno"})
            finally:
                self._record(ip, outcome, node_for_log)

        def _method_not_allowed(self):
            ip = self._ip()
            if state.monitor.is_blocked(ip):
                self._record(ip, "blocked")
                return self._json(429, {"error": "ip bloqueado temporariamente"})
            self._record(ip, "other")
            self.close_connection = True
            self._json(405, {"error": "método não permitido"},
                       extra={"Allow": "GET, POST", "Connection": "close"})

        def do_PUT(self):
            self._method_not_allowed()

        def do_DELETE(self):
            self._method_not_allowed()

        def do_PATCH(self):
            self._method_not_allowed()

        def do_OPTIONS(self):
            self._method_not_allowed()

        def do_HEAD(self):
            self._method_not_allowed()

        def do_TRACE(self):
            self._method_not_allowed()

        def do_CONNECT(self):
            self._method_not_allowed()

    return Handler


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Servidor com limite de threads para reduzir exaustão de recursos por conexões concorrentes."""
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, server_address, RequestHandlerClass, max_workers=MAX_CONCURRENT_REQUESTS):
        if max_workers < 1:
            raise ValueError("max_workers deve ser >= 1")
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


def make_server(host="127.0.0.1", port=8000, state: Optional[State] = None):
    if not _is_loopback_bind(host) and len(os.environ.get("PURA_DASHBOARD_PASSWORD", "")) < 16:
        raise ValueError("bind fora do loopback exige PURA_DASHBOARD_PASSWORD com pelo menos 16 caracteres")
    state = state or State()
    return BoundedThreadingHTTPServer((host, port), make_handler(state)), state


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--traffic-log", default=None, help="grava eventos de tráfego em JSONL (desativado por padrão)")
    ap.add_argument("--traffic-log-max-bytes", type=int, default=DEFAULT_TRAFFIC_LOG_MAX_BYTES)
    ap.add_argument("--traffic-log-backups", type=int, default=DEFAULT_TRAFFIC_LOG_BACKUPS)
    a = ap.parse_args()
    try:
        state = State(traffic_log=a.traffic_log,
                      traffic_log_max_bytes=a.traffic_log_max_bytes,
                      traffic_log_backups=a.traffic_log_backups)
        srv, _ = make_server(a.host, a.port, state)
    except (WeakSecretError, ValueError) as exc:
        raise SystemExit(f"ERRO: {exc}") from exc
    print(f"Gateway em http://{a.host}:{a.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
