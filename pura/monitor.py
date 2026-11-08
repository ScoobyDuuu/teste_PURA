"""Monitoramento de tráfego do gateway: detecção de anomalias e mitigação automática.

Cada requisição que chega ao gateway vira um `TrafficEvent`. O `TrafficMonitor` analisa a janela
recente e gera alertas:

  BAD_SIGNATURE_BURST  várias assinaturas inválidas do mesmo IP (falsificação / força bruta)  -> bloqueia o IP
  FLOOD                taxa de requisições por IP acima do limite (DoS)                       -> bloqueia o IP
  REPLAY               mensagem repetida ou de boot antigo                                    -> alerta
  NODE_SILENCE         nó conhecido parou de enviar (queda de enlace/nó)                      -> alerta

Também funciona offline: `python -m pura.monitor trafego.jsonl`.
"""
from __future__ import annotations

import json
import math
import sys
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, dataclass
from typing import Callable, Deque, Dict, List, Optional

MAX_EVENTS = 20000
MAX_TRACKED_IPS = 4096
MAX_TRACKED_NODES = 1024
DEFAULT_NODE_RETENTION_S = 24 * 60 * 60
TRACKING_CLEANUP_INTERVAL_S = 60.0
MAX_ANALYSIS_IPS = 4096
OUTCOMES = ("accepted", "bad_signature", "replay", "bad_request", "blocked", "control",
            "capacity_rejected", "unauthorized", "other")


@dataclass
class TrafficEvent:
    ts: float
    ip: str
    outcome: str
    node: str = ""
    size: int = 0


@dataclass
class Alert:
    ts: float
    kind: str
    severity: str        # low | medium | high
    source: str          # IP ou nó
    detail: str


class TrafficMonitor:
    def __init__(self, window_s: float = 60.0, bad_sig_limit: int = 5, flood_limit: int = 120,
                 block_s: float = 120.0, silence_s: float = 30.0,
                 clock: Callable[[], float] = time.time,
                 max_tracked_ips: int = MAX_TRACKED_IPS,
                 max_tracked_nodes: int = MAX_TRACKED_NODES,
                 node_retention_s: float = DEFAULT_NODE_RETENTION_S) -> None:
        numeric_settings = (window_s, block_s, silence_s, node_retention_s)
        if (not all(math.isfinite(float(value)) and float(value) > 0 for value in numeric_settings)
                or max_tracked_ips < 1 or max_tracked_nodes < 1
                or bad_sig_limit < 1 or flood_limit < 1):
            raise ValueError("janelas, limites e retenção devem ser positivos e finitos")
        self.window_s, self.bad_sig_limit, self.flood_limit = window_s, bad_sig_limit, flood_limit
        self.block_s, self.silence_s, self.clock = block_s, silence_s, clock
        self.max_tracked_ips = max_tracked_ips
        self.max_tracked_nodes = max_tracked_nodes
        self.node_retention_s = node_retention_s
        self._events: Deque[TrafficEvent] = deque(maxlen=MAX_EVENTS)  # teto de memória sob inundação
        self._blocked: OrderedDict[str, float] = OrderedDict()
        self._last_seen: OrderedDict[str, float] = OrderedDict()
        self._silent: set = set()
        self.alerts: Deque[Alert] = deque(maxlen=200)
        self.totals: Counter = Counter()
        self._last_tracking_cleanup = 0.0
        self._lock = threading.Lock()

    def _cleanup_tracking(self, now: float, force: bool = False) -> None:
        """Remove bloqueios expirados e nós inativos sem permitir crescimento ilimitado."""
        if not force and now - self._last_tracking_cleanup < TRACKING_CLEANUP_INTERVAL_S:
            return
        self._last_tracking_cleanup = now
        for ip, until in list(self._blocked.items()):
            if until <= now:
                self._blocked.pop(ip, None)
        cutoff = now - self.node_retention_s
        for node, seen in list(self._last_seen.items()):
            if seen < cutoff:
                self._last_seen.pop(node, None)
                self._silent.discard(node)

    # ----- mitigação -----
    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            now = self.clock()
            self._cleanup_tracking(now)
            until = self._blocked.get(ip)
            if until is None:
                return False
            if now >= until:
                del self._blocked[ip]
                return False
            return True

    def _block(self, ip: str, now: float, kind: str, detail: str) -> None:
        if ip in self._blocked:
            return
        self._cleanup_tracking(now, force=True)
        if len(self._blocked) >= self.max_tracked_ips:
            # Remove o bloqueio que expira primeiro; a tabela nunca excede o limite.
            oldest_ip = min(self._blocked, key=self._blocked.get)
            del self._blocked[oldest_ip]
        self._blocked[ip] = now + self.block_s
        self._alert(now, kind, "high", ip, f"{detail}; IP bloqueado por {self.block_s:.0f}s")

    def _alert(self, now: float, kind: str, severity: str, source: str, detail: str) -> None:
        self.alerts.append(Alert(now, kind, severity, source, detail))

    # ----- análise -----
    def record(self, ip: str, outcome: str, node: str = "", size: int = 0) -> None:
        # Também limita chamadas internas/offline; o gateway já valida esses campos na entrada.
        ip = str(ip)[:64]
        node = str(node)[:64]
        outcome = outcome if outcome in OUTCOMES else "other"
        size = min(2048, max(0, int(size)))
        now = self.clock()
        with self._lock:
            ev = TrafficEvent(now, ip, outcome, node, size)
            self._events.append(ev)
            self.totals[outcome] += 1
            while self._events and now - self._events[0].ts > self.window_s:
                self._events.popleft()
            self._cleanup_tracking(now)
            if outcome == "accepted" and node:
                if node not in self._last_seen and len(self._last_seen) >= self.max_tracked_nodes:
                    old_node, _ = self._last_seen.popitem(last=False)
                    self._silent.discard(old_node)
                self._last_seen[node] = now
                self._last_seen.move_to_end(node)
                self._silent.discard(node)
            mine = [e for e in self._events if e.ip == ip]
            bad = sum(1 for e in mine if e.outcome == "bad_signature")
            if outcome == "bad_signature" and bad >= self.bad_sig_limit:
                self._block(ip, now, "BAD_SIGNATURE_BURST",
                            f"{bad} assinaturas inválidas em {self.window_s:.0f}s")
            if len(mine) >= self.flood_limit:
                self._block(ip, now, "FLOOD", f"{len(mine)} requisições em {self.window_s:.0f}s")
            if outcome == "replay":
                self._alert(now, "REPLAY", "medium", ip, f"mensagem repetida do nó {node or '?'}")

    def check_silence(self) -> List[Alert]:
        """Chamado periodicamente: alerta nós que pararam de enviar telemetria."""
        now, new = self.clock(), []
        with self._lock:
            self._cleanup_tracking(now)
            for node, seen in self._last_seen.items():
                if now - seen > self.silence_s and node not in self._silent:
                    self._silent.add(node)
                    a = Alert(now, "NODE_SILENCE", "medium", node,
                              f"sem telemetria há {now - seen:.0f}s (queda de enlace ou nó)")
                    self.alerts.append(a)
                    new.append(a)
        return new

    def snapshot(self) -> dict:
        with self._lock:
            now = self.clock()
            self._cleanup_tracking(now, force=True)
            talkers = Counter(e.ip for e in self._events).most_common(5)
            return {"totals": dict(self.totals),
                    "top_talkers": [{"ip": ip, "requests": n} for ip, n in talkers],
                    "blocked": sorted(ip for ip, t in self._blocked.items() if t > now),
                    "alerts": [asdict(a) for a in list(self.alerts)[-20:]][::-1]}


def analyze_log(path: str, max_ips: int = MAX_ANALYSIS_IPS) -> dict:
    """Analisa JSONL em streaming e limita tanto linhas quanto estado em memória."""
    if max_ips < 1:
        raise ValueError("max_ips deve ser >= 1")

    max_line_chars = 64 * 1024
    clock_value = [0.0]
    mon = TrafficMonitor(clock=lambda: clock_value[0])
    by_ip: Dict[str, Counter] = {}
    omitted_events = 0
    event_count = 0
    last_ts = None

    with open(path, encoding="utf-8") as fh:
        line_number = 0
        while True:
            line = fh.readline(max_line_chars + 1)
            if not line:
                break
            line_number += 1
            if len(line) > max_line_chars:
                raise ValueError(f"registro JSONL excede {max_line_chars} caracteres na linha {line_number}")
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("registro deve ser objeto JSON")
                ts = float(event["ts"])
                if not math.isfinite(ts):
                    raise ValueError("ts deve ser finito")
                ip = str(event["ip"])[:64]
                outcome = str(event["outcome"])
                if outcome not in OUTCOMES:
                    outcome = "other"
                node = str(event.get("node", ""))[:64]
                size_value = event.get("size", 0)
                if isinstance(size_value, bool) or not isinstance(size_value, int) or size_value < 0:
                    raise ValueError("size deve ser inteiro não negativo")
                size = min(2048, size_value)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"registro JSONL inválido na linha {line_number}: {exc}") from exc

            clock_value[0] = ts
            mon.record(ip, outcome, node, size)
            event_count += 1
            last_ts = ts
            if ip in by_ip:
                by_ip[ip][outcome] += 1
            elif len(by_ip) < max_ips:
                by_ip[ip] = Counter({outcome: 1})
            else:
                omitted_events += 1

    if event_count == 0:
        return {"events": 0}

    clock_value[0] = last_ts
    mon.check_silence()
    result = mon.snapshot()
    result["events"] = event_count
    result["by_ip"] = {ip: dict(counts) for ip, counts in by_ip.items()}
    result["by_ip_omitted_events"] = omitted_events
    return result


def main(argv: Optional[List[str]] = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("uso: python -m pura.monitor trafego.jsonl")
        return
    print(json.dumps(analyze_log(argv[0]), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
