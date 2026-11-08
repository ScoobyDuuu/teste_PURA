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
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Callable, Deque, Dict, List, Optional

MAX_EVENTS = 20000
OUTCOMES = ("accepted", "bad_signature", "replay", "bad_request", "blocked", "control")


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
                 clock: Callable[[], float] = time.time) -> None:
        self.window_s, self.bad_sig_limit, self.flood_limit = window_s, bad_sig_limit, flood_limit
        self.block_s, self.silence_s, self.clock = block_s, silence_s, clock
        self._events: Deque[TrafficEvent] = deque(maxlen=MAX_EVENTS)  # teto de memória sob inundação
        self._blocked: Dict[str, float] = {}
        self._last_seen: Dict[str, float] = {}
        self._silent: set = set()
        self.alerts: Deque[Alert] = deque(maxlen=200)
        self.totals: Counter = Counter()
        self._lock = threading.Lock()

    # ----- mitigação -----
    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            until = self._blocked.get(ip)
            if until is None:
                return False
            if self.clock() >= until:
                del self._blocked[ip]
                return False
            return True

    def _block(self, ip: str, now: float, kind: str, detail: str) -> None:
        if ip not in self._blocked:
            self._blocked[ip] = now + self.block_s
            self._alert(now, kind, "high", ip, f"{detail}; IP bloqueado por {self.block_s:.0f}s")

    def _alert(self, now: float, kind: str, severity: str, source: str, detail: str) -> None:
        self.alerts.append(Alert(now, kind, severity, source, detail))

    # ----- análise -----
    def record(self, ip: str, outcome: str, node: str = "", size: int = 0) -> None:
        now = self.clock()
        with self._lock:
            ev = TrafficEvent(now, ip, outcome, node, size)
            self._events.append(ev)
            self.totals[outcome] += 1
            while self._events and now - self._events[0].ts > self.window_s:
                self._events.popleft()
            if outcome == "accepted" and node:
                self._last_seen[node] = now
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
            talkers = Counter(e.ip for e in self._events).most_common(5)
            return {"totals": dict(self.totals),
                    "top_talkers": [{"ip": ip, "requests": n} for ip, n in talkers],
                    "blocked": sorted(ip for ip, t in self._blocked.items() if t > now),
                    "alerts": [asdict(a) for a in list(self.alerts)[-20:]][::-1]}


def analyze_log(path: str) -> dict:
    """Análise offline de um arquivo JSONL com eventos {ts, ip, outcome, node, size}."""
    with open(path, encoding="utf-8") as fh:
        events = [json.loads(line) for line in fh if line.strip()]
    if not events:
        return {"events": 0}
    clock_value = [events[0]["ts"]]
    mon = TrafficMonitor(clock=lambda: clock_value[0])
    for e in events:
        clock_value[0] = e["ts"]
        mon.record(e["ip"], e["outcome"], e.get("node", ""), e.get("size", 0))
    clock_value[0] = events[-1]["ts"]
    mon.check_silence()
    by_ip: Dict[str, Counter] = defaultdict(Counter)
    for e in events:
        by_ip[e["ip"]][e["outcome"]] += 1
    snap = mon.snapshot()
    snap["events"] = len(events)
    snap["by_ip"] = {ip: dict(c) for ip, c in by_ip.items()}
    return snap


def main(argv: Optional[List[str]] = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("uso: python -m pura.monitor trafego.jsonl")
        return
    print(json.dumps(analyze_log(argv[0]), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
