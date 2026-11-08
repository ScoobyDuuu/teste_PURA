"""Coleta e sumarização de métricas de uma execução."""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Dict, List


BUDGET_MS = 100.0   # orçamento de tempo real por decisão de roteamento


@dataclass
class TickRecord:
    tick: int
    lat: List[float]                 # latência dos fluxos com rota válida
    risk: List[float]
    goodput: float                   # ponderado pela demanda (0..1)
    utility: float
    J: float
    invalid: Dict[str, str] = field(default_factory=dict)   # fluxo -> motivo (rejeitado pela guarda)


def percentile(vals: List[float], q: float) -> float:
    """Percentil por ranking mais próximo (nearest-rank)."""
    if not vals:
        return float("nan")
    s = sorted(vals)
    k = max(1, math.ceil(q / 100.0 * len(s)))
    return s[k - 1]


def mean_std(vals: List[float]):
    if not vals:
        return float("nan"), float("nan")
    return statistics.fmean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def recovery_ticks(records: List[TickRecord], events, T: int, tol: float = 0.95) -> float:
    """Ticks até todos os fluxos terem rota válida e goodput >= tol * goodput pré-falha."""
    ticks = sorted(e.tick for e in events)
    out = []
    for e in events:
        if e.kind != "link_failure":
            continue
        nxt = min([t for t in ticks if t > e.tick] + [e.tick + 10, T])
        ref = records[e.tick - 1].goodput if e.tick > 0 else 1.0
        window = nxt - e.tick
        rec = window
        for k in range(window):
            r = records[e.tick + k]
            if not r.invalid and r.goodput >= tol * ref:
                rec = k
                break
        out.append(rec)
    return statistics.fmean(out) if out else 0.0


def summarize(records: List[TickRecord], events, decision_ms: List[float], T: int) -> Dict[str, float]:
    lats = [x for r in records for x in r.lat]
    risks = [x for r in records for x in r.risk]
    n_flowticks = len(lats) + sum(len(r.invalid) for r in records)
    reasons: Dict[str, int] = {}
    for r in records:
        for why in r.invalid.values():
            reasons[why] = reasons.get(why, 0) + 1
    return {
        "lat_mean": statistics.fmean(lats) if lats else float("nan"),
        "lat_p95": percentile(lats, 95),
        "goodput": statistics.fmean(r.goodput for r in records),
        "utility": statistics.fmean(r.utility for r in records),
        "drop_frac": sum(len(r.invalid) for r in records) / n_flowticks if n_flowticks else 0.0,
        "risk": statistics.fmean(risks) if risks else float("nan"),
        "recovery": recovery_ticks(records, events, T),
        "compute_ms": statistics.fmean(decision_ms) if decision_ms else 0.0,
        "decisions": float(len(decision_ms)),
        "over_budget": (sum(1 for d in decision_ms if d > BUDGET_MS) / len(decision_ms)) if decision_ms else 0.0,
        "J": statistics.fmean(r.J for r in records),
        "rej_zone": float(reasons.get("zona_proibida", 0)),
        "rej_down": float(reasons.get("enlace_caido", 0)),
    }
