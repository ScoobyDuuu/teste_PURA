"""Alocação de banda por fluxo: proporcional (baseline) vs PSO (Particle Swarm Optimization).

Dadas as rotas, escolhe a taxa x_f em [0, demanda_f] que maximiza a utilidade
U = sum_f w_f * log(1 + x_f)  sujeita à capacidade dos enlaces. Cada partícula é um vetor de
taxas; soluções que violam capacidade são "reparadas" (escala proporcional nos enlaces saturados),
o que mantém toda avaliação factível.
"""
from __future__ import annotations

import math
import random
from typing import Dict, List

from .model import Evaluation, Flow, Network, Path, ekey


def utility(flows: List[Flow], rates: Dict[str, float]) -> float:
    """Utilidade normalizada (1.0 = todas as demandas atendidas)."""
    num = sum(f.weight * math.log1p(rates.get(f.id, 0.0)) for f in flows)
    den = sum(f.weight * math.log1p(f.demand) for f in flows)
    return num / den if den else 1.0


class ProportionalAllocator:
    name = "proportional"

    def allocate(self, net: Network, flows: List[Flow], routes: Dict[str, Path], ev: Evaluation) -> Dict[str, float]:
        return {f.id: f.demand * ev.goodput.get(f.id, 0.0) for f in flows}


class PSOAllocator:
    name = "pso"

    def __init__(self, seed: int = 0, particles: int = 20, iters: int = 40,
                 w: float = 0.7, c1: float = 1.5, c2: float = 1.5) -> None:
        self.rng = random.Random(seed)
        self.n, self.iters, self.w, self.c1, self.c2 = particles, iters, w, c1, c2
        self._cache: Dict = {}

    @staticmethod
    def _repair(x, ids, flows_by_id, routes, net):
        x = list(x)
        loads: Dict = {}
        for xi, fid in zip(x, ids):
            p = routes[fid]
            for a, b in zip(p, p[1:]):
                k = ekey(a, b)
                loads[k] = loads.get(k, 0.0) + xi
        for k, ld in loads.items():
            cap = net.links[k].capacity
            if ld > cap:
                s = cap / ld
                for i, fid in enumerate(ids):
                    p = routes[fid]
                    if any(ekey(a, b) == k for a, b in zip(p, p[1:])):
                        x[i] *= s
        return x

    def allocate(self, net: Network, flows: List[Flow], routes: Dict[str, Path], ev: Evaluation) -> Dict[str, float]:
        ids = [f.id for f in flows if f.id not in ev.invalid]
        key = (tuple((i, routes[i]) for i in ids), tuple(f.demand for f in flows),
               tuple((k, lk.capacity, lk.up) for k, lk in sorted(net.links.items())))
        if key in self._cache:
            return self._cache[key]
        fb = {f.id: f for f in flows}
        d = [fb[i].demand for i in ids]
        w = [fb[i].weight for i in ids]

        def fit(x):
            xr = self._repair(x, ids, fb, routes, net)
            return sum(wi * math.log1p(xi) for wi, xi in zip(w, xr)), xr

        prop = [fb[i].demand * ev.goodput.get(i, 0.0) for i in ids]
        pos = [list(d), prop] + [[self.rng.uniform(0, di) for di in d] for _ in range(self.n - 2)]
        vel = [[0.0] * len(ids) for _ in range(self.n)]
        pbest = [p[:] for p in pos]
        pfit = [fit(p)[0] for p in pos]
        g = max(range(self.n), key=lambda i: pfit[i])
        gbest, gfit = pbest[g][:], pfit[g]
        for _ in range(self.iters):
            for i in range(self.n):
                for j in range(len(ids)):
                    r1, r2 = self.rng.random(), self.rng.random()
                    vel[i][j] = (self.w * vel[i][j] + self.c1 * r1 * (pbest[i][j] - pos[i][j])
                                 + self.c2 * r2 * (gbest[j] - pos[i][j]))
                    pos[i][j] = min(d[j], max(0.0, pos[i][j] + vel[i][j]))
                f, _xr = fit(pos[i])
                if f > pfit[i]:
                    pfit[i], pbest[i] = f, pos[i][:]
                    if f > gfit:
                        gfit, gbest = f, pos[i][:]
        best = self._repair(gbest, ids, fb, routes, net)
        out = {fid: 0.0 for fid in (f.id for f in flows)}
        out.update(dict(zip(ids, best)))
        self._cache[key] = out
        return out
