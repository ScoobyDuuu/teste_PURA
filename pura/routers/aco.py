"""ACO (Ant Colony Optimization) para construção de rotas com feromônio.

- Uma "colônia" constrói rotas para TODOS os fluxos (soluções conjuntas), de modo que a
  carga acumulada pelas formigas anteriores influencia as seguintes (cooperação por capacidade).
- Feromônio por (fluxo, enlace), persistente entre decisões: após uma falha, a colônia reaproveita
  o que aprendeu (warm start) em vez de recomeçar do zero.
- Heurística: 1 / (custo do enlace sob carga + distância restante estimada ao destino).
- Atualização elitista: melhor da iteração e melhor global depositam; evaporação em direção a tau0.
"""
from __future__ import annotations

import random
from typing import Dict, Optional

from ..graph import distances_from
from ..model import Flow, Path, RISK_WEIGHT, World, ekey, evaluate, priority_order, UNTRUSTED
from ..graph import dijkstra
from .base import Router, node_filter


class ACORouter(Router):
    name = "aco"

    def __init__(self, seed: int = 0, ants: int = 8, iters: int = 12, alpha: float = 1.0,
                 beta: float = 2.0, rho: float = 0.25) -> None:
        super().__init__()
        self.rng = random.Random(seed)
        self.ants, self.iters, self.alpha, self.beta, self.rho = ants, iters, alpha, beta, rho
        self.tau: Dict = {}
        self.tau0, self.tau_max = 1.0, 6.0

    # ----- feromônio -----
    def _evaporate(self) -> None:
        for k, v in self.tau.items():
            self.tau[k] = self.tau0 + (v - self.tau0) * (1.0 - self.rho)

    def _deposit(self, routes: Dict[str, Path], amount: float) -> None:
        for fid, p in routes.items():
            for a, b in zip(p, p[1:]):
                k = (fid, ekey(a, b))
                self.tau[k] = min(self.tau_max, self.tau.get(k, self.tau0) + amount)

    # ----- construção -----
    def _walk(self, world: World, f: Flow, loads: Dict, hmap: Dict[str, float]) -> Optional[Path]:
        net = world.net
        cur, path, seen = f.src, [f.src], {f.src}
        while cur != f.dst:
            cands, weights = [], []
            for nb in net.neighbors(cur):
                if nb in seen:
                    continue
                if f.restricted and net.zone[nb] == UNTRUSTED:
                    continue
                h = hmap.get(nb)
                if h is None:
                    continue
                link = net.links[ekey(cur, nb)]
                load = loads.get(link.key, 0.0) + f.demand
                cost = link.eff_latency(load) + RISK_WEIGHT * link.risk
                if load > link.capacity:
                    cost *= 1.0 + 5.0 * (load / link.capacity - 1.0)
                eta = 1.0 / (cost + h + 1e-6)
                weights.append((self.tau.get((f.id, link.key), self.tau0) ** self.alpha) * (eta ** self.beta))
                cands.append(nb)
            if not cands:
                return None
            cur = self.rng.choices(cands, weights=weights)[0]
            path.append(cur)
            seen.add(cur)
        return tuple(path)

    def _heuristics(self, world: World, flows):
        cache = {}
        for f in flows:
            key = (f.dst, f.restricted)
            if key not in cache:
                cache[key] = distances_from(world.net, f.dst, lambda lk: lk.base_cost(), node_filter(world, f))
        return cache

    def decide(self, world: World, tick: int) -> Dict[str, Path]:
        net, flows = world.net, priority_order(world.flows)
        hmaps = self._heuristics(world, flows)

        best: Dict[str, Path] = dict(self._routes or {})        # incumbente (warm start)
        best_j = evaluate(net, world.flows, best).J

        for _ in range(self.iters):
            it_best, it_j = None, float("inf")
            for _a in range(self.ants):
                loads: Dict = {}
                routes: Dict[str, Path] = {}
                for f in flows:
                    p = self._walk(world, f, loads, hmaps[(f.dst, f.restricted)])
                    if p is None:       # formiga presa: cai para o caminho de menor custo base
                        p = dijkstra(net, f.src, f.dst, lambda lk: lk.base_cost(), node_filter(world, f))
                    if p is not None:
                        routes[f.id] = p
                        for a, b in zip(p, p[1:]):
                            k = ekey(a, b)
                            loads[k] = loads.get(k, 0.0) + f.demand
                j = evaluate(net, world.flows, routes).J
                if j < it_j:
                    it_best, it_j = routes, j
            if it_best is not None and it_j < best_j:
                best, best_j = it_best, it_j
            self._evaporate()
            if it_best is not None:
                self._deposit(it_best, min(1.0, best_j / it_j))
            self._deposit(best, 1.0)
        return best
