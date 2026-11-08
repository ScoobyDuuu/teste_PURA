"""Algoritmo Memético: Algoritmo Genético + busca local (hill climbing) em cada filho.

Cromossomo : para cada fluxo, o índice de um caminho dentro de um conjunto de candidatos
             (gerados por Dijkstra com custos perturbados).
Fitness    : função objetivo J (menor é melhor).
Operadores : torneio binário, cruzamento uniforme, mutação por gene, busca local de 1 passada,
             substituição elitista (mu + lambda). A melhor solução anterior entra na população.
"""
from __future__ import annotations

import random
from typing import Dict, List

from ..graph import dijkstra
from ..model import Flow, Path, World, evaluate, priority_order
from .base import Router, node_filter


class MemeticRouter(Router):
    name = "memetic"

    def __init__(self, seed: int = 0, pop: int = 10, gens: int = 6, k_paths: int = 6,
                 p_mut: float = 0.2) -> None:
        super().__init__()
        self.rng = random.Random(seed)
        self.pop_size, self.gens, self.k, self.p_mut = pop, gens, k_paths, p_mut

    def _candidates(self, world: World, f: Flow) -> List[Path]:
        net, ok = world.net, node_filter(world, f)
        paths: List[Path] = []

        def add(p):
            if p and p not in paths:
                paths.append(p)

        add(dijkstra(net, f.src, f.dst, lambda lk: lk.base_cost(), ok))
        for _ in range(self.k * 3):
            if len(paths) >= self.k:
                break
            noise: Dict = {}
            add(dijkstra(net, f.src, f.dst,
                         lambda lk: lk.base_cost() * noise.setdefault(lk.key, self.rng.uniform(0.5, 2.0)), ok))
        prev = (self._routes or {}).get(f.id)
        if prev and prev not in paths:
            from ..model import validate_route
            if validate_route(net, f, prev) is None:
                paths.append(prev)
        return paths

    def decide(self, world: World, tick: int) -> Dict[str, Path]:
        net = world.net
        flows = priority_order(world.flows)
        cands = {f.id: self._candidates(world, f) for f in flows}
        active = [f for f in flows if cands[f.id]]
        if not active:
            return {}
        cache: Dict[tuple, float] = {}

        def build(ind):
            return {f.id: cands[f.id][g] for f, g in zip(active, ind)}

        def fit(ind) -> float:
            key = tuple(ind)
            if key not in cache:
                cache[key] = evaluate(net, world.flows, build(ind)).J
            return cache[key]

        def local_search(ind):
            ind = list(ind)
            for i, f in enumerate(active):
                best_g, best_j = ind[i], fit(ind)
                for g in range(len(cands[f.id])):
                    if g == ind[i]:
                        continue
                    trial = ind[:i] + [g] + ind[i + 1:]
                    j = fit(trial)
                    if j < best_j:
                        best_g, best_j = g, j
                ind[i] = best_g
            return ind

        # população inicial: [melhor anterior] + [todos os caminhos mais curtos] + aleatórios
        prev = self._routes or {}
        seed_prev = [cands[f.id].index(prev[f.id]) if prev.get(f.id) in cands[f.id] else 0 for f in active]
        pop = [seed_prev, [0] * len(active)]
        while len(pop) < self.pop_size:
            pop.append([self.rng.randrange(len(cands[f.id])) for f in active])
        pop = [local_search(ind) for ind in pop]

        for _ in range(self.gens):
            children = []
            for _c in range(self.pop_size):
                a = min(self.rng.sample(pop, 2), key=fit)
                b = min(self.rng.sample(pop, 2), key=fit)
                child = [x if self.rng.random() < 0.5 else y for x, y in zip(a, b)]
                for i, f in enumerate(active):
                    if self.rng.random() < self.p_mut:
                        child[i] = self.rng.randrange(len(cands[f.id]))
                children.append(local_search(child))
            pop = sorted(pop + children, key=fit)[: self.pop_size]
        return build(min(pop, key=fit))
