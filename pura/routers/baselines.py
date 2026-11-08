"""Baselines obrigatórios: rota estática fixa e Dijkstra recalculado a cada evento.

Inclui também um baseline mais forte (Dijkstra com capacidade residual, guloso sequencial)
para evitar uma comparação com 'espantalho'.
"""
from __future__ import annotations

from typing import Dict

from ..graph import dijkstra
from ..model import Path, World, ekey, priority_order, RISK_WEIGHT
from .base import Router, node_filter


def _static_cost(world: World) -> Dict[str, Path]:
    routes: Dict[str, Path] = {}
    for f in world.flows:
        p = dijkstra(world.net, f.src, f.dst, lambda lk: lk.base_cost(), node_filter(world, f))
        if p:
            routes[f.id] = p
    return routes


class StaticRouter(Router):
    """Calcula as rotas uma única vez (tick 0) e nunca as atualiza."""
    name = "static"
    reactive = False

    def decide(self, world, tick):
        return _static_cost(world)


class DijkstraRouter(Router):
    """Dijkstra recalculado a cada evento, com custo = latência base + risco (ignora carga)."""
    name = "dijkstra"

    def decide(self, world, tick):
        return _static_cost(world)


class DijkstraResidualRouter(Router):
    """Dijkstra sequencial por prioridade, evitando enlaces sem capacidade residual."""
    name = "dijkstra_residual"

    def decide(self, world, tick):
        net = world.net
        loads: Dict = {}
        routes: Dict[str, Path] = {}
        for f in priority_order(world.flows):
            def w(lk, f=f):
                return lk.eff_latency(loads.get(lk.key, 0.0) + f.demand) + RISK_WEIGHT * lk.risk
            ok = node_filter(world, f)
            p = dijkstra(net, f.src, f.dst, w, ok,
                         edge_ok=lambda lk, f=f: lk.capacity - loads.get(lk.key, 0.0) >= f.demand)
            if p is None:
                p = dijkstra(net, f.src, f.dst, w, ok)
            if p:
                routes[f.id] = p
                for a, b in zip(p, p[1:]):
                    k = ekey(a, b)
                    loads[k] = loads.get(k, 0.0) + f.demand
        return routes
