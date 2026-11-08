"""Cenário sintético e reprodutível: rede mesh IoT com zona não confiável e eventos programados.

A topologia é fixa (documentada em docs/); latência, capacidade e confiança de cada enlace variam
±15% / ±0.03 conforme a semente. Dados SINTÉTICOS: ver relatório (seção Dados e premissas).

Papéis dos nós:  G gateway | C* núcleo | E* retransmissores de borda | S* sensores (S1 = ESP32 real)
                 U* retransmissores de terceiros (zona 'untrusted': atalhos rápidos e pouco confiáveis)
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List

from .events import Event, LatencySpike, LinkFailure, LinkRecovery, TrafficSurge
from .graph import dijkstra
from .model import Flow, Network, UNTRUSTED, World, ekey

# (a, b, latência ms, capacidade kbps, confiança)
LINKS = [
    ("G", "C1", 3, 600, 0.98), ("G", "C2", 3, 600, 0.98), ("G", "C3", 3, 600, 0.98),
    ("C1", "C2", 4, 500, 0.97), ("C2", "C3", 4, 500, 0.97),
    ("C1", "E1", 7, 400, 0.94), ("C1", "E2", 7, 400, 0.94), ("C2", "E2", 7, 400, 0.94),
    ("C2", "E3", 7, 400, 0.94), ("C3", "E3", 7, 400, 0.94), ("C3", "E4", 7, 400, 0.94),
    ("E1", "E2", 5, 300, 0.90), ("E3", "E4", 5, 300, 0.90),
    ("S1", "E1", 11, 300, 0.88), ("S2", "E1", 11, 300, 0.88), ("S2", "E2", 11, 300, 0.88),
    ("S3", "E2", 11, 300, 0.88), ("S3", "E3", 11, 300, 0.88), ("S4", "E3", 11, 300, 0.88),
    ("S5", "E3", 11, 300, 0.88), ("S5", "E4", 11, 300, 0.88), ("S6", "E4", 11, 300, 0.88),
    # zona não confiável: atalhos de baixa latência e baixa confiança
    ("E1", "U1", 3, 250, 0.40), ("U1", "C2", 3, 250, 0.40), ("U1", "G", 2, 250, 0.35),
    ("E4", "U2", 3, 250, 0.45), ("U2", "C2", 3, 250, 0.40), ("U1", "U2", 2, 250, 0.35),
    ("S1", "U1", 6, 200, 0.50), ("S6", "U2", 6, 200, 0.50),
]
ZONES = {"G": "core", "C1": "core", "C2": "core", "C3": "core",
         "E1": "edge", "E2": "edge", "E3": "edge", "E4": "edge",
         "S1": "edge", "S2": "edge", "S3": "edge", "S4": "edge", "S5": "edge", "S6": "edge",
         "U1": UNTRUSTED, "U2": UNTRUSTED}


def base_flows() -> List[Flow]:
    flows = [Flow(f"T{i}", f"S{i}", "G", 20.0, 2.0, False, "telemetry") for i in range(1, 7)]
    flows += [Flow("K1", "G", "S1", 10.0, 5.0, True, "control"),     # comando do relé do ESP32 real
              Flow("K2", "G", "S6", 10.0, 5.0, True, "control"),
              Flow("B1", "S3", "G", 150.0, 1.0, False, "bulk"),       # logs / atualização de firmware
              Flow("B2", "S5", "G", 150.0, 1.0, False, "bulk")]
    return flows


def build_network(rng: random.Random) -> Network:
    net = Network()
    for n, z in ZONES.items():
        net.add_node(n, z)
    for a, b, lat, cap, tr in LINKS:
        net.add_link(a, b, lat * rng.uniform(0.85, 1.15), cap * rng.uniform(0.85, 1.15),
                     min(0.995, max(0.05, tr + rng.uniform(-0.03, 0.03))))
    return net


@dataclass
class Scenario:
    name: str
    seed: int
    world: World
    events: List[Event]
    T: int = 60

    def events_at(self, tick: int) -> List[Event]:
        return [e for e in self.events if e.tick == tick]


def _reachable(world: World, failed) -> bool:
    w = world.clone()
    for a, b in failed:
        w.net.link(a, b).up = False
    for f in w.flows:
        ok = None
        if f.restricted:
            def ok(n, z=w.net.zone):
                return z[n] != UNTRUSTED
        if dijkstra(w.net, f.src, f.dst, lambda lk: 1.0, ok) is None:
            return False
    return True


def build_scenario(seed: int, surge: float = 1.5, T: int = 60) -> Scenario:
    rng = random.Random(seed)
    world = World(build_network(rng), base_flows())

    # usa a rota inicial de menor custo para escolher falhas que realmente causam impacto
    use: dict = {}
    k1_links = []
    for f in world.flows:
        p = dijkstra(world.net, f.src, f.dst, lambda lk: lk.base_cost(),
                     (lambda n: world.net.zone[n] != UNTRUSTED) if f.restricted else None)
        for a, b in zip(p, p[1:]):
            use[ekey(a, b)] = use.get(ekey(a, b), 0) + 1
            if f.id == "K1":
                k1_links.append(ekey(a, b))

    ranked = sorted(use, key=lambda k: (-use[k], rng.random()))
    fail1 = next(k for k in ranked if _reachable(world, [k]))
    cand2 = [k for k in k1_links if k != fail1 and _reachable(world, [fail1, k])]
    fail2 = cand2[0] if cand2 else next(k for k in ranked if k != fail1 and _reachable(world, [fail1, k]))
    spike = next(k for k in ranked if k not in (fail1, fail2))

    events: List[Event] = [
        LinkFailure(15, a=fail1[0], b=fail1[1]),
        TrafficSurge(25, factor=surge),
        LatencySpike(35, a=spike[0], b=spike[1], factor=4.0),
        LinkFailure(45, a=fail2[0], b=fail2[1]),
        TrafficSurge(50, factor=1.0),
        LinkRecovery(52, a=fail1[0], b=fail1[1]),
        LatencySpike(55, a=spike[0], b=spike[1], factor=1.0),
    ]
    return Scenario(f"mesh_surge{surge}", seed, world, events, T)
