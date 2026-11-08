"""Modelo do problema de otimização: rede, fluxos, restrições e função objetivo.

Variáveis de decisão : para cada fluxo f, um caminho P_f (sequência de nós) de src a dst.
Função objetivo (min): J = sum_f w_f * sum_{e in P_f} (lat_ef(e, carga) + RISK_WEIGHT * risco(e))
                          + OVERLOAD_PENALTY * sobrecarga relativa + INVALID_PENALTY * fluxos sem rota
Restrições           : (R1) capacidade dos enlaces (suave, penalizada e medida como perda de goodput);
                       (R2) zonas proibidas: fluxos 'restricted' não atravessam nós da zona 'untrusted';
                       (R3) rota válida: contígua, sem laços, só por enlaces ativos.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

RISK_WEIGHT = 30.0        # ms equivalentes por unidade de risco (1 - confiança) de um enlace
OVERLOAD_PENALTY = 400.0
INVALID_PENALTY = 1500.0
UNTRUSTED = "untrusted"

Path = Tuple[str, ...]
EdgeKey = Tuple[str, str]


def ekey(a: str, b: str) -> EdgeKey:
    return (a, b) if a < b else (b, a)


@dataclass
class Link:
    a: str
    b: str
    latency: float      # ms (base)
    capacity: float     # kbps
    trust: float        # 0..1 (confiança do enlace; risco = 1 - trust)
    up: bool = True
    lat_factor: float = 1.0   # multiplicador temporário (picos de latência)

    @property
    def key(self) -> EdgeKey:
        return ekey(self.a, self.b)

    @property
    def risk(self) -> float:
        return 1.0 - self.trust

    def base_cost(self) -> float:
        """Custo que não depende de carga (usado por Dijkstra clássico e rota estática)."""
        return self.latency * self.lat_factor + RISK_WEIGHT * self.risk

    def eff_latency(self, load: float) -> float:
        """Latência efetiva: cresce com a utilização do enlace (modelo de fila simplificado)."""
        u = min(load / self.capacity, 1.5)
        return self.latency * self.lat_factor * (1.0 + 4.0 * u * u)


@dataclass
class Flow:
    id: str
    src: str
    dst: str
    demand: float            # kbps
    weight: float            # prioridade
    restricted: bool = False  # True: não pode passar pela zona 'untrusted'
    kind: str = "telemetry"   # telemetry | control | bulk
    base_demand: float = 0.0

    def __post_init__(self):
        if not self.base_demand:
            self.base_demand = self.demand


class Network:
    def __init__(self) -> None:
        self.zone: Dict[str, str] = {}
        self.links: Dict[EdgeKey, Link] = {}
        self._adj: Dict[str, List[str]] = {}

    def add_node(self, node: str, zone: str) -> None:
        self.zone[node] = zone
        self._adj.setdefault(node, [])

    def add_link(self, a: str, b: str, latency: float, capacity: float, trust: float) -> Link:
        link = Link(a, b, latency, capacity, trust)
        self.links[link.key] = link
        self._adj[a].append(b)
        self._adj[b].append(a)
        return link

    def link(self, a: str, b: str) -> Optional[Link]:
        return self.links.get(ekey(a, b))

    def neighbors(self, node: str) -> List[str]:
        """Vizinhos alcançáveis por enlaces ativos."""
        return [m for m in self._adj[node] if self.links[ekey(node, m)].up]


@dataclass
class World:
    """Estado mutável da simulação: rede + fluxos."""
    net: Network
    flows: List[Flow]

    def clone(self) -> "World":
        return copy.deepcopy(self)


def priority_order(flows: List[Flow]) -> List[Flow]:
    return sorted(flows, key=lambda f: (-f.weight, -f.demand, f.id))


def validate_route(net: Network, flow: Flow, path: Optional[Path]) -> Optional[str]:
    """Retorna None se a rota é válida; senão o motivo da rejeição."""
    if not path or path[0] != flow.src or path[-1] != flow.dst:
        return "extremos_invalidos"
    if len(set(path)) != len(path):
        return "laco"
    for n in path:
        if n not in net.zone:
            return "no_inexistente"
    if flow.restricted and any(net.zone[n] == UNTRUSTED for n in path):
        return "zona_proibida"
    for a, b in zip(path, path[1:]):
        link = net.link(a, b)
        if link is None:
            return "enlace_inexistente"
        if not link.up:
            return "enlace_caido"
    return None


@dataclass
class Evaluation:
    J: float
    latency: Dict[str, float]
    risk: Dict[str, float]
    goodput: Dict[str, float]     # razão entregue/demandada (0 se sem rota)
    invalid: Dict[str, str]       # fluxo -> motivo
    overload: float
    loads: Dict[EdgeKey, float] = field(default_factory=dict)


def evaluate(net: Network, flows: List[Flow], routes: Dict[str, Path]) -> Evaluation:
    valid: Dict[str, Path] = {}
    invalid: Dict[str, str] = {}
    for f in flows:
        reason = validate_route(net, f, routes.get(f.id))
        if reason is None:
            valid[f.id] = routes[f.id]
        else:
            invalid[f.id] = reason

    loads: Dict[EdgeKey, float] = {}
    for f in flows:
        p = valid.get(f.id)
        if p:
            for a, b in zip(p, p[1:]):
                k = ekey(a, b)
                loads[k] = loads.get(k, 0.0) + f.demand

    lat: Dict[str, float] = {}
    risk: Dict[str, float] = {}
    good: Dict[str, float] = {}
    J = 0.0
    for f in flows:
        p = valid.get(f.id)
        if not p:
            J += INVALID_PENALTY * f.weight
            good[f.id] = 0.0
            continue
        lk = r = 0.0
        g = 1.0
        for a, b in zip(p, p[1:]):
            k = ekey(a, b)
            link = net.links[k]
            load = loads[k]
            lk += link.eff_latency(load)
            r += link.risk
            if load > link.capacity:
                g = min(g, link.capacity / load)
        lat[f.id], risk[f.id], good[f.id] = lk, r, g
        J += f.weight * (lk + RISK_WEIGHT * r)
    over = sum(max(0.0, (ld - net.links[k].capacity) / net.links[k].capacity) for k, ld in loads.items())
    J += OVERLOAD_PENALTY * over
    return Evaluation(J, lat, risk, good, invalid, over, loads)
