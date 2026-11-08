"""Eventos de rede e barramento (padrão Observer).

O simulador publica eventos; roteadores e coletores de métricas se inscrevem como observadores.
Nenhum roteador conhece o simulador, e o simulador não conhece os roteadores concretos.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List

from .model import World


@dataclass
class Event:
    tick: int
    kind: str = "event"

    def apply(self, world: World) -> None:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class LinkFailure(Event):
    a: str = ""
    b: str = ""
    kind: str = "link_failure"

    def apply(self, world: World) -> None:
        world.net.link(self.a, self.b).up = False


@dataclass
class LinkRecovery(Event):
    a: str = ""
    b: str = ""
    kind: str = "link_recovery"

    def apply(self, world: World) -> None:
        world.net.link(self.a, self.b).up = True


@dataclass
class LatencySpike(Event):
    a: str = ""
    b: str = ""
    factor: float = 4.0
    kind: str = "latency_spike"

    def apply(self, world: World) -> None:
        world.net.link(self.a, self.b).lat_factor = self.factor


@dataclass
class TrafficSurge(Event):
    """Pico de tráfego: multiplica a demanda dos fluxos 'bulk' (factor=1.0 restaura)."""
    factor: float = 2.0
    kind: str = "traffic_surge"

    def apply(self, world: World) -> None:
        for f in world.flows:
            if f.kind == "bulk":
                f.demand = f.base_demand * self.factor


class EventBus:
    def __init__(self) -> None:
        self._subs: List[Callable[[Event], None]] = []

    def subscribe(self, callback: Callable[[Event], None]) -> None:
        self._subs.append(callback)

    def publish(self, event: Event) -> None:
        for cb in self._subs:
            cb(event)
