"""Interface Strategy dos roteadores (Template Method em `routes`).

Cada roteador é um observador de eventos: ao receber um evento, marca que precisa re-decidir.
O simulador chama `routes()` a cada tick; a decisão só roda quando necessário.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from ..events import Event
from ..model import Flow, Path, UNTRUSTED, World


def node_filter(world: World, flow: Flow):
    """Filtro de zona: fluxos restritos não podem usar nós 'untrusted'."""
    if flow.restricted:
        zone = world.net.zone
        return lambda n: zone[n] != UNTRUSTED
    return None


class Router(ABC):
    name = "base"
    reactive = True          # False: ignora eventos (rota estática)

    def __init__(self) -> None:
        self._routes: Optional[Dict[str, Path]] = None
        self._dirty = True
        self.decision_ms: List[float] = []

    def on_event(self, event: Event) -> None:          # callback do Observer
        if self.reactive:
            self._dirty = True

    def routes(self, world: World, tick: int) -> Dict[str, Path]:
        if self._routes is None or self._dirty:
            t0 = time.perf_counter()
            self._routes = self.decide(world, tick)
            self.decision_ms.append((time.perf_counter() - t0) * 1000.0)
            self._dirty = False
        return self._routes

    @property
    def current(self) -> Optional[Dict[str, Path]]:
        return self._routes

    @abstractmethod
    def decide(self, world: World, tick: int) -> Dict[str, Path]:
        """Retorna um caminho por fluxo (fluxos sem caminho possível ficam de fora)."""
