"""Simulador de eventos discretos. Separado do motor de decisão (ver ADR-0001/0003).

A cada tick: aplica eventos -> publica no EventBus (Observer) -> pede rotas ao roteador (Strategy)
-> a GUARDA rejeita qualquer rota inválida -> avalia o estado da rede e registra métricas.
"""
from __future__ import annotations

from .bandwidth import ProportionalAllocator, utility
from .events import EventBus
from .metrics import TickRecord, summarize
from .model import evaluate, validate_route
from .routers.base import Router
from .scenario import Scenario


class Simulator:
    def __init__(self, scenario: Scenario, router: Router, allocator=None) -> None:
        self.scenario = scenario
        self.router = router
        self.allocator = allocator or ProportionalAllocator()
        self.bus = EventBus()
        self.bus.subscribe(router.on_event)
        self.world = scenario.world.clone()
        self.records = []

    def run(self):
        sc, world = self.scenario, self.world
        for tick in range(sc.T):
            for ev in sc.events_at(tick):
                ev.apply(world)
                self.bus.publish(ev)
            proposed = self.router.routes(world, tick)
            installed, rejected = {}, {}
            for f in world.flows:                     # guarda: nunca instala rota inválida
                why = validate_route(world.net, f, proposed.get(f.id))
                if why is None:
                    installed[f.id] = proposed[f.id]
                else:
                    rejected[f.id] = why
            ev_ = evaluate(world.net, world.flows, installed)
            rates = self.allocator.allocate(world.net, world.flows, installed, ev_)
            total = sum(f.demand for f in world.flows)
            good = sum(rates[f.id] for f in world.flows) / total if total else 1.0
            self.records.append(TickRecord(tick, list(ev_.latency.values()), list(ev_.risk.values()),
                                           good, utility(world.flows, rates), ev_.J, rejected))
        return summarize(self.records, sc.events, self.router.decision_ms, sc.T)
