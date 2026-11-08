import unittest

from pura.bandwidth import ProportionalAllocator, PSOAllocator, utility
from pura.model import ekey, evaluate
from pura.routers import make_router
from pura.scenario import build_scenario
from pura.events import TrafficSurge


class BandwidthTests(unittest.TestCase):
    def test_pso_e_factivel_e_nao_pior_que_proporcional(self):
        sc = build_scenario(2, 2.0)
        w = sc.world.clone()
        TrafficSurge(0, factor=2.0).apply(w)
        routes = make_router("dijkstra").routes(w, 0)
        ev = evaluate(w.net, w.flows, routes)
        prop = ProportionalAllocator().allocate(w.net, w.flows, routes, ev)
        pso = PSOAllocator(1).allocate(w.net, w.flows, routes, ev)
        loads = {}
        for f in w.flows:
            for a, b in zip(routes[f.id], routes[f.id][1:]):
                loads[ekey(a, b)] = loads.get(ekey(a, b), 0) + pso[f.id]
        for k, ld in loads.items():
            self.assertLessEqual(ld, w.net.links[k].capacity + 1e-6)
        for f in w.flows:
            self.assertLessEqual(pso[f.id], f.demand + 1e-6)
        self.assertGreaterEqual(utility(w.flows, pso), utility(w.flows, prop) - 1e-9)


if __name__ == "__main__":
    unittest.main()
