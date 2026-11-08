import unittest

from pura.events import EventBus, LinkFailure
from pura.model import UNTRUSTED, validate_route
from pura.routers import ROUTERS, make_router
from pura.routers.base import Router
from pura.scenario import build_scenario
from pura.simulator import Simulator


class BadRouter(Router):
    """Roteador malicioso/defeituoso: propõe rota por enlace inexistente e por zona proibida."""
    name = "bad"

    def decide(self, world, tick):
        return {f.id: (f.src, "U1", f.dst) for f in world.flows}


class RouterTests(unittest.TestCase):
    def test_observer_marca_dirty(self):
        sc = build_scenario(0)
        for name, expected in (("dijkstra", True), ("aco", True), ("static", False)):
            r = make_router(name)
            r.routes(sc.world.clone(), 0)
            self.assertFalse(r._dirty)
            bus = EventBus()
            bus.subscribe(r.on_event)
            bus.publish(LinkFailure(1, a="G", b="C1"))
            self.assertEqual(r._dirty, expected, name)

    def test_guarda_nunca_instala_rota_invalida(self):
        sc = build_scenario(0)
        sim = Simulator(sc, BadRouter())
        sim.run()
        for rec in sim.records:
            # K1/K2 são restritos (zona proibida); T2..T6 usam enlaces que não existem
            self.assertEqual(rec.invalid["K1"], "zona_proibida")
            self.assertEqual(rec.invalid["K2"], "zona_proibida")
            self.assertEqual(rec.invalid["T2"], "enlace_inexistente")
            # T1 (S1->U1->G) é a única rota proposta que realmente existe e é permitida
            self.assertNotIn("T1", rec.invalid)

    def test_roteadores_reativos_nunca_propoem_rota_invalida(self):
        for seed in (0, 1, 2):
            for surge in (1.5, 2.0):
                sc = build_scenario(seed, surge)
                for name in ROUTERS:
                    if name == "static":
                        continue
                    sim = Simulator(sc, make_router(name, seed))
                    res = sim.run()
                    self.assertEqual(res["rej_zone"], 0, (name, seed))
                    self.assertEqual(res["rej_down"], 0, (name, seed))
                    self.assertEqual(res["drop_frac"], 0.0, (name, seed))

    def test_static_fica_com_rota_obsoleta_apos_falha(self):
        sc = build_scenario(0)
        res = Simulator(sc, make_router("static")).run()
        self.assertGreater(res["rej_down"], 0)

    def test_fluxos_restritos_evitam_zona_nao_confiavel(self):
        sc = build_scenario(3)
        w = sc.world.clone()
        for name in ROUTERS:
            routes = make_router(name, 1).routes(w, 0)
            for f in w.flows:
                if f.restricted:
                    self.assertTrue(all(w.net.zone[n] != UNTRUSTED for n in routes[f.id]), name)
                    self.assertIsNone(validate_route(w.net, f, routes[f.id]))

    def test_determinismo_por_semente(self):
        a = Simulator(build_scenario(5), make_router("aco", 11)).run()
        b = Simulator(build_scenario(5), make_router("aco", 11)).run()
        # compute_ms e over_budget são derivados do tempo de parede e variam
        # com a carga da máquina; compare apenas as métricas determinísticas.
        a.pop("compute_ms")
        b.pop("compute_ms")
        a.pop("over_budget")
        b.pop("over_budget")
        self.assertEqual(a, b)

    def test_cenario_tem_eventos_dinamicos(self):
        kinds = {e.kind for e in build_scenario(0).events}
        self.assertTrue({"link_failure", "traffic_surge", "latency_spike"} <= kinds)


if __name__ == "__main__":
    unittest.main()
