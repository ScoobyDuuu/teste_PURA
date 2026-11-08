import unittest

from pura.graph import dijkstra
from pura.model import Flow, Network, evaluate, validate_route, UNTRUSTED


def tiny():
    n = Network()
    for name, z in [("A", "edge"), ("B", "core"), ("C", "core"), ("U", UNTRUSTED), ("D", "core")]:
        n.add_node(name, z)
    n.add_link("A", "B", 5, 100, 0.9)
    n.add_link("B", "D", 5, 100, 0.9)
    n.add_link("A", "C", 8, 100, 0.9)
    n.add_link("C", "D", 8, 100, 0.9)
    n.add_link("A", "U", 1, 100, 0.3)
    n.add_link("U", "D", 1, 100, 0.3)
    return n


class ModelTests(unittest.TestCase):
    def test_validacao_motivos(self):
        n = tiny()
        f = Flow("f", "A", "D", 10, 1)
        k = Flow("k", "A", "D", 10, 1, restricted=True)
        self.assertIsNone(validate_route(n, f, ("A", "B", "D")))
        self.assertEqual(validate_route(n, f, ("A", "D")), "enlace_inexistente")
        self.assertEqual(validate_route(n, f, ("B", "D")), "extremos_invalidos")
        self.assertEqual(validate_route(n, f, ("A", "B", "A", "B", "D")), "laco")
        self.assertEqual(validate_route(n, k, ("A", "U", "D")), "zona_proibida")
        n.link("A", "B").up = False
        self.assertEqual(validate_route(n, f, ("A", "B", "D")), "enlace_caido")

    def test_rota_invalida_nao_gera_carga_e_e_penalizada(self):
        n = tiny()
        f = Flow("f", "A", "D", 10, 1)
        bom = evaluate(n, [f], {"f": ("A", "B", "D")})
        ruim = evaluate(n, [f], {"f": ("A", "D")})
        self.assertEqual(ruim.loads, {})
        self.assertIn("f", ruim.invalid)
        self.assertGreater(ruim.J, bom.J)

    def test_sobrecarga_reduz_goodput_e_aumenta_J(self):
        n = tiny()
        a = Flow("a", "A", "D", 80, 1)
        b = Flow("b", "A", "D", 80, 1)
        junto = evaluate(n, [a, b], {"a": ("A", "B", "D"), "b": ("A", "B", "D")})
        separado = evaluate(n, [a, b], {"a": ("A", "B", "D"), "b": ("A", "C", "D")})
        self.assertAlmostEqual(junto.goodput["a"], 100 / 160)
        self.assertEqual(separado.goodput["a"], 1.0)
        self.assertGreater(junto.J, separado.J)

    def test_dijkstra_respeita_zona_e_falhas(self):
        n = tiny()
        def ok(x):
            return n.zone[x] != UNTRUSTED

        self.assertEqual(dijkstra(n, "A", "D", lambda lk: lk.base_cost(), ok), ("A", "B", "D"))
        n.link("A", "B").up = False
        n.link("A", "C").up = False
        self.assertIsNone(dijkstra(n, "A", "D", lambda lk: lk.base_cost(), ok))
        self.assertEqual(dijkstra(n, "A", "D", lambda lk: lk.base_cost()), ("A", "U", "D"))


if __name__ == "__main__":
    unittest.main()
