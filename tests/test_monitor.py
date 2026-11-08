import json
import os
import tempfile
import unittest

from pura.monitor import TrafficMonitor, analyze_log


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.mon = TrafficMonitor(window_s=60, bad_sig_limit=5, flood_limit=20, block_s=100,
                                  silence_s=30, clock=self.clock)

    def kinds(self):
        return [a.kind for a in self.mon.alerts]

    def test_rajada_de_assinaturas_invalidas_gera_alerta_e_bloqueio(self):
        for _ in range(4):
            self.mon.record("10.0.0.9", "bad_signature")
        self.assertFalse(self.mon.is_blocked("10.0.0.9"))
        self.mon.record("10.0.0.9", "bad_signature")
        self.assertIn("BAD_SIGNATURE_BURST", self.kinds())
        self.assertTrue(self.mon.is_blocked("10.0.0.9"))
        self.assertFalse(self.mon.is_blocked("10.0.0.10"))

    def test_bloqueio_expira(self):
        for _ in range(5):
            self.mon.record("10.0.0.9", "bad_signature")
        self.clock.t += 101
        self.assertFalse(self.mon.is_blocked("10.0.0.9"))

    def test_assinaturas_invalidas_fora_da_janela_nao_somam(self):
        for _ in range(4):
            self.mon.record("10.0.0.9", "bad_signature")
        self.clock.t += 61
        self.mon.record("10.0.0.9", "bad_signature")
        self.assertNotIn("BAD_SIGNATURE_BURST", self.kinds())

    def test_flood(self):
        for _ in range(20):
            self.mon.record("10.0.0.7", "control", "S1")
        self.assertIn("FLOOD", self.kinds())
        self.assertTrue(self.mon.is_blocked("10.0.0.7"))

    def test_replay_gera_alerta(self):
        self.mon.record("10.0.0.5", "replay", "S1")
        self.assertEqual(self.kinds(), ["REPLAY"])

    def test_silencio_do_no_alerta_uma_vez(self):
        self.mon.record("10.0.0.2", "accepted", "S1")
        self.clock.t += 10
        self.assertEqual(self.mon.check_silence(), [])
        self.clock.t += 31
        self.assertEqual(len(self.mon.check_silence()), 1)
        self.assertEqual(self.mon.check_silence(), [])          # não repete
        self.mon.record("10.0.0.2", "accepted", "S1")           # voltou
        self.clock.t += 31
        self.assertEqual(len(self.mon.check_silence()), 1)

    def test_limites_de_ips_e_nos_rastreados(self):
        mon = TrafficMonitor(clock=self.clock, bad_sig_limit=1, max_tracked_ips=2,
                             max_tracked_nodes=2, node_retention_s=10)
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            mon.record(ip, "bad_signature")
        self.assertLessEqual(len(mon._blocked), 2)

        for node in ("S1", "S2", "S3"):
            mon.record("10.0.0.9", "accepted", node)
        self.assertLessEqual(len(mon._last_seen), 2)
        self.assertNotIn("S1", mon._last_seen)

        self.clock.t += 11
        mon.record("10.0.0.9", "accepted", "S4")
        self.assertLessEqual(len(mon._last_seen), 2)
        self.assertNotIn("S2", mon._last_seen)

    def test_analise_de_log_limita_ips_unicos(self):
        rows = [
            {"ts": 1000 + i, "ip": f"192.0.2.{i}", "outcome": "accepted", "node": "", "size": 10}
            for i in range(5)
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as fh:
            fh.write("\n".join(json.dumps(row) for row in rows))
            path = fh.name
        try:
            result = analyze_log(path, max_ips=2)
        finally:
            os.unlink(path)
        self.assertEqual(result["events"], 5)
        self.assertEqual(len(result["by_ip"]), 2)
        self.assertEqual(result["by_ip_omitted_events"], 3)

    def test_analise_rejeita_size_malformado_e_linha_excessiva(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "bad.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": 1000, "ip": "10.0.0.1", "outcome": "accepted", "size": "grande"}) + "\n")
            with self.assertRaisesRegex(ValueError, "linha 1"):
                analyze_log(path)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("x" * (64 * 1024 + 10) + "\n")
            with self.assertRaisesRegex(ValueError, "excede"):
                analyze_log(path)

    def test_configuracao_de_monitor_rejeita_limites_invalidos(self):
        with self.assertRaises(ValueError):
            TrafficMonitor(flood_limit=0)
        with self.assertRaises(ValueError):
            TrafficMonitor(window_s=float("inf"))

    def test_snapshot_e_analise_offline(self):
        rows = [{"ts": 1000 + i, "ip": "10.0.0.9", "outcome": "bad_signature", "node": "", "size": 90}
                for i in range(6)]
        rows += [{"ts": 1010, "ip": "10.0.0.2", "outcome": "accepted", "node": "S1", "size": 120}]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
            fh.write("\n".join(json.dumps(r) for r in rows))
            path = fh.name
        try:
            res = analyze_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(res["events"], 7)
        self.assertIn("10.0.0.9", res["blocked"])
        self.assertEqual(res["by_ip"]["10.0.0.9"]["bad_signature"], 6)
        self.assertEqual(res["alerts"][0]["kind"] in ("BAD_SIGNATURE_BURST", "NODE_SILENCE"), True)


if __name__ == "__main__":
    unittest.main()
