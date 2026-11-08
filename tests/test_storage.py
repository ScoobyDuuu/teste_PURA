import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pura.server import FanPolicy, State
from tools import security_demo


SECRET = b"segredo-de-teste-com-mais-de-16"


class StorageTests(unittest.TestCase):
    def test_politica_do_ventilador_limita_nos(self):
        policy = FanPolicy(max_nodes=2)
        policy.update("S1", 1200, 25)
        policy.update("S2", 500, 25)
        policy.update("S3", 500, 25)
        self.assertEqual(set(policy.fan), {"S2", "S3"})
        self.assertEqual(set(policy.cseq), {"S2", "S3"})

    def test_gateway_apenas_registra_estado_fisico_e_nao_decide_pelos_sensores(self):
        policy = FanPolicy()
        # Mesmo com ppm alto, a decisão automática continua sendo do ESP32.
        policy.update("S1", 1500, 25, False)
        self.assertFalse(policy.fan["S1"])
        self.assertEqual(policy.mode("S1"), "auto")
        # O dashboard pode aplicar um override remoto.
        policy.set_manual("S1", True)
        self.assertTrue(policy.target("S1"))
        self.assertEqual(policy.mode("S1"), "manual")
        # A telemetria continua refletindo o estado físico medido no ESP32.
        policy.update("S1", None, None, True)
        self.assertTrue(policy.fan["S1"])
        # Retornar a AUTO remove o override e devolve a decisão à placa.
        policy.set_auto("S1")
        self.assertEqual(policy.mode("S1"), "auto")
        self.assertTrue(policy.target("S1"))

        recovered = FanPolicy()
        recovered.update("S1", None, None, True)
        self.assertTrue(recovered.fan["S1"])

    def test_log_de_trafego_rotaciona_e_respeita_limite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "traffic.jsonl")
            state = State(SECRET, traffic_log=path, traffic_log_max_bytes=1024,
                          traffic_log_backups=2)
            for index in range(100):
                state.log_traffic("192.0.2.10", "accepted", f"S{index % 4}", 128)

            files = [Path(path), Path(f"{path}.1"), Path(f"{path}.2")]
            existing = [file for file in files if file.exists()]
            self.assertGreaterEqual(len(existing), 2)
            self.assertLessEqual(len(existing), 3)
            self.assertTrue(all(file.stat().st_size <= 1024 for file in existing))

    def test_log_legado_maior_que_limite_e_reduzido_ao_rotacionar(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "legacy.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                for index in range(500):
                    fh.write(f'{{"ts":{index},"ip":"192.0.2.1","outcome":"accepted"}}\n')
            state = State(SECRET, traffic_log=path, traffic_log_max_bytes=1024,
                          traffic_log_backups=2)
            state.log_traffic("192.0.2.1", "accepted", "S1", 128)
            backup = Path(f"{path}.1")
            self.assertTrue(backup.exists())
            self.assertLessEqual(backup.stat().st_size, 1024)
            self.assertLessEqual(Path(path).stat().st_size, 1024)

    def test_demo_remove_diretorio_temporario_ao_terminar(self):
        created_dirs = []
        original = tempfile.TemporaryDirectory

        def tracked_temp_dir(*args, **kwargs):
            directory = original(*args, **kwargs)
            created_dirs.append(directory.name)
            return directory

        output = io.StringIO()
        with mock.patch.object(security_demo.tempfile, "TemporaryDirectory", side_effect=tracked_temp_dir):
            with contextlib.redirect_stdout(output):
                security_demo.main()

        self.assertTrue(created_dirs)
        self.assertTrue(all(not os.path.exists(path) for path in created_dirs))
        self.assertIn("eventos:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
