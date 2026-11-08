"""Testes ponta a ponta para o controle remoto manual com controle automático local."""
import base64
import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from pura.security import sign, verify
from pura.server import State, make_server

SECRET = b"segredo-de-teste-com-mais-de-16"
DASHBOARD_PASSWORD = "senha-dashboard-teste-com-16"


def http_request(port, path, body=None, headers=None, method=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body, headers=headers or {},
        method=method or ("POST" if body is not None else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


class FanRemoteControlTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"PURA_DASHBOARD_PASSWORD": DASHBOARD_PASSWORD})
        self.env.start()
        self.state = State(SECRET)
        self.server, _ = make_server("127.0.0.1", 0, self.state)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.auth = "Basic " + base64.b64encode(
            f"pura:{DASHBOARD_PASSWORD}".encode()).decode()
        self.control_nonce_counter = 0
        self.dashboard_headers = {
            "Authorization": self.auth,
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{self.port}",
            "X-PURA-Action": "fan-control",
        }
        # Registra o nó e informa que o relé está fisicamente desligado.
        telemetry = json.dumps({"node": "S1", "boot": 1, "seq": 1,
                                "t": 25, "h": 50, "ppm": 1500, "fan": False}).encode()
        status, _, _ = http_request(self.port, "/telemetry", telemetry,
                                    {"Content-Type": "application/json",
                                     "X-Signature": sign(SECRET, telemetry)})
        self.assertEqual(status, 200)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.env.stop()

    def dashboard_command(self, payload, headers=None):
        merged = dict(self.dashboard_headers if headers is None else headers)
        return http_request(self.port, "/api/fan", json.dumps(payload).encode(), merged)

    def fetch_signed_control(self):
        self.control_nonce_counter += 1
        nonce = f"{0x1020304050607080 + self.control_nonce_counter:016x}"
        request_message = f"GET\n/control\nS1\n{nonce}".encode()
        status, body, headers = http_request(
            self.port, f"/control?node=S1&nonce={nonce}",
            headers={"X-Request-Signature": sign(SECRET, request_message)})
        self.assertEqual(status, 200)
        self.assertTrue(verify(SECRET, body, headers["X-Signature"]))
        command = json.loads(body)
        self.assertEqual(command["nonce"], nonce)
        return command

    def test_dashboard_forca_ligar_e_esp32_recebe_comando_assinado(self):
        status, body, _ = self.dashboard_command({"node": "S1", "mode": "manual", "fan": True})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["fan"])
        self.assertEqual(self.fetch_signed_control()["mode"], "manual")
        command = self.fetch_signed_control()
        self.assertTrue(command["fan"])

    def test_dashboard_forca_desligar(self):
        status, _, _ = self.dashboard_command({"node": "S1", "mode": "manual", "fan": False})
        self.assertEqual(status, 200)
        command = self.fetch_signed_control()
        self.assertEqual(command["mode"], "manual")
        self.assertFalse(command["fan"])

    def test_dashboard_retorna_controle_automatico_ao_esp32(self):
        self.dashboard_command({"node": "S1", "mode": "manual", "fan": True})
        status, _, _ = self.dashboard_command({"node": "S1", "mode": "auto"})
        self.assertEqual(status, 200)
        command = self.fetch_signed_control()
        self.assertEqual(command["mode"], "auto")
        # Em AUTO, o servidor devolve apenas o último estado físico; a decisão é local.
        self.assertFalse(command["fan"])

    def test_comando_exige_autenticacao_e_protecao_csrf(self):
        no_auth = dict(self.dashboard_headers)
        no_auth.pop("Authorization")
        self.assertEqual(self.dashboard_command(
            {"node": "S1", "mode": "manual", "fan": True}, no_auth)[0], 401)
        bad_origin = dict(self.dashboard_headers)
        bad_origin["Origin"] = "https://site-malicioso.example"
        self.assertEqual(self.dashboard_command(
            {"node": "S1", "mode": "manual", "fan": True}, bad_origin)[0], 403)

    def test_rejeita_no_nao_registrado_e_payload_invalido(self):
        self.assertEqual(self.dashboard_command(
            {"node": "S2", "mode": "manual", "fan": True})[0], 404)
        self.assertEqual(self.dashboard_command(
            {"node": "S1", "mode": "manual", "fan": "true"})[0], 400)
        self.assertEqual(self.dashboard_command(
            {"node": "S1", "mode": "auto", "fan": False})[0], 400)

    def test_dashboard_html_exposes_direct_fan_control_panel(self):
        status, body, _ = http_request(self.port, "/", headers={"Authorization": self.auth})
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn('href="#fanControl"', html)
        self.assertIn('id="fanControl"', html)
        self.assertIn('id="fanForceOn"', html)
        self.assertIn('id="fanForceOff"', html)
        self.assertIn('id="fanReturnAuto"', html)
        self.assertIn("fetch('/api/fan'", html)


if __name__ == "__main__":
    unittest.main()
