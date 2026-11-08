"""Testes de regressão das vulnerabilidades encontradas (ver docs/VULNERABILIDADES.md)."""
import base64
import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from pura.monitor import TrafficMonitor
from pura.security import ReplayGuard, WeakSecretError, load_secret, sign, timestamp_ok
from pura.server import BoundedThreadingHTTPServer, State, make_handler, make_server

SECRET = b"segredo-de-teste-com-mais-de-16"


def request(port, path, body=None, sig=None, method=None, headers=None):
    headers = dict(headers or {})
    if sig is not None:
        headers["X-Signature"] = sig
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, headers=headers,
                                 method=method or ("POST" if body is not None else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers)


def msg(boot, seq, node="S1", ppm=500):
    return json.dumps({"node": node, "boot": boot, "seq": seq, "t": 25.0, "h": 50, "ppm": ppm}).encode()


class ServerHarness(unittest.TestCase):
    def start(self, monitor=None):
        self.state = State(SECRET, monitor or TrafficMonitor())
        self.srv, _ = make_server("127.0.0.1", 0, self.state)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        if hasattr(self, "srv"):
            self.srv.shutdown()
            self.srv.server_close()


class Vuln001Replay(ServerHarness):
    def test_guarda_rejeita_boot_antigo(self):
        g = ReplayGuard()
        self.assertTrue(g.accept("S1", 111, 5))
        self.assertTrue(g.accept("S1", 222, 1))          # o ESP32 reiniciou
        self.assertFalse(g.accept("S1", 111, 5))         # replay do boot antigo (antes era aceito)
        self.assertFalse(g.accept("S1", 111, 3))
        self.assertTrue(g.accept("S1", 111, 6))          # seq novo no mesmo boot continua válido

    def test_replay_de_boot_antigo_ponta_a_ponta(self):
        self.start()
        a1, b1 = msg(111, 5), msg(222, 1)
        self.assertEqual(request(self.port, "/telemetry", a1, sign(SECRET, a1))[0], 200)
        self.assertEqual(request(self.port, "/telemetry", b1, sign(SECRET, b1))[0], 200)
        self.assertEqual(request(self.port, "/telemetry", a1, sign(SECRET, a1))[0], 409)
        self.assertEqual(self.state.counters["replay"], 1)
        self.assertIn("REPLAY", [a.kind for a in self.state.monitor.alerts])


class ReplayCapacity(ServerHarness):
    def test_gateway_recusa_novo_no_quando_capacidade_anti_replay_acaba(self):
        self.start()
        self.state.replay = ReplayGuard(max_nodes=1)
        first = msg(1, 1, node="S1")
        second = msg(1, 1, node="S2")
        self.assertEqual(request(self.port, "/telemetry", first, sign(SECRET, first))[0], 200)
        self.assertEqual(request(self.port, "/telemetry", second, sign(SECRET, second))[0], 503)
        self.assertEqual(self.state.counters["capacity_rejected"], 1)
        self.assertFalse(self.state.replay.accept("S1", 1, 1))


class Vuln002SegredoFraco(unittest.TestCase):
    def test_sem_segredo_o_gateway_nao_sobe(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(WeakSecretError):
                load_secret()
        with mock.patch.dict(os.environ, {"PURA_SECRET": "curto"}, clear=True):
            with self.assertRaises(WeakSecretError):
                load_secret()

    def test_segredo_forte_e_modo_laboratorio(self):
        with mock.patch.dict(os.environ, {"PURA_SECRET": "x" * 16}, clear=True):
            self.assertEqual(load_secret(), b"x" * 16)
        with mock.patch.dict(os.environ, {"PURA_ALLOW_DEV_SECRET": "1"}, clear=True):
            self.assertGreaterEqual(len(load_secret()), 16)


class Vuln003ForcaBrutaEFlood(ServerHarness):
    def test_rajada_de_assinaturas_invalidas_bloqueia_o_ip(self):
        self.start(TrafficMonitor(bad_sig_limit=3, block_s=60))
        body = msg(1, 1)
        codes = [request(self.port, "/telemetry", body, "00" * 32)[0] for _ in range(3)]
        self.assertEqual(codes, [401, 401, 401])
        # depois do limite, até uma mensagem legítima é barrada (429) durante o bloqueio
        self.assertEqual(request(self.port, "/telemetry", body, sign(SECRET, body))[0], 429)
        self.assertEqual(request(self.port, "/control?node=S1")[0], 429)
        self.assertEqual(request(self.port, "/healthz")[0], 200)     # health check segue livre
        self.assertIn("BAD_SIGNATURE_BURST", [a.kind for a in self.state.monitor.alerts])

    def test_flood_de_leituras_bloqueia_o_ip(self):
        self.start(TrafficMonitor(flood_limit=10, block_s=60))
        codes = [request(self.port, "/control?node=S1")[0] for _ in range(12)]
        self.assertIn(429, codes)
        self.assertIn("FLOOD", [a.kind for a in self.state.monitor.alerts])


class Vuln005XForwardedFor(ServerHarness):
    def _get_with_xff(self, xff):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/control?node=S1",
                                     headers={"X-Forwarded-For": xff})
        try:
            return urllib.request.urlopen(req, timeout=3).status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_cliente_nao_consegue_forjar_o_ip_para_fugir_do_bloqueio(self):
        with mock.patch.dict(os.environ, {"TRUST_PROXY": "1", "PROXY_HOPS": "1"}):
            self.start(TrafficMonitor(flood_limit=5, block_s=60))
            # o atacante forja um IP diferente a cada requisição, no início da lista;
            # o proxy confiável acrescenta o IP real (203.0.113.7) ao fim
            codes = [self._get_with_xff(f"10.9.9.{i}, 203.0.113.7") for i in range(8)]
        self.assertIn(429, codes)
        self.assertTrue(self.state.monitor.is_blocked("203.0.113.7"))
        self.assertFalse(self.state.monitor.is_blocked("10.9.9.1"))

    def test_sem_proxy_confiavel_o_cabecalho_e_ignorado(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.start(TrafficMonitor(flood_limit=5, block_s=60))
            [self._get_with_xff("203.0.113.7") for _ in range(8)]
        self.assertTrue(self.state.monitor.is_blocked("127.0.0.1"))
        self.assertFalse(self.state.monitor.is_blocked("203.0.113.7"))


class Vuln006ReplayAposReinicio(ServerHarness):
    """O ReplayGuard vive em RAM: reiniciar o gateway (ou o plano gratuito hibernar) o zerava."""

    @staticmethod
    def signed(ts=None, boot=111, seq=5):
        d = {"node": "S1", "boot": boot, "seq": seq, "t": 25.0, "ppm": 500}
        if ts is not None:
            d["ts"] = ts
        return json.dumps(d).encode()

    def test_funcao_de_janela(self):
        now = 1_800_000_000.0
        self.assertTrue(timestamp_ok(now - 10, now, required=True))
        self.assertFalse(timestamp_ok(now - 3600, now, required=True))
        self.assertFalse(timestamp_ok(now + 3600, now, required=True))     # relógio no futuro
        self.assertFalse(timestamp_ok(None, now, required=True))
        self.assertTrue(timestamp_ok(None, now, required=False))           # modo laboratório (HTTP, sem NTP)
        self.assertFalse(timestamp_ok(now - 3600, now, required=False))    # se existe, sempre é validado
        self.assertFalse(timestamp_ok("agora", now, required=True))
        self.assertFalse(timestamp_ok(True, now, required=True))
        self.assertFalse(timestamp_ok(float("nan"), now, required=True))
        self.assertFalse(timestamp_ok(float("inf"), now, required=True))
        self.assertFalse(timestamp_ok(now, now, required=True, window_s=float("nan")))

    def test_replay_apos_reinicio_do_gateway_e_barrado(self):
        with mock.patch.dict(os.environ, {"PURA_REQUIRE_TS": "1"}):
            self.start()
            old = self.signed(ts=int(time.time()) - 600)       # capturada há 10 min
            # estado zerado (como após reinício): o ReplayGuard nunca viu esta mensagem
            self.assertEqual(request(self.port, "/telemetry", old, sign(SECRET, old))[0], 409)
            fresh = self.signed(ts=int(time.time()), seq=6)
            self.assertEqual(request(self.port, "/telemetry", fresh, sign(SECRET, fresh))[0], 200)
            # a guarda de (boot, seq) continua valendo dentro da janela
            self.assertEqual(request(self.port, "/telemetry", fresh, sign(SECRET, fresh))[0], 409)

    def test_ts_ausente_e_rejeitado_quando_exigido(self):
        with mock.patch.dict(os.environ, {"PURA_REQUIRE_TS": "1"}):
            self.start()
            no_ts = self.signed()
            self.assertEqual(request(self.port, "/telemetry", no_ts, sign(SECRET, no_ts))[0], 409)
        self.assertIn("REPLAY", [a.kind for a in self.state.monitor.alerts])

    def test_modo_laboratorio_aceita_sem_ts(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.start()
            no_ts = self.signed()
            self.assertEqual(request(self.port, "/telemetry", no_ts, sign(SECRET, no_ts))[0], 200)


class Vuln007ComandoAmarradoAoNo(ServerHarness):
    """Segredo único compartilhado: um comando assinado para S2 também seria válido para S1.
    O gateway amarra o nó ao corpo assinado; o firmware confere `node` antes de acionar o relé."""

    def test_comando_assinado_carrega_no_nonce_e_sequencia(self):
        self.start()
        for node in ("S1", "S2"):
            self.state.policy.update(node, 500, 25)
            nonce = "0011223344556677"
            request_message = f"GET\n/control\n{node}\n{nonce}".encode()
            headers = {"X-Request-Signature": sign(SECRET, request_message)}
            status, _ = request(self.port, f"/control?node={node}&nonce={nonce}", headers=headers)
            self.assertEqual(status, 200)
            with urllib.request.urlopen(urllib.request.Request(
                    f"http://127.0.0.1:{self.port}/control?node={node}&nonce={nonce}",
                    headers=headers), timeout=3) as response:
                body = response.read()
                sig = response.headers["X-Signature"]
            data = json.loads(body)
            self.assertEqual(data["node"], node)
            self.assertEqual(data["nonce"], nonce)
            self.assertGreater(data["cseq"], 0)
            self.assertEqual(sig, sign(SECRET, body))

    def test_comando_rejeita_requisicao_sem_hmac_ou_nonce_invalido(self):
        self.start()
        self.state.policy.update("S1", 500, 25)
        self.assertEqual(request(self.port, "/control?node=S1&nonce=0011223344556677")[0], 401)
        nonce = "0011223344556677"
        headers = {"X-Request-Signature": sign(SECRET, b"GET\n/control\nS1\n" + nonce.encode())}
        self.assertEqual(request(self.port, "/control?node=S1&nonce=invalid", headers=headers)[0], 400)


class TelemetryValidationTests(ServerHarness):
    def test_rejeita_string_no_campo_numerico_assinado(self):
        self.start()
        body = json.dumps({"node": "S1", "boot": 1, "seq": 1,
                           "t": 25, "h": 50, "ppm": "valor_invalido"}).encode()
        self.assertEqual(request(self.port, "/telemetry", body, sign(SECRET, body))[0], 400)
        self.assertNotIn("S1", self.state.policy.fan)

    def test_rejeita_nan_e_uint32_invalido(self):
        self.start()
        for payload in (
            {"node": "S1", "boot": 1, "seq": 1, "t": 25, "h": 50, "ppm": float("nan")},
            {"node": "S1", "boot": -1, "seq": 2, "t": 25, "h": 50, "ppm": 500},
            {"node": "S1", "boot": 1, "seq": True, "t": 25, "h": 50, "ppm": 500},
            {"node": "../bad", "boot": 1, "seq": 3, "t": 25, "h": 50, "ppm": 500},
        ):
            body = json.dumps(payload).encode()
            self.assertEqual(request(self.port, "/telemetry", body, sign(SECRET, body))[0], 400)
        self.assertEqual(self.state.counters["accepted"], 0)


class DashboardAuthTests(ServerHarness):
    def test_dashboard_e_api_exigem_basic_auth_quando_configurado(self):
        password = "dashboard-secret-com-mais-de-16"
        with mock.patch.dict(os.environ, {"PURA_DASHBOARD_PASSWORD": password}, clear=True):
            self.start()
            self.assertEqual(request(self.port, "/api/telemetry")[0], 401)
            token = base64.b64encode(f"pura:{password}".encode()).decode()
            headers = {"Authorization": f"Basic {token}"}
            self.assertEqual(request(self.port, "/api/telemetry", headers=headers)[0], 200)
            self.assertEqual(request(self.port, "/healthz")[0], 200)

    def test_bind_externo_exige_senha_forte(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                make_server("0.0.0.0", 0, State(SECRET))
        with mock.patch.dict(os.environ, {"PURA_DASHBOARD_PASSWORD": "short"}, clear=True):
            with self.assertRaises(ValueError):
                make_server("0.0.0.0", 0, State(SECRET))
        with mock.patch.dict(os.environ, {"PURA_DASHBOARD_PASSWORD": "dashboard-secret-com-mais-de-16"}, clear=True):
            server, _ = make_server("0.0.0.0", 0, State(SECRET))
            server.server_close()


class ServerResourceLimitTests(ServerHarness):
    def test_endpoints_de_leitura_entram_no_monitoramento_de_flood(self):
        self.start(TrafficMonitor(flood_limit=4, block_s=60))
        statuses = [request(self.port, "/api/alerts")[0] for _ in range(7)]
        self.assertIn(429, statuses)
        self.assertIn("FLOOD", [alert.kind for alert in self.state.monitor.alerts])

    def test_servidor_recusa_exceder_limite_de_workers(self):
        handler = make_handler(State(SECRET))
        server = BoundedThreadingHTTPServer(("127.0.0.1", 0), handler, max_workers=1)
        try:
            self.assertTrue(server._worker_slots.acquire(blocking=False))
            self.assertFalse(server._worker_slots.acquire(blocking=False))
            server._worker_slots.release()
        finally:
            server.server_close()

    def test_peer_nao_confiavel_nao_pode_injetar_x_forwarded_for(self):
        with mock.patch.dict(os.environ, {
            "TRUST_PROXY": "1", "PROXY_HOPS": "1",
            "PURA_TRUSTED_PROXY_CIDRS": "203.0.113.0/24"
        }):
            self.start(TrafficMonitor(flood_limit=5, block_s=60))
            for _ in range(7):
                self._request = urllib.request.Request(
                    f"http://127.0.0.1:{self.port}/api/alerts",
                    headers={"X-Forwarded-For": "203.0.113.7"})
                try:
                    urllib.request.urlopen(self._request, timeout=3).read()
                except urllib.error.HTTPError:
                    pass
        self.assertTrue(self.state.monitor.is_blocked("127.0.0.1"))
        self.assertFalse(self.state.monitor.is_blocked("203.0.113.7"))


class Hardening(ServerHarness):
    def test_cabecalhos_de_seguranca(self):
        self.start()
        status, headers = request(self.port, "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))

    def test_corpo_gigante_e_caminho_malicioso(self):
        self.start()
        big = b"{" + b"a" * 5000 + b"}"
        self.assertEqual(request(self.port, "/telemetry", big, sign(SECRET, big))[0], 400)
        self.assertEqual(request(self.port, "/../../etc/passwd")[0], 404)
        self.assertEqual(request(self.port, "/control/../../etc/passwd")[0], 404)

    def test_nao_ha_endpoint_nao_autenticado_que_acione_o_atuador(self):
        self.start()
        for path in ("/fan?on=1", "/relay", "/api/fan", "/control?node=S1&fan=1"):
            status, _ = request(self.port, path, method="POST", body=b"{}")
            self.assertIn(status, (400, 401, 403, 404))
        # GET /control só devolve estado; o ventilador segue desligado
        self.assertFalse(self.state.policy.fan.get("S1", False))

    def test_alertas_e_saude(self):
        self.start()
        self.assertEqual(request(self.port, "/healthz")[0], 200)
        self.assertEqual(request(self.port, "/api/alerts")[0], 200)


if __name__ == "__main__":
    unittest.main()
