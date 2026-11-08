import json
import threading
import unittest
import urllib.error
import urllib.request

from pura.security import ReplayCapacityError, ReplayGuard, sign, verify
from pura.server import State, make_server

SECRET = b"segredo-de-teste"


def post(port, body: bytes, sig: str):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/telemetry", data=body, method="POST",
                                 headers={"X-Signature": sig, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


class SecurityTests(unittest.TestCase):
    def test_hmac(self):
        b = b'{"node":"S1"}'
        s = sign(SECRET, b)
        self.assertTrue(verify(SECRET, b, s))
        self.assertFalse(verify(SECRET, b + b" ", s))
        self.assertFalse(verify(b"outro", b, s))
        self.assertFalse(verify(SECRET, b, ""))

    def test_replay_guard(self):
        g = ReplayGuard()
        self.assertTrue(g.accept("S1", 1, 1))
        self.assertTrue(g.accept("S1", 1, 2))
        self.assertFalse(g.accept("S1", 1, 2))
        self.assertFalse(g.accept("S1", 1, 1))
        self.assertTrue(g.accept("S1", 2, 1))      # novo boot
        self.assertFalse(g.accept("S1", 1, 2))     # boot antigo: replay (VULN-001)

    def test_replay_guard_limita_identidades_sem_descartar_estado_antigo(self):
        g = ReplayGuard(max_nodes=1)
        self.assertTrue(g.accept("S1", 10, 1))
        with self.assertRaises(ReplayCapacityError):
            g.accept("S2", 20, 1)
        self.assertFalse(g.accept("S1", 10, 1))  # estado de S1 continua protegido

    def test_servidor_end_to_end(self):
        srv, st = make_server("127.0.0.1", 0, State(SECRET))
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            ok = json.dumps({"node": "S1", "boot": 7, "seq": 1, "t": 24.0, "h": 50, "ppm": 1500}).encode()
            self.assertEqual(post(port, ok, sign(SECRET, ok)), 200)
            self.assertEqual(post(port, ok, sign(SECRET, ok)), 409)             # replay
            self.assertEqual(post(port, ok, "00" * 32), 401)                    # assinatura errada
            adulterado = ok.replace(b"1500", b"400 ")
            self.assertEqual(post(port, adulterado, sign(SECRET, ok)), 401)     # corpo adulterado
            self.assertEqual(post(port, b"{}", sign(SECRET, b"{}")), 400)       # campos faltando
            self.assertEqual(st.counters["accepted"], 1)
            self.assertEqual(st.counters["replay"], 1)
            self.assertEqual(st.counters["bad_signature"], 2)
            # O gateway não decide pelo ppm: em AUTO devolve o estado físico reportado.
            nonce = "1020304050607080"
            request_message = f"GET\n/control\nS1\n{nonce}".encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/control?node=S1&nonce={nonce}",
                headers={"X-Request-Signature": sign(SECRET, request_message)})
            with urllib.request.urlopen(req, timeout=3) as r:
                body, sig = r.read(), r.headers["X-Signature"]
            self.assertTrue(verify(SECRET, body, sig))
            self.assertFalse(json.loads(body)["fan"])
            self.assertEqual(json.loads(body)["mode"], "auto")
            self.assertEqual(json.loads(body)["nonce"], nonce)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
