"""Demonstração de segurança em laboratório: sobe um gateway LOCAL (127.0.0.1) e mostra
  1) tráfego legítimo aceito;  2) falsificação (assinatura inválida) -> alerta + bloqueio do IP;
  3) replay de mensagem de boot antigo (VULN-001) -> 409 + alerta;  4) análise do log de tráfego.
Só funciona contra o loopback: não aponta para nenhum outro host."""
import json
import os
import tempfile
import threading
import urllib.error
import urllib.request

from pura.monitor import TrafficMonitor, analyze_log
from pura.security import sign
from pura.server import State, make_server

SECRET = b"segredo-de-demonstracao-16+"


def post(port, body, sig):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/telemetry", data=body,
                                 headers={"X-Signature": sig}, method="POST")
    try:
        return urllib.request.urlopen(req, timeout=3).status
    except urllib.error.HTTPError as exc:
        return exc.code


def msg(boot, seq):
    return json.dumps({"node": "S1", "boot": boot, "seq": seq, "t": 26.0, "h": 52, "ppm": 640}).encode()


def main():
    log = os.path.join(tempfile.mkdtemp(), "trafego.jsonl")
    state = State(SECRET, TrafficMonitor(bad_sig_limit=5, block_s=60), traffic_log=log)
    srv, _ = make_server("127.0.0.1", 0, state)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    print("== 1) Tráfego legítimo do ESP32 (boot=111)")
    first = msg(111, 1)
    print("   seq=1 ->", post(port, first, sign(SECRET, first)))
    second = msg(111, 2)
    print("   seq=2 ->", post(port, second, sign(SECRET, second)))

    print("== 2) O ESP32 reinicia (boot=222) e continua enviando")
    third = msg(222, 1)
    print("   boot=222 seq=1 ->", post(port, third, sign(SECRET, third)))

    print("== 3) Atacante reenvia mensagem capturada do boot antigo (VULN-001)")
    print("   replay (boot=111, seq=2) ->", post(port, second, sign(SECRET, second)), "(409 = rejeitado)")

    print("== 4) Falsificação: 6 mensagens com assinatura inválida")
    codes = [post(port, msg(999, i), "00" * 32) for i in range(6)]
    print("   códigos:", codes, "(401 ... depois 429 = IP bloqueado)")
    print("   mensagem legítima durante o bloqueio ->", post(port, msg(222, 2), sign(SECRET, msg(222, 2))))

    print("== 5) Alertas do monitor")
    for a in state.monitor.snapshot()["alerts"]:
        print(f"   [{a['severity']:6}] {a['kind']:20} {a['source']:12} {a['detail']}")
    srv.shutdown()
    srv.server_close()

    print("== 6) Análise offline do log de tráfego (python -m pura.monitor <arquivo>)")
    res = analyze_log(log)
    print("   eventos:", res["events"], "| por IP:", res["by_ip"], "| bloqueados:", res["blocked"])


if __name__ == "__main__":
    main()
