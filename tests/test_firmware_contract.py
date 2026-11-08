"""Testes estáticos do contrato de segurança/continuidade do firmware ESP32.

Eles não substituem a compilação com Arduino-ESP32 nem o ensaio em hardware real.
"""
from pathlib import Path
import unittest


FIRMWARE = Path(__file__).resolve().parents[1] / "firmware" / "esp32_node" / "esp32_node.ino"


class FirmwareContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIRMWARE.read_text(encoding="utf-8")

    def test_setup_nao_fica_bloqueado_esperando_wifi(self):
        wifi_setup = self.source.split("void startWiFi()", 1)[1].split("bool deadlineReached", 1)[0]
        self.assertIn("WiFi.begin(WIFI_SSID, WIFI_PASS)", wifi_setup)
        self.assertNotIn("while (WiFi.status() != WL_CONNECTED)", self.source)

    def test_controle_automatico_local_executa_antes_de_tentar_a_rede(self):
        loop = self.source.split("void loop()", 1)[1]
        self.assertLess(loop.index("readSensors()"), loop.index("const bool connected = WiFi.status()"))
        self.assertLess(loop.index("applyFanControl()"), loop.index("const bool connected = WiFi.status()"))
        self.assertIn("delay(5)", loop)
        self.assertNotIn("return;", loop)

    def test_comando_remoto_tem_override_mas_volta_a_auto_se_perder_nuvem(self):
        self.assertIn('const bool modeAuto = body.indexOf("\\"mode\\":\\"auto\\"") >= 0;', self.source)
        self.assertIn('const bool modeManual = body.indexOf("\\"mode\\":\\"manual\\"") >= 0;', self.source)
        self.assertIn("remoteOverrideActive = true", self.source)
        self.assertIn("remoteOverrideActive = false", self.source)
        self.assertIn("COMMAND_TIMEOUT_MS", self.source)
        self.assertIn("void applyFanControl()", self.source)

    def test_comando_exige_hmac_nonce_e_no_destino(self):
        fetch = self.source.split("bool fetchCommand()", 1)[1].split("void applyFanControl()", 1)[0]
        self.assertIn("X-Request-Signature", fetch)
        self.assertIn(r'\"nonce\"', fetch)
        self.assertIn(r'\"node\"', fetch)
        self.assertIn('"X-Signature"', fetch)

    def test_controle_local_nao_interpreta_dois_sensores_invalidos_como_ar_limpo(self):
        policy = self.source.split("void applyFanControl()", 1)[1].split("void startWiFi()", 1)[0]
        self.assertIn("isnan(ppmEstimate) && isnan(tempC)", policy)

    def test_firmware_usa_https_com_validacao_de_ca_e_nao_tls_inseguro(self):
        self.assertIn('tlsClient.setCACert(ROOT_CA)', self.source)
        self.assertNotIn('tlsClient.setInsecure', self.source)
        secrets = FIRMWARE.with_name("secrets.example.h").read_text(encoding="utf-8")
        self.assertIn('https://SEU-SERVICO.onrender.com', secrets)
        self.assertIn('ISRG Root X1', secrets)

    def test_firmware_reflete_polaridade_do_bc548(self):
        self.assertIn('constexpr bool RELAY_ACTIVE_LOW = false;', self.source)
        self.assertIn('GPIO26 HIGH liga o transistor', self.source)

    def test_limites_locais_coincidem_com_politica_do_gateway(self):
        self.assertIn('LOCAL_PPM_ON = 1000.0f', self.source)
        self.assertIn('LOCAL_PPM_OFF = 800.0f', self.source)
        self.assertIn('LOCAL_TEMP_ON = 30.0f', self.source)
        self.assertIn('LOCAL_TEMP_OFF = 28.0f', self.source)

    def test_firmware_tem_retentativa_progressiva_e_aquecimento_do_mq(self):
        self.assertIn('RETRY_MAX_MS = 60000', self.source)
        self.assertIn('MQ_WARMUP_MS = 60000', self.source)
        self.assertIn('retryDelayMs * 2UL', self.source)


if __name__ == "__main__":
    unittest.main()
