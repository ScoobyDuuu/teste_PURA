/*
  P.U.R.A - Nó sensor/atuador ESP32 (nó S1 da topologia mesh)
  - Lê DHT11 (GPIO4) e MQ-135 (GPIO34, via divisor 10k/10k)
  - Envia telemetria ao gateway com assinatura HMAC-SHA256 + (boot, seq) contra replay
  - Se GATEWAY_URL começa com https://, usa TLS com verificação do certificado (ROOT_CA) e hora via NTP
  - Busca comando do ventilador (GET /control), VERIFICA a assinatura e só então aciona o relé (GPIO26)
  - Fail-safe: sem comando válido por 30 s, usa regra local com histerese
  Bibliotecas: "DHT sensor library" + "Adafruit Unified Sensor" (Adafruit). Demais são do core ESP32.
*/
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <time.h>
#include <DHT.h>
#include "mbedtls/md.h"
#include "secrets.h"

#define PIN_DHT 4
#define PIN_MQ 34
#define PIN_RELAY 26
#define PIN_LED 2
const bool RELAY_ACTIVE_LOW = true;
const float DIV_RATIO = 2.0, VCC_MQ = 5.0, RL_KOHM = 10.0, R0_KOHM = 76.63;  // calibre R0 em ar limpo
const float PARA = 116.6020682, PARB = 2.769034857;
const uint32_t PERIOD_MS = 5000, CMD_TIMEOUT_MS = 30000;
const float LOCAL_PPM_ON = 1200, LOCAL_PPM_OFF = 900, LOCAL_T_ON = 32, LOCAL_T_OFF = 29;

DHT dht(PIN_DHT, DHT11);
WiFiClientSecure tlsClient;
WiFiClient plainClient;
bool useTls = false;
uint32_t bootId, seqNo = 0, lastCmdSeq = 0, lastCmdMs = 0, lastSend = 0;
bool fanOn = false;
float temp = NAN, hum = NAN, ppm = NAN;

String hmacHex(const String &msg) {
  unsigned char out[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *)HMAC_SECRET, strlen(HMAC_SECRET));
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)msg.c_str(), msg.length());
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  String hex;
  for (int i = 0; i < 32; i++) { char b[3]; snprintf(b, 3, "%02x", out[i]); hex += b; }
  return hex;
}

bool safeEquals(const String &a, const String &b) {   // comparação em tempo constante
  if (a.length() != b.length()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < a.length(); i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

void setFan(bool on) {
  fanOn = on;
  digitalWrite(PIN_RELAY, (RELAY_ACTIVE_LOW ? !on : on) ? HIGH : LOW);
  digitalWrite(PIN_LED, on ? HIGH : LOW);
}

void readSensors() {
  float h = dht.readHumidity(), t = dht.readTemperature();
  if (!isnan(h) && !isnan(t)) { hum = h; temp = t; }
  uint32_t acc = 0;
  for (int i = 0; i < 16; i++) { acc += analogReadMilliVolts(PIN_MQ); delay(2); }
  float vao = (acc / 16.0) / 1000.0 * DIV_RATIO;
  if (vao > 0.05 && vao < VCC_MQ - 0.05) {
    float rs = (VCC_MQ - vao) / vao * RL_KOHM;
    ppm = constrain(PARA * pow(rs / R0_KOHM, -PARB), 0, 10000);
  }
}

WiFiClient &netClient() { return useTls ? static_cast<WiFiClient &>(tlsClient) : plainClient; }

void syncTime() {   // certificados TLS só validam com a data correta
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  time_t now = 0;
  uint32_t t0 = millis();
  while (now < 1700000000 && millis() - t0 < 20000) { delay(300); time(&now); }
  Serial.println(now >= 1700000000 ? "hora sincronizada" : "AVISO: sem NTP, o TLS vai falhar");
}

void sendTelemetry() {
  // VULN-006: em modo https (com NTP) o corpo assinado leva o carimbo de tempo; o gateway rejeita fora da janela.
  String ts = useTls ? String(",\"ts\":") + String((unsigned long)time(nullptr)) : String("");
  String body = String("{\"node\":\"") + NODE_ID + "\",\"boot\":" + bootId + ",\"seq\":" + (++seqNo) + ts +
                ",\"t\":" + (isnan(temp) ? "null" : String(temp, 1)) +
                ",\"h\":" + (isnan(hum) ? "null" : String(hum, 0)) +
                ",\"ppm\":" + (isnan(ppm) ? "null" : String(ppm, 0)) +
                ",\"fan\":" + (fanOn ? "true" : "false") + ",\"rssi\":" + WiFi.RSSI() + "}";
  HTTPClient http;
  http.begin(netClient(), String(GATEWAY_URL) + "/telemetry");
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Signature", hmacHex(body));
  int code = http.POST(body);
  Serial.printf("telemetria seq=%lu -> HTTP %d\n", (unsigned long)seqNo, code);
  http.end();
}

void fetchCommand() {
  HTTPClient http;
  http.begin(netClient(), String(GATEWAY_URL) + "/control?node=" + NODE_ID);
  const char *keys[] = {"X-Signature"};
  http.collectHeaders(keys, 1);
  if (http.GET() == 200) {
    String body = http.getString(), sig = http.header("X-Signature");
    if (!safeEquals(hmacHex(body), sig)) { Serial.println("comando REJEITADO: assinatura invalida"); }
    else if (body.indexOf(String("\"node\":\"") + NODE_ID + "\"") < 0) {   // VULN-007: comando de outro nó
      Serial.println("comando REJEITADO: destinado a outro no");
    } else {
      int i = body.indexOf("\"cseq\":");
      uint32_t cseq = i >= 0 ? strtoul(body.c_str() + i + 7, nullptr, 10) : 0;
      if (cseq < lastCmdSeq) { Serial.println("comando REJEITADO: cseq antigo (replay)"); }
      else {
        lastCmdSeq = cseq; lastCmdMs = millis();
        setFan(body.indexOf("\"fan\":true") >= 0);
      }
    }
  }
  http.end();
}

void localFailSafe() {
  if (millis() - lastCmdMs < CMD_TIMEOUT_MS && lastCmdMs != 0) return;
  bool hi = (!isnan(ppm) && ppm >= LOCAL_PPM_ON) || (!isnan(temp) && temp >= LOCAL_T_ON);
  bool lo = (isnan(ppm) || ppm <= LOCAL_PPM_OFF) && (isnan(temp) || temp <= LOCAL_T_OFF);
  if (!fanOn && hi) setFan(true); else if (fanOn && lo) setFan(false);
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_RELAY, OUTPUT); pinMode(PIN_LED, OUTPUT);
  setFan(false);
  analogReadResolution(12);
  analogSetPinAttenuation(PIN_MQ, ADC_11db);
  dht.begin();
  bootId = esp_random();
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.printf("\nIP %s | boot=%lu\n", WiFi.localIP().toString().c_str(), (unsigned long)bootId);
  useTls = String(GATEWAY_URL).startsWith("https://");
  if (useTls) { syncTime(); tlsClient.setCACert(ROOT_CA); }   // sem setInsecure(): o certificado É verificado
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) { WiFi.reconnect(); delay(1000); return; }
  if (millis() - lastSend >= PERIOD_MS) {
    lastSend = millis();
    readSensors();
    sendTelemetry();
    fetchCommand();
    localFailSafe();
  }
}
