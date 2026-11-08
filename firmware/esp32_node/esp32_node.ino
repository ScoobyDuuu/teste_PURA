/*
  P.U.R.A. — ESP32 conectado ao gateway hospedado no Render.

  Hardware:
    - DHT11 DATA -> GPIO4
    - MQ-135 AO -> divisor 10k/10k -> GPIO34
    - GPIO26 -> resistor 10k -> base do BC548B
    - BC548B emissor -> GND comum; coletor -> IN do módulo relé ativo em LOW
    - GPIO2 -> LED integrado da placa

  Protocolo:
    - POST /telemetry a cada 5 s, JSON autenticado por HMAC-SHA256.
    - GET /control após cada telemetria, com nonce e assinatura HMAC.
  - Controle automático local por sensores; o dashboard pode impor LIGADO/DESLIGADO
    em modo manual ou devolver o controle ao ESP32 com o modo AUTO.
    - HTTPS valida o certificado do servidor usando ROOT_CA, sem TLS inseguro.
    - NTP fornece o timestamp exigido pelo gateway em produção.
    - Se a nuvem ficar indisponível por 30 s, o controle local assume com histerese.

  Bibliotecas Arduino IDE:
    - DHT sensor library (Adafruit)
    - Adafruit Unified Sensor
  Placa: ESP32 Dev Module (pacote Arduino-ESP32 da Espressif).
  Configure Wi-Fi, URL e segredo em secrets.h (copie secrets.example.h).
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include <DHT.h>
#include "mbedtls/md.h"
#include "secrets.h"

#define PIN_DHT   4
#define PIN_MQ    34
#define PIN_RELAY 26
#define PIN_LED   2

// O BC548B inverte a lógica do módulo de relé ativo em LOW:
// GPIO26 HIGH liga o transistor e puxa IN para GND (relé LIGADO).
// Portanto, a GPIO é ativa em HIGH nesta montagem.
constexpr bool RELAY_ACTIVE_LOW = false;

constexpr float DIV_RATIO = 2.0f;       // divisor 10k/10k
constexpr float VCC_MQ = 5.0f;          // alimentação do módulo MQ-135
constexpr float RL_KOHM = 10.0f;        // conferir o resistor do módulo
constexpr float R0_KOHM = 76.63f;       // calibrar em ar limpo
constexpr float PARA = 116.6020682f;
constexpr float PARB = 2.769034857f;

constexpr uint32_t SAMPLE_PERIOD_MS = 5000;
constexpr uint32_t WIFI_RETRY_MS = 10000;
constexpr uint32_t COMMAND_TIMEOUT_MS = 30000;
constexpr uint32_t MQ_WARMUP_MS = 60000;
constexpr uint32_t HTTP_TIMEOUT_MS = 8000;
constexpr uint32_t RETRY_INITIAL_MS = 5000;
constexpr uint32_t RETRY_MAX_MS = 60000;

// Limites da automação local executada pelo próprio ESP32.
constexpr float LOCAL_PPM_ON = 1000.0f;
constexpr float LOCAL_PPM_OFF = 800.0f;
constexpr float LOCAL_TEMP_ON = 30.0f;
constexpr float LOCAL_TEMP_OFF = 28.0f;

DHT dht(PIN_DHT, DHT11);
WiFiClientSecure tlsClient;
WiFiClient plainClient;

uint32_t bootId = 0;
uint32_t seqNo = 0;
uint32_t lastRemoteCommandMs = 0;
uint32_t lastCycleMs = 0;
uint32_t lastReconnectMs = 0;
uint32_t lastTimeWarningMs = 0;
uint32_t bootMs = 0;
uint32_t nextNetworkAttemptMs = 0;
uint32_t retryDelayMs = RETRY_INITIAL_MS;

bool fanOn = false;
bool useTls = false;
bool timeConfigured = false;
bool remoteOverrideActive = false;
bool remoteFanOn = false;
bool wifiWasConnected = false;

float tempC = NAN;
float humidity = NAN;
float ppmEstimate = NAN;

// Calcula HMAC-SHA256 em hexadecimal. Uma falha criptográfica interrompe a mensagem.
String hmacHex(const String &message) {
  unsigned char output[32];
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);

  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr || mbedtls_md_setup(&context, info, 1) != 0 ||
      mbedtls_md_hmac_starts(&context,
          reinterpret_cast<const unsigned char *>(HMAC_SECRET), strlen(HMAC_SECRET)) != 0 ||
      mbedtls_md_hmac_update(&context,
          reinterpret_cast<const unsigned char *>(message.c_str()), message.length()) != 0 ||
      mbedtls_md_hmac_finish(&context, output) != 0) {
    mbedtls_md_free(&context);
    return String();
  }

  mbedtls_md_free(&context);
  String hex;
  hex.reserve(64);
  for (size_t i = 0; i < sizeof(output); ++i) {
    char byteHex[3];
    snprintf(byteHex, sizeof(byteHex), "%02x", output[i]);
    hex += byteHex;
  }
  return hex;
}

bool safeEquals(const String &a, const String &b) {
  if (a.length() != b.length()) return false;
  uint8_t difference = 0;
  for (size_t i = 0; i < a.length(); ++i) {
    difference |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
  }
  return difference == 0;
}

void setFan(bool on) {
  fanOn = on;
  const uint8_t relayLevel = RELAY_ACTIVE_LOW ? (on ? LOW : HIGH) : (on ? HIGH : LOW);
  digitalWrite(PIN_RELAY, relayLevel);
  digitalWrite(PIN_LED, on ? HIGH : LOW);
}

void readSensors() {
  const float h = dht.readHumidity();
  const float t = dht.readTemperature();

  humidity = (!isnan(h) && h >= 0.0f && h <= 100.0f) ? h : NAN;
  tempC = (!isnan(t) && t >= -40.0f && t <= 125.0f) ? t : NAN;

  // O MQ-135 precisa aquecer. Enquanto isso, o gateway recebe ppm=null e não
  // toma decisões com uma leitura inicial ainda instável.
  ppmEstimate = NAN;
  if (millis() - bootMs < MQ_WARMUP_MS) return;

  uint32_t accumulatedMv = 0;
  for (int i = 0; i < 16; ++i) {
    accumulatedMv += analogReadMilliVolts(PIN_MQ);
    delay(2);
  }

  const float voltageAtPin = (accumulatedMv / 16.0f) / 1000.0f;
  const float sensorVoltage = voltageAtPin * DIV_RATIO;
  if (sensorVoltage > 0.05f && sensorVoltage < VCC_MQ - 0.05f) {
    const float sensorResistance = (VCC_MQ - sensorVoltage) / sensorVoltage * RL_KOHM;
    ppmEstimate = constrain(PARA * pow(sensorResistance / R0_KOHM, -PARB), 0.0f, 10000.0f);
  }
}

WiFiClient &networkClient() {
  return useTls ? static_cast<WiFiClient &>(tlsClient) : plainClient;
}

void startTimeSync() {
  // A sincronização começa somente depois de o Wi-Fi estar associado.
  configTime(0, 0, "pool.ntp.org", "time.google.com", "time.cloudflare.com");
  timeConfigured = true;
  Serial.println("NTP iniciado; aguardando horário válido para HTTPS.");
}

bool timeReady() {
  time_t now = 0;
  time(&now);
  return now >= 1700000000;
}

String jsonNumber(float value, int decimals) {
  return isnan(value) ? String("null") : String(value, decimals);
}

bool sendTelemetry() {
  const String timestamp = useTls
      ? String(",\"ts\":") + String(static_cast<unsigned long>(time(nullptr)))
      : String();

  String body = String("{\"node\":\"") + NODE_ID + "\",\"boot\":" + String(bootId) +
                ",\"seq\":" + String(++seqNo) + timestamp +
                ",\"t\":" + jsonNumber(tempC, 1) +
                ",\"h\":" + jsonNumber(humidity, 0) +
                ",\"ppm\":" + jsonNumber(ppmEstimate, 0) +
                ",\"fan\":" + (fanOn ? "true" : "false") +
                ",\"rssi\":" + String(WiFi.RSSI()) + "}";

  const String signature = hmacHex(body);
  if (signature.length() != 64) {
    Serial.println("ERRO: não foi possível calcular HMAC da telemetria.");
    return false;
  }

  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.setConnectTimeout(HTTP_TIMEOUT_MS);
  http.setReuse(false);
  const String url = String(GATEWAY_URL) + "/telemetry";
  if (!http.begin(networkClient(), url)) {
    Serial.println("ERRO: não foi possível iniciar HTTP para /telemetry.");
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Signature", signature);
  http.addHeader("Connection", "close");
  const int status = http.POST(body);
  http.end();

  Serial.printf("telemetria seq=%lu -> HTTP %d\n", static_cast<unsigned long>(seqNo), status);
  return status == HTTP_CODE_OK;
}

bool fetchCommand() {
  char nonce[17];
  snprintf(nonce, sizeof(nonce), "%08lx%08lx",
           static_cast<unsigned long>(esp_random()),
           static_cast<unsigned long>(esp_random()));

  const String requestMessage = String("GET\n/control\n") + NODE_ID + "\n" + nonce;
  const String requestSignature = hmacHex(requestMessage);
  if (requestSignature.length() != 64) {
    Serial.println("ERRO: não foi possível calcular HMAC da consulta de comando.");
    return false;
  }

  const String url = String(GATEWAY_URL) + "/control?node=" + NODE_ID + "&nonce=" + nonce;
  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.setConnectTimeout(HTTP_TIMEOUT_MS);
  http.setReuse(false);
  if (!http.begin(networkClient(), url)) {
    Serial.println("ERRO: não foi possível iniciar HTTP para /control.");
    return false;
  }

  const char *responseHeaders[] = {"X-Signature"};
  http.collectHeaders(responseHeaders, 1);
  http.addHeader("X-Request-Signature", requestSignature);
  http.addHeader("Connection", "close");

  const int status = http.GET();
  bool accepted = false;
  if (status == HTTP_CODE_OK) {
    const String body = http.getString();
    const String responseSignature = http.header("X-Signature");
    const String expectedNode = String("\"node\":\"") + NODE_ID + "\"";
    const String expectedNonce = String("\"nonce\":\"") + nonce + "\"";

    const int cseqPosition = body.indexOf("\"cseq\":");
    char *endPointer = nullptr;
    const unsigned long long commandSequence = cseqPosition >= 0
        ? strtoull(body.c_str() + cseqPosition + 7, &endPointer, 10)
        : 0;
    const bool hasSequence = cseqPosition >= 0 &&
        endPointer != body.c_str() + cseqPosition + 7 && commandSequence > 0;
    const bool fanIsOn = body.indexOf("\"fan\":true") >= 0;
    const bool fanIsOff = body.indexOf("\"fan\":false") >= 0;
    const bool modeAuto = body.indexOf("\"mode\":\"auto\"") >= 0;
    const bool modeManual = body.indexOf("\"mode\":\"manual\"") >= 0;

    if (!safeEquals(hmacHex(body), responseSignature)) {
      Serial.println("COMANDO REJEITADO: assinatura de resposta inválida.");
    } else if (body.indexOf(expectedNode) < 0 || body.indexOf(expectedNonce) < 0) {
      Serial.println("COMANDO REJEITADO: nó ou nonce não corresponde à requisição.");
    } else if (!hasSequence || (!modeAuto && !modeManual) || (!fanIsOn && !fanIsOff)) {
      Serial.println("COMANDO REJEITADO: campos do comando inválidos.");
    } else if (modeAuto) {
      // A nuvem não decide o estado no modo AUTO: o controle é exclusivamente local.
      remoteOverrideActive = false;
      Serial.println("Comando recebido: modo AUTOMÁTICO (controle pelo ESP32).");
      accepted = true;
    } else {
      // Em MANUAL, o valor vindo do servidor prevalece enquanto a conexão se mantém.
      remoteOverrideActive = true;
      remoteFanOn = fanIsOn;
      lastRemoteCommandMs = millis();
      setFan(remoteFanOn);
      Serial.printf("Comando remoto MANUAL: ventilador %s.\n", remoteFanOn ? "LIGADO" : "DESLIGADO");
      accepted = true;
    }
  } else {
    Serial.printf("consulta de comando -> HTTP %d\n", status);
  }

  http.end();
  return accepted;
}

void applyFanControl() {
  // Um comando manual permanece ativo enquanto o gateway renova sua validade.
  // Sem confirmação autenticada por 30 s, o ESP32 volta ao controle autônomo.
  if (remoteOverrideActive) {
    if (millis() - lastRemoteCommandMs < COMMAND_TIMEOUT_MS) {
      setFan(remoteFanOn);
      return;
    }
    remoteOverrideActive = false;
    Serial.println("Comando remoto expirou; retomando controle automático local.");
  }

  // O ESP32 decide localmente no modo AUTO, mesmo sem Wi-Fi ou servidor.
  // Se ambos os sensores estiverem inválidos, conserva o estado atual.
  if (isnan(ppmEstimate) && isnan(tempC)) return;

  const bool high = (!isnan(ppmEstimate) && ppmEstimate >= LOCAL_PPM_ON) ||
                    (!isnan(tempC) && tempC >= LOCAL_TEMP_ON);
  const bool low = (isnan(ppmEstimate) || ppmEstimate <= LOCAL_PPM_OFF) &&
                   (isnan(tempC) || tempC <= LOCAL_TEMP_OFF);

  if (!fanOn && high) setFan(true);
  else if (fanOn && low) setFan(false);
}

void startWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.persistent(false);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("Conectando ao Wi-Fi '%s'...\n", WIFI_SSID);
}

bool deadlineReached(uint32_t now, uint32_t deadline) {
  return static_cast<int32_t>(now - deadline) >= 0;
}

void setup() {
  Serial.begin(115200);
  bootMs = millis();

  pinMode(PIN_RELAY, OUTPUT);
  pinMode(PIN_LED, OUTPUT);
  setFan(false);

  analogReadResolution(12);
  analogSetPinAttenuation(PIN_MQ, ADC_11db);
  dht.begin();

  bootId = esp_random();
  useTls = String(GATEWAY_URL).startsWith("https://");
  if (useTls) {
    // ROOT_CA contém certificados-raiz públicos para as CAs usadas pelo Render.
    // A cadeia é verificada; não use setInsecure() em hipótese alguma.
    tlsClient.setCACert(ROOT_CA);
    tlsClient.setHandshakeTimeout(15);
  } else {
    Serial.println("AVISO: HTTP sem TLS está habilitado. Use apenas em laboratório local.");
  }

  if (strlen(HMAC_SECRET) < 16) {
    Serial.println("ERRO: HMAC_SECRET precisa ter pelo menos 16 caracteres.");
  }
  if (strlen(NODE_ID) == 0 || strlen(NODE_ID) > 64) {
    Serial.println("ERRO: NODE_ID deve conter de 1 a 64 caracteres.");
  }

  startWiFi();
  lastCycleMs = millis() - SAMPLE_PERIOD_MS;
  Serial.println("PURA iniciado. Controle local permanece ativo sem conexão com a nuvem.");
}

void loop() {
  const uint32_t now = millis();

  // A leitura dos sensores e a automação local não dependem da disponibilidade da nuvem.
  if (now - lastCycleMs >= SAMPLE_PERIOD_MS) {
    lastCycleMs = now;
    readSensors();
    applyFanControl();

    const bool connected = WiFi.status() == WL_CONNECTED;
    if (!connected) {
      wifiWasConnected = false;
      timeConfigured = false;
      if (now - lastReconnectMs >= WIFI_RETRY_MS) {
        lastReconnectMs = now;
        Serial.println("Wi-Fi desconectado; tentando reconectar...");
        WiFi.reconnect();
      }
    } else {
      if (!wifiWasConnected) {
        wifiWasConnected = true;
        Serial.printf("Wi-Fi conectado. IP local: %s | RSSI: %d dBm\n",
                      WiFi.localIP().toString().c_str(), WiFi.RSSI());
        if (useTls) startTimeSync();
      }

      if (useTls && !timeReady()) {
        if (now - lastTimeWarningMs >= 15000) {
          lastTimeWarningMs = now;
          Serial.println("AVISO: aguardando NTP. Telemetria HTTPS ainda não será enviada.");
        }
      } else if (deadlineReached(millis(), nextNetworkAttemptMs)) {
        const bool telemetryOk = sendTelemetry();
        const bool commandOk = telemetryOk && fetchCommand();

        if (telemetryOk && commandOk) {
          retryDelayMs = RETRY_INITIAL_MS;
          nextNetworkAttemptMs = millis() + SAMPLE_PERIOD_MS;
        } else {
          Serial.printf("Sincronização incompleta; nova tentativa em %lu ms.\n",
                        static_cast<unsigned long>(retryDelayMs));
          nextNetworkAttemptMs = millis() + retryDelayMs;
          retryDelayMs = retryDelayMs >= (RETRY_MAX_MS / 2UL)
              ? RETRY_MAX_MS
              : retryDelayMs * 2UL;
        }
      }
    }

    applyFanControl();
    Serial.printf("T=%.1f C | U=%.0f %% | PPM~%.0f | FAN=%s | MODE=%s | Wi-Fi=%s%s\n",
                  tempC, humidity, ppmEstimate, fanOn ? "ON" : "OFF",
                  remoteOverrideActive ? "MANUAL" : "AUTO",
                  WiFi.status() == WL_CONNECTED ? "OK" : "OFF",
                  (millis() - bootMs < MQ_WARMUP_MS) ? " | MQ-135 aquecendo" : "");
  }

  delay(5);
}
