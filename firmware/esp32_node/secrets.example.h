// Copie para secrets.h (que está no .gitignore) e preencha. NUNCA publique o segredo real.
#pragma once
#define WIFI_SSID   "SUA_REDE"
#define WIFI_PASS   "SUA_SENHA"
// Nuvem (TLS):  "https://pura-gateway.onrender.com"   |   Laboratório (sem TLS): "http://192.168.0.10:8000"
#define GATEWAY_URL "https://pura-gateway.onrender.com"
#define HMAC_SECRET "COLE_AQUI_O_PURA_SECRET_DO_GATEWAY"   // 16+ caracteres, igual ao PURA_SECRET
#define NODE_ID     "S1"                                   // nó S1 da topologia (o ESP32 real)

// Certificado RAIZ da cadeia do seu gateway (obrigatório para https://). Como obter: abra a URL no navegador,
// veja o certificado, exporte a cadeia em PEM e copie o certificado raiz (ex.: ISRG Root X1).
static const char ROOT_CA[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
COLE_AQUI_O_CERTIFICADO_RAIZ_EM_PEM
-----END CERTIFICATE-----
)EOF";
