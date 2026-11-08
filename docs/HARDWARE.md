# Nó físico (ESP32 = nó S1 da topologia)

| Componente | Pino do componente | Pino do ESP32 |
|---|---|---|
| DHT11 | DATA / VCC / GND | GPIO4 / 3V3 / GND |
| MQ-135 | AO (via divisor 10k+10k) / VCC / GND | GPIO34 / VIN (5 V) / GND |
| Relé 5V | IN / VCC / GND | GPIO26 / VIN (5 V) / GND |

- Divisor: AO → 10k → nó (GPIO34) → 10k → GND (o AO chega a 5 V, o ESP32 aceita no máximo 3,3 V).
- Circuito de potência: +12 V da fonte → COM do relé; NO → fio positivo do ventilador (12 V); negativo do ventilador → −12 V. Se o ventilador for de 5 V, ligue COM ao 5 V (VIN) e o negativo ao GND.
- Alimente o ESP32 pela USB. Nunca ligue 12 V no VIN nem nos trilhos de 5 V.
- Protoboard: ESP32 nas colunas 1–15 (USB para a coluna 1); DHT11 nas colunas 20–22; MQ-135 nas 32–35; divisor nas 35–41; relé nas 45–47. Trilho superior = 5 V/GND, inferior = 3,3 V/GND.
- Firmware: `firmware/esp32_node/` (copie `secrets.example.h` para `secrets.h`). O Wi-Fi conecta em segundo plano; a automação da ventoinha pelos sensores é executada localmente e continua ativa sem rede. O dashboard pode impor LIGADO/DESLIGADO em MANUAL ou devolver a decisão ao ESP32 em AUTO. O firmware exige desafio HMAC com nonce para consultar e validar comandos remotos do gateway.
- Papel na pesquisa: o ESP32 é a fonte real de telemetria (formato, período e tamanho da mensagem definem a demanda de S1) e o atuador real do fluxo de controle **K1** (restrito à zona confiável). A **otimização de rotas roda na simulação**; o hardware não forma a malha.
