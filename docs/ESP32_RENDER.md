# ESP32 ligado ao gateway PURA no Render

## Arquivos

- Firmware: `firmware/esp32_node/esp32_node.ino`
- Modelo de configuração: `firmware/esp32_node/secrets.example.h`
- Configuração privada local: `firmware/esp32_node/secrets.h` (você cria; já está no `.gitignore`)

O firmware não hospeda uma API no próprio ESP32. Ele age como cliente: envia dados para o gateway na nuvem e consulta comandos remotos autenticados. **O controle automático pertence ao ESP32**; o servidor não calcula os limites de acionamento. No dashboard você pode forçar LIGADO, forçar DESLIGADO ou selecionar AUTO para devolver a decisão aos sensores locais.

## 1. Primeiro publique o servidor

Siga `docs/DEPLOY.md`. Depois do primeiro deploy, anote:

- A URL HTTPS do serviço, por exemplo `https://pura-gateway.onrender.com`.
- O valor `PURA_SECRET`, encontrado em Render → serviço → Environment.
- A senha `PURA_DASHBOARD_PASSWORD`, para abrir o dashboard.

O endereço de exemplo não representa um serviço já publicado. Use a URL real gerada pelo Render.

## 2. Prepare o firmware

1. Abra `firmware/esp32_node/`.
2. Faça uma cópia de `secrets.example.h` e chame a cópia de `secrets.h`.
3. Edite somente os campos abaixo no `secrets.h`:

```cpp
#define WIFI_SSID   "NOME_DA_REDE_WIFI"
#define WIFI_PASS   "SENHA_DA_REDE_WIFI"
#define GATEWAY_URL "https://SEU-SERVICO.onrender.com"
#define HMAC_SECRET "VALOR_EXATO_DE_PURA_SECRET_COPIADO_DO_RENDER"
#define NODE_ID "S1"
```

`HMAC_SECRET` deve ser exatamente igual a `PURA_SECRET` no Render. Não use a senha do dashboard nesse campo. Para outro ESP32, use um `NODE_ID` diferente.

O arquivo `secrets.example.h` já contém certificados-raiz públicos para validar certificados emitidos por Let's Encrypt e Google Trust Services, autoridades usadas pelo Render. A validação TLS permanece habilitada; não ative `setInsecure()`.

## 3. Arduino IDE

1. Selecione a placa **ESP32 Dev Module**.
2. Instale no Library Manager a biblioteca **DHT sensor library** da Adafruit e **Adafruit Unified Sensor**.
3. Abra `esp32_node.ino` e compile/grave o programa.
4. Abra o Monitor Serial em 115200 baud.

O firmware usa bibliotecas do core ESP32 para Wi-Fi, HTTPS, NTP e HMAC; não precisa de biblioteca HTTP/MQTT adicional.

## 4. Fiação do relé com BC548B

Este firmware foi ajustado para a montagem descrita no projeto:

- GPIO26 → resistor de 10 kΩ → base do BC548B.
- Emissor do BC548B → GND comum.
- Coletor do BC548B → IN do módulo relé ativo em LOW.
- O módulo relé deve receber a alimentação compatível indicada pelo fabricante.

Com o transistor como chave de coletor aberto, a lógica é **GPIO26 HIGH = relé ligado**. Por isso, no firmware, `RELAY_ACTIVE_LOW = false`. Se a fiação ou o tipo de módulo for diferente, não energize o ventilador até conferir a polaridade.

O MQ-135 AO precisa entrar no GPIO34 através do divisor de tensão 10 kΩ/10 kΩ. Não aplique 5 V diretamente ao ADC do ESP32. Una os GNDs da fonte, ESP32, sensor e módulo relé conforme o circuito.

## 5. O que acontece em operação

- A cada 5 segundos, o ESP32 lê os sensores e tenta enviar `POST /telemetry`.
- A cada ciclo, o ESP32 lê os sensores e aplica localmente a histerese automática: liga a partir de 1000 ppm estimados ou 30 °C; desliga quando ppm cai para 800 ou menos e temperatura cai para 28 °C ou menos. Se os dois sensores estiverem inválidos, conserva o estado atual.
- Quando a telemetria é aceita, consulta `GET /control` com um nonce aleatório.
- O gateway verifica HMAC, timestamp e sequência anti-replay. O ESP32 valida assinatura, nó, nonce e modo antes de aplicar um comando remoto.
- No dashboard, **Ligar ventilador** e **Desligar ventilador** ativam modo MANUAL e enviam o estado solicitado. O comando é renovado a cada consulta autenticada enquanto o dispositivo estiver conectado.
- **Automático (ESP32)** remove a sobreposição manual. A placa volta a decidir com os sensores, sem depender da nuvem.
- Se um comando MANUAL deixar de ser renovado por 30 segundos, o ESP32 encerra a sobreposição e retoma o controle automático local. Isso também mantém o ventilador sob controle quando o Render ou a conexão ficam indisponíveis.
- O MQ-135 fica em aquecimento por 60 segundos; nesse período, `ppm` é enviado como `null` para não controlar o ventilador com uma leitura inicial instável.
- O valor do MQ-135 é uma estimativa dependente de calibração (R0, carga e curva do sensor); não é uma medição certificada de CO₂ nem substitui um medidor específico de qualidade do ar.
- O estado MANUAL fica guardado na memória do gateway até você selecionar AUTO ou o serviço reiniciar. A placa aplica o comando recebido e exige renovações autenticadas; após 30 segundos sem renovação, volta ao modo automático local. Se o serviço reiniciar, os overrides em RAM são perdidos e o modo retornado passa a ser AUTO.
- Se o Render estiver acordando ou a conexão falhar, o firmware aumenta progressivamente o intervalo de nova tentativa até 60 segundos. O controle automático local continua funcionando durante toda a indisponibilidade.

No Monitor Serial, procure `Wi-Fi conectado`, respostas HTTP 200 para telemetria e consulta de comando, além de `MODE=AUTO` ou `MODE=MANUAL`. Depois abra a URL HTTPS do Render e autentique com usuário `pura` e a senha `PURA_DASHBOARD_PASSWORD`. No menu lateral, abra **Controle da ventoinha**, escolha o ESP32 e teste Ligar, Desligar e Automático. Os botões só ficam habilitados se a última telemetria tiver chegado nos últimos 20 segundos. O estado físico mostrado muda após a próxima telemetria do dispositivo.

## 6. Requisitos da rede pública

O ESP32 conecta por Wi-Fi 2,4 GHz em modo estação e faz conexões de saída HTTPS na porta TCP 443. Também precisa resolver DNS e alcançar um servidor NTP (UDP 123) para validar os timestamps exigidos pelo gateway.

O firmware atual usa SSID e senha WPA/WPA2-Personal configurados em `secrets.h`. Ele **não** automatiza o login em páginas de captive portal, cadastro por MAC, Wi-Fi WPA2-Enterprise ou redes que exigem aceite de termos em navegador. Nessas redes, solicite à administração uma rede IoT sem captive portal ou use um roteador/hotspot próprio com saída à internet.

Ao mudar de Wi-Fi, edite `WIFI_SSID`/`WIFI_PASS` e grave novamente o firmware. Esta entrega ainda não inclui portal de provisionamento por celular.

## 7. Importante sobre o Render gratuito

Com o ESP32 enviando dados continuamente, o serviço normalmente não atinge os 15 minutos de inatividade. Se a placa ficar desligada/desconectada por mais de 15 minutos, o Render pode suspender o serviço; a primeira requisição pode levar cerca de um minuto para acordá-lo. O firmware tentará novamente, mantendo o controle local.

O plano gratuito também pode reiniciar o serviço, tem limite de horas mensais e não mantém os dados em RAM após reinícios/suspensão. Portanto, este arranjo é adequado para protótipo e demonstração, não para controle de ventilação crítico ou operação pública que exija disponibilidade garantida.
