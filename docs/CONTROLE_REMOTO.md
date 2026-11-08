# Controle remoto da ventoinha

## Onde encontrar

No dashboard do PURA, use o item **Controle da ventoinha** no menu lateral. Ele leva diretamente ao painel de controle. O painel oferece três ações:

- **Ligar ventilador**: ativa um override manual ligado.
- **Desligar ventilador**: ativa um override manual desligado.
- **Automático (ESP32)**: remove o override e devolve a decisão ao firmware local.

Os botões ficam desabilitados até existir telemetria recente de um ESP32. O gateway considera conectado o nó cuja última mensagem foi recebida há no máximo 20 segundos. Isso evita habilitar comandos para nós que só aparecem no histórico antigo em memória.

## Caminho do comando

1. O dashboard autenticado envia `POST /api/fan` com `node`, `mode` e, no modo manual, `fan`.
2. O gateway valida autenticação Basic, origem, cabeçalho anti-CSRF e payload.
3. O ESP32 envia telemetria assinada para `POST /telemetry` e consulta `GET /control` com nonce e HMAC.
4. O gateway devolve `node`, `mode`, `fan`, `cseq` e `nonce`, assinados em `X-Signature`.
5. O ESP32 valida a assinatura e o nonce antes de aplicar o comando.

## Prioridade do controle

- Em **AUTO**, o ESP32 decide localmente com temperatura e estimativa do MQ-135.
- Em **MANUAL**, o comando remoto prevalece enquanto o dispositivo recebe renovações autenticadas.
- Sem renovação válida por 30 segundos, o ESP32 abandona o override e volta à automação local.
- Se o serviço Render reiniciar, os comandos manuais mantidos apenas em memória são perdidos; após reconectar, o ESP32 opera em AUTO.

## Verificação

- `GET /healthz`: confirma que o processo do gateway está disponível.
- `GET /api/telemetry` (autenticação do dashboard): mostra `samples`, `counters.accepted`, `fan`, `mode` e `command_fan`.
- `counters.accepted` deve crescer enquanto o ESP32 envia telemetria.
- Na interface, a origem muda para **AO VIVO · ESP32** após mensagem recente; `DEMO` representa dados simulados.
