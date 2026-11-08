# Implantação no GitHub + Render

## O que o deploy faz

O Render lê o `render.yaml` na raiz do repositório, constrói a imagem pelo `Dockerfile`, inicia `python -m pura.server` usando a porta `PORT` fornecida pelo Render e verifica `/healthz`. O `render.yaml` gera `PURA_SECRET` e `PURA_DASHBOARD_PASSWORD`; os dois valores são mantidos no painel do Render, não no GitHub.

## Publicação

1. Extraia o ZIP e entre na pasta `pura/`. **O conteúdo dessa pasta deve ser a raiz do repositório GitHub**: `render.yaml`, `Dockerfile`, `README.md`, `pura/`, `web/`, `firmware/`, `tests/` etc. não devem ficar dentro de uma segunda subpasta `pura/` no repositório.
2. Crie um repositório no GitHub e envie o conteúdo para a branch `main`.
3. Aguarde o GitHub Actions finalizar `lint`, testes Python e build/teste do Docker.
4. No Render, use **New → Blueprint**, conecte o repositório e confirme a criação do serviço `pura-gateway`.
5. Depois do primeiro deploy, copie a URL pública HTTPS do serviço, por exemplo `https://pura-gateway.onrender.com`.
6. No Render → serviço → **Environment**, copie o valor de `PURA_SECRET`. Guarde também `PURA_DASHBOARD_PASSWORD` em um gerenciador de senhas.
7. Siga `docs/ESP32_RENDER.md` para preparar o `secrets.h`, compilar e gravar o firmware.

O `autoDeployTrigger: checksPass` faz o Render esperar que os checks do GitHub terminem com sucesso antes de implantar alterações da branch vinculada. O comportamento está documentado na referência oficial do Blueprint Render: https://render.com/docs/blueprint-spec.

## Teste de saúde

Abra `https://SEU-SERVICO.onrender.com/healthz`. A resposta esperada é:

```json
{"status": "ok"}
```

O endpoint `/healthz` não exige senha para que o Render consiga monitorar o serviço. O dashboard e suas APIs de leitura exigem Basic Auth.

## Variáveis e segurança

| Variável | Finalidade |
|---|---|
| `PURA_SECRET` | Segredo HMAC compartilhado entre gateway e ESP32; mínimo 16 caracteres. Gerado pelo Render. |
| `PURA_DASHBOARD_USER` | Usuário do dashboard; neste Blueprint é `pura`. |
| `PURA_DASHBOARD_PASSWORD` | Senha do dashboard e APIs administrativas/leitura, inclusive comandos remotos. Gerada pelo Render; diferente do segredo HMAC. |
| `PURA_REQUIRE_TS` | `1`: exige timestamp assinado na telemetria. |
| `PURA_TS_WINDOW_S` | Janela máxima de diferença do timestamp; padrão aqui é 120 segundos. |

O endpoint `POST /telemetry` exige HMAC válido. O ESP32 obtém comandos em `GET /control`, autenticando a requisição por HMAC e nonce aleatório; a resposta também é assinada e vinculada ao nonce. O gateway aceita telemetria HTTPS somente com timestamp dentro da janela configurada.

O controle automático da ventoinha é executado localmente pelo ESP32. Para comando remoto, o dashboard autenticado oferece LIGAR, DESLIGAR e AUTO. A API correspondente é `POST /api/fan`: modo manual usa `{"node":"S1","mode":"manual","fan":true}` (ou `false`); modo automático usa `{"node":"S1","mode":"auto"}`. O endpoint exige Basic Auth, `Origin` do mesmo host e o cabeçalho `X-PURA-Action: fan-control`. O comando manual é transmitido ao ESP32 pelo canal HMAC já existente; se não for renovado em 30 s, a placa retoma o controle local.

**Nunca** publique `firmware/esp32_node/secrets.h`. O arquivo está listado no `.gitignore`; publique apenas `secrets.example.h`, que contém os campos de configuração e certificados-raiz públicos.

## Limitações do plano gratuito do Render

- O serviço gratuito suspende após 15 minutos sem receber tráfego de entrada e leva cerca de um minuto para voltar a responder. Um ESP32 conectado e enviando a cada 5 segundos mantém o serviço ativo; a estratégia de repetição do firmware tenta novamente após falhas/cold start.
- Há um limite de 750 horas gratuitas de instância por workspace por mês. Um único serviço ligado continuamente consome cerca de 720–744 horas por mês (conforme o número de dias); outros serviços gratuitos no mesmo workspace também consomem essa franquia.
- O sistema atual mantém as últimas 600 amostras, estado anti-replay, estado reportado dos ventiladores, overrides manuais e alertas em RAM. Reinício, suspensão ou novo deploy apaga esse estado. Não há histórico permanente nem banco de dados configurado nesta versão.
- A própria documentação do Render recomenda não usar instâncias gratuitas em produção. Para operação pública contínua/crítica, use plano pago e armazenamento persistente (ou adicione um banco de dados persistente).

Documentação oficial: https://render.com/docs/free e https://render.com/docs/tls.
