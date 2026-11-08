# Deploy em nuvem (camada gratuita) e CI/CD

## Arquitetura de entrega
```
Pull Request ──► GitHub Actions (CI): ruff (lint) ─► testes (Python 3.10 e 3.12) ─► build Docker + health check
      │                                                           │
      └── merge em main ──► Render (CD): só faz deploy se os checks passaram (autoDeployTrigger: checksPass)
```
Repositório público ⇒ o histórico do pipeline (logs do Actions) é público.

## Passo a passo (Render, plano gratuito)
1. Crie o repositório **público** no GitHub e envie o código (`git push`).
2. Proteja `main` (exige PR, 1 aprovação e os checks `lint`, `test (3.10)`, `test (3.12)` e `docker`): `tools/github_setup.sh <dono>/<repo>` ou *Settings → Branches*.
3. No Render: *New → Blueprint*, aponte para o repositório. O arquivo `render.yaml` cria o serviço Docker gratuito
   e **gera o `PURA_SECRET`** automaticamente.
4. Copie o valor de `PURA_SECRET` (Dashboard → serviço → Environment) para `HMAC_SECRET` no `secrets.h` do ESP32.
5. Teste: `curl https://<seu-servico>.onrender.com/healthz` deve devolver `{"status": "ok"}`.
6. Ajuste `PROXY_HOPS` se necessário: envie uma requisição com `X-Forwarded-For: 1.2.3.4` e confira em
   `/api/alerts` qual IP o monitor registrou. Ele deve ser o **seu** IP real, nunca `1.2.3.4`.

## Limitações do plano gratuito
- O serviço **dorme após ~15 min sem tráfego** (a primeira requisição demora alguns segundos). Para a apresentação,
  acorde-o antes (`/healthz`) ou mantenha o ESP32 enviando telemetria.
- Disco efêmero: telemetria e alertas ficam em memória e se perdem a cada deploy/reinício. Os resultados dos
  experimentos vão na imagem (`results/`).
- Domínio personalizado não está disponível no plano gratuito (o TLS vem no domínio `onrender.com`).
- Outras camadas gratuitas servem (Google Cloud Run, Fly.io): o `Dockerfile` é portátil e só exige `PORT` e `PURA_SECRET`.

## Carimbo de tempo (VULN-006)
`render.yaml` define `PURA_REQUIRE_TS=1`: o gateway só aceita telemetria com `ts` assinado (±120 s, ajustável em `PURA_TS_WINDOW_S`). O firmware envia `ts` automaticamente quando `GATEWAY_URL` é `https://` (usa NTP). Para testar com `http://` em laboratório, **não** defina essa variável.

## Segredos
Nunca no Git. `PURA_SECRET` vive só no painel do provedor e no `secrets.h` local (ignorado pelo Git).
