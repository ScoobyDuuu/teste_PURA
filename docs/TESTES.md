# Roteiro de testes (o que o grupo deve executar e registrar)

Legenda: **[A]** automático (já passa no ambiente de desenvolvimento) · **[M]** manual, deve ser feito pelo grupo e
registrado com print, link ou log no relatório.

## A. Testes automáticos — rodar localmente antes de qualquer PR
| # | Comando | Resultado esperado |
|---|---|---|
| A1 | `python -m unittest discover -s tests -t . -v` | Todos os testes automatizados devem passar (modelo, roteadores, segurança, monitor, armazenamento, API e regressões) |
| A2 | `python -m pip install -r requirements-dev.txt` e `python -m ruff check .` | `All checks passed!`; `tools/minilint.py` segue como alternativa offline |
| A3 | `python -m pura.experiments --seeds 30` | ~1 min; recria `results/`. Confira: Dijkstra residual vence ou empata em tempo; ACO/Memético reduzem a latência p95 contra o Dijkstra |
| A4 | `python -m tools.security_demo` | 200, 200, 200 → **409** (replay) → 401×5 e **429** (bloqueio) → alertas `BAD_SIGNATURE_BURST` e `REPLAY`; pasta temporária removida ao terminar |
| A5 | `docker build -t pura-gateway . && docker run --rm -p 8000:8000 -e PURA_SECRET=segredo-com-16-ou-mais -e PURA_DASHBOARD_PASSWORD=senha-dashboard-com-16 pura-gateway` | `/healthz` público retorna `{"status": "ok"}`; dashboard pede autenticação Basic |
| A6 | `docker run --rm -e PURA_SECRET=segredo-com-16-ou-mais pura-gateway` (sem senha do dashboard) | **Deve falhar** ao tentar bind externo sem `PURA_DASHBOARD_PASSWORD` |

A análise de retenção e os limites de logs/memória são descritos em `docs/DADOS_E_RETENCAO.md`; os testes de rotação e limites são executados pela suíte automatizada.

## B. Testes manuais obrigatórios

### B1. Ciclo real de Pull Request com revisão (exigência de Open Source)
1. Cada integrante cria um branch e abre **um PR** pequeno e real, por exemplo:
   - novo teste ou detector no monitor (`monitor.py`);
   - melhoria na documentação (ADR, README, HARDWARE);
   - ajuste de parâmetro com justificativa e reexecução dos experimentos.
2. Outro integrante **revisa** (comentários de linha e aprovação) antes do merge (squash).
3. Evidência: links dos PRs, comentários de revisão e gráfico de commits (*Insights → Contributors*) com **todos** os integrantes.

### B2. CI com lint e testes em cada PR
1. Abra um PR e confirme os jobs verdes: `lint`, `test` (3.10 e 3.12) e `docker`.
2. **Prova de que o CI barra erros:** abra um PR de teste com um `import os` não usado e confirme que `lint` falha e o merge fica bloqueado. Repita com um teste quebrado de propósito. Feche esses PRs sem merge.
3. Proteja a `main` com `tools/github_setup.sh <dono>/<repo>` (ou em *Settings → Branches*) e confirme que os checks `lint`, `test (3.10)`, `test (3.12)` e `docker` são obrigatórios.

### B3. Deploy em nuvem
1. Siga `docs/DEPLOY.md`. Confirme `https://<servico>.onrender.com/healthz` e o dashboard no navegador.
2. Confirme que um commit com CI **vermelho** não gera deploy (`autoDeployTrigger: checksPass`).
3. Meça o *cold start* (primeira requisição após 15 min de inatividade) e registre o tempo.
4. Verifique em `/api/alerts` o IP que o monitor enxerga e ajuste `PROXY_HOPS` se for o IP do proxy (VULN-005).

### B4. Hardware e firmware (**não testados em hardware até aqui**)
1. Compile `firmware/esp32_node/esp32_node.ino` (ESP32 Dev Module, bibliotecas Adafruit DHT + Unified Sensor) com `secrets.h` preenchido.
2. **Meça com multímetro** a tensão no GPIO34 com o divisor 10k/10k (deve ficar **abaixo de 3,3 V**; esperado ~2,5 V com o MQ-135 aquecido).
3. Monitor Serial: leituras de T, UR e ppm plausíveis; o relé estala ao acionar; em AUTO, o próprio ESP32 deve aplicar a histerese local (1000/800 ppm estimados e 30/28 °C). O ventilador liga no circuito de 12 V (ou 5 V, conforme o ventilador).
4. Com o MQ-135, aguarde o aquecimento e calibre `R0_KOHM` em ar limpo.
5. Teste também iniciar o ESP32 com o roteador desligado: ele não deve travar no `setup()`; a automação local deve controlar a ventoinha normalmente.

### B5. Integração ESP32 ↔ gateway
1. Telemetria aparece no dashboard (aba *Telemetria ao vivo*), `Aceitas` incrementa.
2. Em AUTO, provoque temperatura ou leitura do sensor acima do limite de ligar e confirme que o ESP32 aciona o relé sem depender do Render.
3. No dashboard, teste Ligar ventilador, Desligar ventilador e Automático (ESP32). Confirme no Monitor Serial `MODE=MANUAL`/`MODE=AUTO` e na telemetria o estado físico do relé.
4. Em MANUAL, interrompa a conexão com o gateway por mais de 30 segundos e confirme que a placa retoma o controle automático local.
5. Reinicie o ESP32: novo `boot` é aceito e a telemetria continua. Se o gateway reiniciar, os overrides manuais em RAM são apagados e o dispositivo volta para AUTO.

### B6. Segurança (evidências para o relatório)
| Teste | Como | Esperado |
|---|---|---|
| Assinatura inválida | `curl -X POST -H "X-Signature: 00" -d '{"node":"S1","boot":1,"seq":1}' <gateway>/telemetry` | HTTP 401 e contador `Assinatura inválida` sobe |
| Replay | Capture uma mensagem válida (log do ESP32 ou proxy) e reenvie | HTTP 409 e alerta `REPLAY` |
| Replay de boot antigo | Reinicie o ESP32 e reenvie uma mensagem do boot anterior | HTTP 409 (VULN-001) |
| Rajada | 6 requisições com assinatura inválida seguidas | 401… e depois **429** + alerta `BAD_SIGNATURE_BURST` + IP bloqueado no painel |
| Replay após reinício (VULN-006) | Reinicie o gateway (com `PURA_REQUIRE_TS=1`) e reenvie uma mensagem capturada há mais de 2 min | HTTP 409 e alerta `REPLAY` |
| Comando de outro nó (VULN-007) | Entregue ao firmware uma resposta HMAC válida, mas com `node` diferente | Serial: `comando REJEITADO: destinado a outro no`; relé não muda |
| Replay de comando | Reenvie uma resposta antiga com nonce de requisição anterior | Serial: `comando REJEITADO: nonce incorreto (resposta antiga)`; relé não muda |
| API sem credencial (VULN-008) | Abra `/api/telemetry` sem Basic Auth em bind de rede | HTTP 401; `/healthz` continua HTTP 200 |
| Telemetria inválida (VULN-009) | Assine JSON com `ppm` string ou `NaN` | HTTP 400; nenhuma política/telemetria é atualizada |
| Silêncio de nó | Desligue o ESP32 por mais de 30 s | Alerta `NODE_SILENCE` |
| Sem segredo | Suba o gateway sem `PURA_SECRET` | Recusa subir |
| **Criptografia em trânsito (VULN-004)** | Em rede de laboratório **própria**, capture com Wireshark/tcpdump: (1) `http://` e (2) `https://` | HTTP: JSON e comando legíveis. HTTPS: só dados cifrados |
| Análise offline | Rode o gateway com `--traffic-log trafego.jsonl` e depois `python -m pura.monitor trafego.jsonl` | Resumo por IP, alertas e IPs bloqueados |

Faça estes testes **apenas** no sistema do próprio grupo.

## C. Critérios de aceite
- A1 a A6 passam; B2 demonstra o CI barrando um erro; B3 mostra o serviço no ar com health check verde.
- B6 documentada com prints/logs; `docs/VULNERABILIDADES.md` referencia essas evidências.
- Todos os integrantes aparecem no histórico do GitHub e em pelo menos um PR revisado.

## D. Preparação para a avaliação individual (09 a 13/11)
Todo integrante deve conseguir responder:
1. Qual é o problema de otimização? Variáveis, objetivo (J) e restrições.
2. Por que o Dijkstra residual é um baseline mais forte? O que os resultados mostram?
3. Como funciona o ACO neste projeto (feromônio por fluxo e enlace, warm start)? E o memético?
4. Por que usar o PSO para banda e como a solução é "reparada"?
5. Onde estão Strategy e Observer no código e por que foram escolhidos?
6. Quais das 7 vulnerabilidades foram encontradas, como foram reproduzidas e como foram mitigadas?
7. O que o HMAC garante e o que ele **não** garante? Onde entra o TLS?
8. Como o monitor detecta e bloqueia ataques? Quais são os riscos do bloqueio por IP?
9. Como é o fluxo de CI/CD: o que roda em cada PR e quando acontece o deploy?
10. Quais são as limitações (dados sintéticos, simulação sem pacotes, firmware, plano gratuito)?

## E. Cronograma sugerido (hoje: 01/11; avaliação de 09 a 13/11)
| Quando | O quê |
|---|---|
| 01/11 | Criar o repositório público, subir o código, preencher `CODEOWNERS`/`GOVERNANCE`/`SECURITY`, proteger `main` (`tools/github_setup.sh`) e apresentar o MVP 1 do Projeto Tech |
| 02–03/11 | PRs com revisão de todos os integrantes (B1) e deploy no Render (B3) |
| 04–06/11 | Firmware e hardware (B4, B5) e testes de segurança com evidências (B6) |
| 07–08/11 | Ensaio das perguntas da seção D; congelar `main` com a tag `v1.0.0` **antes de 09/11** (rode `python tools/preparar_entrega.py` antes da tag) |
