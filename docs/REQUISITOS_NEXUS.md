# Matriz de requisitos — Categoria NEXUS (ExpoTech 2026.2) — atualizada em 01/11/2026

Verificado neste ambiente: **39 testes OK · `ruff check .` OK (ruff real) · experimentos de 30 sementes reproduzidos sem diferença ·
demo de ataques (A4) OK · gateway sobe com segredo e recusa sem segredo (A5/A6 sem Docker)**. Docker e hardware **não** foram exercitados.

| Requisito | Evidência no repositório | Situação |
|---|---|---|
| **Open Source**: licença reconhecida | `LICENSE` (MIT) | Pronto |
| README completo | `README.md` | Pronto |
| CONTRIBUTING.md | `CONTRIBUTING.md`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, template de PR, CODEOWNERS | Pronto no código; **preencher nomes/usuários** (`tools/preparar_entrega.py` lista) |
| **Ao menos um ciclo real de PR com revisão entre integrantes** | `docs/TESTES.md` B1 | **Pendente (grupo)**: não pode ser gerado por código |
| **Telecom & Security**: monitoramento de tráfego | `pura/monitor.py` (online e offline JSONL), painel no dashboard | Pronto |
| ≥ 1 vulnerabilidade real identificada **e mitigada** | `docs/VULNERABILIDADES.md`: **7 casos** (VULN-006 e 007 novos), testes de regressão | Pronto |
| Protocolos de telecom / criptografia em trânsito | HMAC-SHA256 + janela de tempo assinada + TLS | Pronto; **firmware (inclui `ts` e checagem de nó) não testado em hardware** |
| **CI & AO**: técnica de inteligência computacional | ACO, Memético, PSO; baselines; 30 sementes (reproduzido) | Pronto |
| **Arquitetura e padrões** documentados e justificados | Strategy, Observer, guarda de rotas, Template Method; **8 ADRs** | Pronto |
| **Cloud**: deploy em nuvem (camada gratuita) | `Dockerfile`, `render.yaml`, `docs/DEPLOY.md` | Configurado; **deploy a executar pelo grupo** |
| Pipeline CI/CD público com **testes e lint** em cada PR | `.github/workflows/ci.yml` + CD do Render; **lint agora passa** | Configurado; **precisa do repositório público**; proteção da main: `tools/github_setup.sh` |
| Equipe de 3 a 5 integrantes, inscrição até 15/09 | Fora do código | Verificar com o grupo |
| Avaliação individual (09 a 13/11) | `docs/TESTES.md` D | Preparar |
| Projeto **não pode ser alterado após a avaliação** | Tag `v1.0.0` antes de 09/11; `python tools/preparar_entrega.py` | Atenção ao calendário |
