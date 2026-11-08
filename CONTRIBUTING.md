# Como contribuir

Este repositório é de um grupo acadêmico, mas segue práticas de projetos de código aberto.

## Fluxo de trabalho
1. Abra uma **issue** descrevendo o problema ou a melhoria (modelos em `.github/`).
2. Crie um branch a partir de `main`: `feat/<tema>`, `fix/<tema>` ou `docs/<tema>`.
3. Faça commits pequenos, com mensagens no formato `tipo: resumo` (`feat`, `fix`, `test`, `docs`, `refactor`).
4. Abra um **Pull Request** usando o modelo. Ele só entra com **1 aprovação** de outro integrante (nunca a sua própria) e CI verde (**lint, testes e build Docker**).
5. Use *squash merge*. O histórico de commits de cada integrante é evidência de contribuição.

## Rodando localmente
```bash
python -m unittest discover -s tests -t .        # 39 testes
ruff check .                                     # lint (pip install ruff); o CI exige
python -m pura.experiments --seeds 30      # protocolo experimental completo (~1 min)
PURA_SECRET=um-segredo-com-16-ou-mais python -m pura.server   # gateway + dashboard em http://localhost:8000
```

## Regras do projeto
- Toda mudança na **função objetivo ou nas restrições** (`model.py`) precisa de teste em `tests/test_model.py`.
- Um novo otimizador entra implementando `Router` e registrado em `routers/__init__.py` (padrão Strategy). Não altere o simulador.
- Resultados só valem com **baseline, várias sementes e média ± desvio-padrão**. Não apague resultados desfavoráveis.
- Dados sintéticos devem ser declarados. **Não suba capturas de tráfego de redes reais.**
- Segredos nunca entram no Git (`secrets.h` e `.env` estão no `.gitignore`).
