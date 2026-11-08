# ADR-0007: Deploy em contêiner na camada gratuita e CI/CD em duas etapas
**Status**: aceita
**Contexto**: a categoria exige deploy em nuvem e pipeline público com testes e lint em cada PR, sem custo.
**Decisão**: imagem Docker única (`Dockerfile`, usuário sem privilégios, `HEALTHCHECK`), publicada no Render gratuito via Blueprint (`render.yaml`). CI no GitHub Actions: `ruff check` (lint), testes em Python 3.10 e 3.12, fumaça dos experimentos e job `docker` que constrói a imagem, sobe o contêiner, confere `/healthz` e confirma que ele **não sobe sem segredo**. O CD é do Render com `autoDeployTrigger: checksPass` (só publica quando os checks passam). TLS é terminado pelo proxy do provedor.
**Consequências**: zero custo e deploy reprodutível. Limitações: o serviço dorme sem tráfego, o estado fica em memória e o IP do cliente depende de `PROXY_HOPS` correto (VULN-005).
