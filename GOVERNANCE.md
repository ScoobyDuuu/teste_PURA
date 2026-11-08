# Governança

| Papel | Responsabilidade | Quem |
|---|---|---|
| Mantenedores | Aprovam PRs, fazem releases, resolvem conflitos | todos os integrantes do grupo (preencher nomes) |
| Responsável de área | Revisor obrigatório da sua área (ver `.github/CODEOWNERS`) | CI&AO, Telecom&Security, Arquitetura, Open Source |
| Orientação | Valida escopo e rumo | professor(a) da disciplina |

**Decisões**: por consenso em issue/PR; se não houver, voto simples dos mantenedores. Decisões de arquitetura viram
ADR em `docs/adr/` (imutável: para mudar, cria-se um ADR novo que substitui o anterior).
**Branch `main`**: protegida, PR obrigatório, 1 aprovação, CI verde. **Releases**: tags semânticas (`v1.0.0` = entrega final).
