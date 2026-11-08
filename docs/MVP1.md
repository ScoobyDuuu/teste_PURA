# MVP 1 (01/11/2026) — respostas às 4 perguntas do portão

1. **Qual é o problema de otimização?** Escolher, para cada um de 10 fluxos, um caminho em uma rede mesh que muda durante a execução.
   Variáveis: caminho por fluxo. Objetivo: minimizar J = Σ peso·(latência sob carga + 30·risco) + penalidade de sobrecarga + penalidade de fluxo sem rota.
   Restrições: capacidade dos enlaces, zona proibida para fluxos de controle, rota válida (sem laço, só enlaces ativos). Ver `pura/model.py`.
2. **Os dados já estão na mão?** Sim, simulação sintética em execução (`python -m pura.experiments`) e telemetria real do ESP32 no gateway.
3. **O que estará pronto em 01/11?** Pronto: modelo, baselines (estático, Dijkstra, Dijkstra residual), ACO, Memético, PSO de banda, simulador com eventos, gateway com HMAC, dashboard, testes, 30 execuções com média ± desvio. **Fora do escopo**: Mininet/NS-3, topologias do Topology Zoo, TLS, múltiplos ESP32 formando a malha física.
4. **Todos estão contribuindo?** Preencher com o gráfico de commits do GitHub (Insights → Contributors). Cada integrante deve ter commits em sua área (ver GOVERNANCE.md).
