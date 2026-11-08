# ADR-0005: Protocolo experimental e dados sintéticos
**Status**: aceita
**Contexto**: o enunciado exige baseline, múltiplas execuções, dados declarados e aceita resultado negativo honesto.
**Decisão**: topologia fixa de 16 nós e 30 enlaces com parâmetros sorteados por semente (±15% / ±0,03); 10 fluxos; 60 ticks com 7 eventos programados; 2 intensidades de pico de tráfego; 30 sementes por célula; comparação pareada por semente com IC95%. Baselines: rota estática, Dijkstra recalculado (obrigatórios) e Dijkstra com capacidade residual (baseline forte, para evitar comparação com espantalho). Dados 100% sintéticos, sem captura de rede real.
**Consequências**: reprodutível (`python -m pura.experiments`). Limitação: J é a função que as metaheurísticas otimizam; por isso as conclusões usam também métricas independentes (latência p95, goodput).
