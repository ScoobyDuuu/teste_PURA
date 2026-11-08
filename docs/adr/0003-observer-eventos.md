# ADR-0003: Observer para eventos de mudança na rede
**Status**: aceita
**Contexto**: o roteamento deve reagir a falhas de enlace, picos de latência e de tráfego sem intervenção humana.
**Decisão**: `EventBus` publica `LinkFailure`, `LinkRecovery`, `LatencySpike`, `TrafficSurge`. Roteadores se inscrevem via `on_event` e marcam `dirty`; o Dijkstra "recalculado a cada evento" e as metaheurísticas só reotimizam quando notificados. A rota estática ignora eventos.
**Consequências**: reação orientada a eventos, sem polling; novos observadores (métricas, logs, alarmes) entram sem alterar o simulador.
