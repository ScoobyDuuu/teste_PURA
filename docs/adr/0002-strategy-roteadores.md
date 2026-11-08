# ADR-0002: Strategy para intercambiar otimizadores
**Status**: aceita
**Contexto**: precisamos comparar 2 baselines obrigatórios, 1 baseline forte e 2 metaheurísticas com o mesmo protocolo.
**Decisão**: interface `Router` (`decide`) com Template Method `routes()` que cuida de cache, cronometragem e dirty flag. Fábrica `make_router(nome, semente)`. Alocação de banda segue o mesmo padrão (`ProportionalAllocator` / `PSOAllocator`).
**Consequências**: adicionar um otimizador não toca no simulador; a comparação é justa porque o ciclo de decisão é idêntico. Custo: o roteador estático precisa de uma flag `reactive`.
