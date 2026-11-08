# ADR-0001: Monólito modular em Python (sem microsserviços)
**Status**: aceita
**Contexto**: 9 semanas, 4 integrantes, necessidade de rodar em máquina limpa. O enunciado diz que arquitetura é decisão, não requisito.
**Decisão**: um único pacote com fronteiras claras: `model` (problema), `graph`, `events`, `routers` (decisão), `simulator`, `metrics`, `bandwidth`, `security`, `server`. O motor de decisão não importa o simulador; o simulador só conhece a interface `Router`. Núcleo usa só a biblioteca padrão.
**Consequências**: setup trivial e testes rápidos; para escalar, cada módulo pode virar serviço, pois as dependências já são unidirecionais.
