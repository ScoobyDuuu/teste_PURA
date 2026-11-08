# Política de segurança

**Escopo**: código deste repositório (simulador, gateway, firmware). Não há dados reais de terceiros.
**Como reportar**: abra um *security advisory* privado no GitHub ou envie e-mail ao mantenedor (preencher).
**Histórico**: vulnerabilidades tratadas e riscos residuais estão em `docs/VULNERABILIDADES.md` (VULN-001 a VULN-010).
**Limitações conhecidas**: HMAC garante integridade e autenticidade; confidencialidade exige TLS (`https://`). Em laboratório com HTTP, use rede isolada. O nonce por requisição protege respostas de comando contra replay sem depender de contador persistente no ESP32; o estado anti-replay da telemetria fica em RAM no gateway e exige timestamp em produção (`PURA_REQUIRE_TS=1`). O segredo HMAC é compartilhado por todos os nós; o bloqueio é por IP. Dashboard e APIs de leitura usam Basic Auth quando expostos fora do loopback; `/healthz` é público para health checks.
**Segredos**: `PURA_SECRET` (16+ caracteres) e `PURA_DASHBOARD_PASSWORD` (16+ caracteres em bind externo) nunca devem ser versionados.
**Ética**: ataques de teste somente contra o gateway do próprio grupo (`tools/security_demo.py` só fala com 127.0.0.1).
