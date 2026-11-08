# Registro de vulnerabilidades (identificadas, mitigadas e testadas)

Escopo: o próprio sistema (gateway, protocolo ESP32↔gateway, dashboard). Todas foram **reproduzidas** antes da correção
e têm **teste de regressão** em `tests/test_vulnerabilities.py`. As severidades são estimativas qualitativas da equipe,
não pontuações CVSS oficiais.

| ID | Vulnerabilidade | Severidade | Como foi encontrada | Mitigação | Teste |
|---|---|---|---|---|---|
| VULN-001 | **Replay de mensagem de boot antigo.** `ReplayGuard` só lembrava o último `(boot, seq)`; qualquer mensagem de outro boot era aceita. | Alta | Revisão de código do anti-replay + reprodução | Guarda mantém o maior `seq` de **cada** boot (até 256 por nó) | `Vuln001Replay` |
| VULN-002 | **Segredo padrão público.** Sem `PURA_SECRET`, o gateway subia com uma chave conhecida (qualquer pessoa assinaria mensagens válidas). | Alta | Revisão de configuração | Gateway **recusa subir** sem segredo ≥ 16 caracteres; modo laboratório exige `PURA_ALLOW_DEV_SECRET=1`; CI verifica que o contêiner falha sem segredo | `Vuln002SegredoFraco` |
| VULN-003 | **Sem limitação de taxa:** força bruta de assinaturas e inundação de requisições. | Média | Modelagem de ameaças (STRIDE: spoofing e DoS) | `TrafficMonitor` detecta rajadas/inundação e **bloqueia o IP** (HTTP 429) por tempo limitado; alertas no dashboard | `Vuln003ForcaBrutaEFlood`, `test_monitor` |
| VULN-004 | **Tráfego em claro (HTTP):** o HMAC garante integridade/autenticidade, mas telemetria e comandos podiam ser lidos na rede. | Média | Captura de pacotes (ver roteiro de testes) | TLS na nuvem (proxy do provedor) e firmware com `https://` + verificação do certificado raiz + NTP. HTTP só em laboratório isolado | Manual (Wireshark), `docs/TESTES.md` |
| VULN-005 | **`X-Forwarded-For` forjável:** a primeira versão confiava no cabeçalho sem validar o peer TCP. | Alta | Revisão de código + teste com peer não confiável | Só usa o cabeçalho se o peer pertencer a `PURA_TRUSTED_PROXY_CIDRS`; seleciona `PROXY_HOPS` a partir do fim e valida os IPs | `Vuln005XForwardedFor` |
| VULN-006 | **Replay após reinício do gateway.** O `ReplayGuard` fica em RAM; no plano gratuito o serviço hiberna e perde o estado, então qualquer mensagem capturada voltava a ser aceita. | Média | Revisão do ciclo de vida do gateway (ADR-0007) + reprodução em teste | `ts` (epoch) no corpo **assinado**; gateway rejeita fora de ±120 s e, com `PURA_REQUIRE_TS=1` (Render), rejeita mensagem sem `ts`. ADR-0008 | `Vuln006ReplayAposReinicio` |
| VULN-007 | **Comando válido para outro nó.** O segredo é único; um comando assinado para S2 verificava como válido em S1. | Alta | Revisão do firmware | O firmware confere o nó e um nonce aleatório por requisição; a chamada também exige HMAC próprio, e a resposta é assinada e contém o mesmo nonce | `Vuln007ComandoAmarradoAoNo` + testes de contrato |
| VULN-008 | **APIs e dashboard sem autenticação.** Leituras, IPs e alertas eram públicos em bind de rede. | Alta | Revisão dos endpoints HTTP | Basic Auth opcional no loopback e obrigatório (senha de 16+ caracteres) em bind externo; `/healthz` permanece público | `DashboardAuthTests` |
| VULN-009 | **Validação insuficiente de telemetria.** Campos assinados, mas malformados, podiam alterar o estado associado ao ventilador. | Média | Entrada JSON malformada | Validação de tipo, faixa, finitude e inteiros uint32 antes de alterar estados | `TelemetryValidationTests` |
| VULN-010 | **Exaustão por conexões concorrentes.** Servidor criava uma thread por conexão sem limite. | Média | Revisão de `ThreadingHTTPServer` | Limite de 32 workers e timeout de leitura de 5 segundos | `ServerResourceLimitTests` |

## Evidência de VULN-001 (antes da correção)
```
ESP32 envia boot=111 seq=5     -> aceito
ESP32 reinicia: boot=222 seq=1 -> aceito
ATACANTE reenvia (boot=111, seq=5) -> aceito   <- VULNERÁVEL
```
Depois da correção o mesmo reenvio retorna **HTTP 409** (`results/seguranca_demo.txt`, passo 3).

## Evidência de VULN-006
```
Gateway reinicia (guard vazio). Atacante reenvia mensagem capturada há 10 min (ts antigo) -> HTTP 409   (test_replay_apos_reinicio_do_gateway_e_barrado)
Mensagem nova (ts atual)                                                                -> HTTP 200
Mensagem sem ts com PURA_REQUIRE_TS=1                                                    -> HTTP 409
```

## Riscos residuais (assumidos)
- `/healthz` permanece público para health checks; não revela telemetria.
- Em implantação atrás de proxy, `X-Forwarded-For` só será usado quando `TRUST_PROXY=1` e o peer estiver em `PURA_TRUSTED_PROXY_CIDRS`. Configuração incorreta pode agrupar clientes sob o IP do proxy, mas não permite forjar o IP a partir de um peer não confiável.
- Dentro da janela de 120 s, após reinício do gateway, uma mensagem de telemetria capturada recentemente ainda pode passar uma vez; use `PURA_REQUIRE_TS=1` em produção.
- O bloqueio é por IP: dispositivos atrás do mesmo NAT também podem ser bloqueados durante a janela.
- HTTP em laboratório não oferece confidencialidade. Na Internet, use HTTPS/TLS.
- Segredo HMAC compartilhado único: comprometer um nó compromete todos. Evolução futura: chave por nó.


## Hardening de armazenamento e memória

A revisão posterior identificou crescimento potencial em logs JSONL e tabelas de rastreamento. As medidas atuais são:

- `--traffic-log` fica desativado por padrão; quando habilitado, cada arquivo tem limite padrão de 5 MiB e são mantidos até três backups rotativos.
- `tools.security_demo` usa `TemporaryDirectory`, removido automaticamente ao finalizar.
- A análise offline percorre o JSONL em streaming e detalha no máximo 4096 IPs.
- Monitor e política do gateway possuem limites de IPs/nós; o estado anti-replay aceita até 1024 identidades e recusa novos nós com HTTP 503 quando a capacidade acaba, sem expulsar estado de segurança antigo.
- Telemetria valida tipos, intervalos, finitude e inteiros uint32 antes de alterar o estado.
- Leituras `null` nos dois sensores não são tratadas como ambiente seguro; o gateway preserva o estado do relé reportado pelo ESP32.
- Nó recebido com identificador inválido é rejeitado.

Essas medidas limitam o crescimento provocado pelo processo. Elas não removem automaticamente arquivos antigos de log criados antes da atualização, exceto quando o arquivo é rotacionado pela primeira vez. Consulte `docs/DADOS_E_RETENCAO.md`.
