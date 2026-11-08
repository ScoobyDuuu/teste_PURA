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
| VULN-005 | **`X-Forwarded-For` forjável:** a primeira versão usava o primeiro valor da lista, controlado pelo cliente, permitindo fugir do bloqueio ou incriminar outro IP. | Média | Revisão de código antes de publicar | Só confia no cabeçalho com `TRUST_PROXY=1` e usa o `PROXY_HOPS`-ésimo valor **a partir do fim** (o que o proxy acrescenta) | `Vuln005XForwardedFor` |
| VULN-006 | **Replay após reinício do gateway.** O `ReplayGuard` fica em RAM; no plano gratuito o serviço hiberna e perde o estado, então qualquer mensagem capturada voltava a ser aceita. | Média | Revisão do ciclo de vida do gateway (ADR-0007) + reprodução em teste | `ts` (epoch) no corpo **assinado**; gateway rejeita fora de ±120 s e, com `PURA_REQUIRE_TS=1` (Render), rejeita mensagem sem `ts`. ADR-0008 | `Vuln006ReplayAposReinicio` |
| VULN-007 | **Comando válido para outro nó.** O segredo é único; um comando assinado para S2 verificava como válido em S1. | Baixa | Revisão do firmware | Firmware confere `"node":"<NODE_ID>"` no corpo assinado antes de acionar o relé; gateway sempre inclui o nó destino | `Vuln007ComandoAmarradoAoNo` (contrato do gateway); **conferência no firmware: manual** |

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
- `/api/telemetry` e `/api/alerts` são públicos (somente leitura), como o dashboard: expõem leituras de temperatura/umidade/ppm e IPs vistos. Para uso real, pôr autenticação no painel.
- Dentro da janela de 120 s, após um reinício do gateway, um replay recente ainda pode passar uma vez.
- Mensagens retidas pelo atacante e entregues depois não são detectáveis sem relógio no nó (mitigado em parte pelo carimbo `ts` assinado, VULN-006, limitado à janela de 120 s).
- O bloqueio é por IP: dispositivos atrás do mesmo NAT do atacante também são barrados durante o bloqueio (120 s).
- O contador anti-replay de **comandos** fica em RAM no ESP32; após reinício, um comando antigo pode ser aceito uma vez.
- Segredo HMAC compartilhado único: comprometer um nó compromete todos. Evolução: chave por nó.
