# Dados, memória e retenção no P.U.R.A.

Este documento descreve os limites introduzidos para impedir crescimento não controlado de dados durante a execução.

## Arquivos em disco

### Log de tráfego

O gateway não cria logs em disco por padrão. O arquivo JSONL só é ativado quando `--traffic-log CAMINHO` é informado.

| Parâmetro | Padrão | Descrição |
|---|---:|---|
| `--traffic-log-max-bytes` | 5.242.880 bytes (5 MiB) | Tamanho máximo do arquivo ativo |
| `--traffic-log-backups` | 3 | Quantidade de arquivos rotativos preservados (máximo 10) |

O limite agregado normal é aproximadamente 20 MiB (arquivo ativo + três backups). A rotação mantém o trecho final de arquivos legados que ultrapassem o limite, preservando apenas registros completos. O campo IP e o identificador de nó também são limitados no registro para evitar uma linha individual desproporcional.

Exemplo CMD:

```cmd
python -m pura.server --traffic-log logs\trafego.jsonl
```

Falhas de escrita desativam o logger e geram um aviso em `stderr`; elas não derrubam o endpoint de telemetria.

### Outros arquivos

- `pura.experiments` sobrescreve `runs.csv`, `summary.csv`, `results.json` e gráficos no diretório de saída. Não faz append em cada execução.
- `tools.security_demo` cria o JSONL em `TemporaryDirectory`; o diretório é removido ao finalizar, inclusive em caso de exceção.
- Logs (`*.log`, `*.jsonl`) e caches Python/Ruff estão no `.gitignore` para não serem adicionados acidentalmente ao repositório.

## Limites em memória

| Estrutura | Limite | Política ao atingir o limite |
|---|---:|---|
| Amostras de telemetria | 600 | As amostras mais antigas saem da deque |
| Eventos recentes | 20.000 | Os eventos mais antigos saem da deque |
| Alertas | 200 | Os alertas mais antigos saem da deque |
| IPs bloqueados | 4096 | Expirados são removidos; se necessário, sai o bloqueio que expira primeiro |
| Nós no monitor | 1024 | Nó menos recentemente visto é removido; inatividade superior a 24 h também expira |
| Estado físico e override manual do ventilador | 1024 nós | Estado menos recentemente atualizado é removido; decisão automática roda no ESP32 |
| Estado anti-replay | 1024 nós × até 256 boots por nó | Novos nós são recusados com HTTP 503; estado existente não é descartado para liberar espaço |
| Análise offline `by_ip` | 4096 IPs | IPs adicionais são contados em `by_ip_omitted_events` |

O limite do anti-replay é deliberadamente *fail-closed*: expulsar a identidade mais antiga poderia permitir que uma mensagem anteriormente vista fosse aceita como replay. Para aumentar a capacidade, altere `MAX_REPLAY_NODES` em `pura/security.py` e dimensione a memória do gateway. A retenção de boots por nó permanece limitada a 256 entradas; em implantação de produção, mantenha `PURA_REQUIRE_TS=1` e o timestamp assinado para limitar replays após reinício e para boots antigos.

## Análise de logs grandes

`analyze_log()` percorre o JSONL linha por linha. Não carrega o arquivo inteiro em uma lista. A memória fica limitada pelo monitor, pela janela de eventos e pelo máximo de IPs detalhados.

## Verificação local

No CMD, a partir da raiz do projeto:

```cmd
python -m unittest discover -s tests -t .
python -m pura.server --help
```
