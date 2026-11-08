# P.U.R.A. — Purificação Unificada e Reativa do Ar

Sistema de monitoramento e purificação de microclimas internos. Nós ESP32 medem temperatura, umidade e concentração estimada de poluentes; o gateway Python recebe telemetria autenticada, monitora o tráfego e disponibiliza um dashboard local ou hospedado na nuvem.

## Requisitos

- Python 3.10 ou superior.
- O núcleo (gateway, simulador, testes e ferramentas) usa somente a biblioteca padrão.
- Matplotlib é opcional e necessário apenas para gerar os gráficos PNG dos experimentos.

## Como instalar e executar no Windows (CMD)

Execute os comandos a partir da pasta raiz do projeto, onde estão `README.md`, `requirements.txt` e `pyproject.toml`.

```cmd
REM Instala o Ruff, usado para lint e desenvolvimento.
python -m pip install -r requirements-dev.txt

REM Executa os testes automatizados.
python -m unittest discover -s tests -t .

REM Verifica o código com Ruff.
python -m ruff check .

REM Executa 30 sementes; recria os arquivos de resultados em results/.
python -m pura.experiments --seeds 30

REM Executa a demonstração de segurança apenas no loopback (127.0.0.1).
REM Os arquivos temporários são removidos automaticamente ao terminar.
python -m tools.security_demo
```

Para gerar os gráficos PNG dos experimentos, instale a dependência opcional:

```cmd
python -m pip install -r requirements-graphics.txt
```

### Iniciar o servidor e o dashboard

Configure um segredo local com pelo menos 16 caracteres e inicie o gateway:

```cmd
REM Defina a chave somente nesta janela do CMD.
set "PURA_SECRET=troque-por-um-segredo-local-com-mais-de-16-caracteres"

REM Inicie o servidor acessível apenas pelo próprio computador.
python -m pura.server --host 127.0.0.1 --port 8000
```

Abra `http://127.0.0.1:8000` no navegador. O servidor permanece em execução até `Ctrl+C`.

Para acesso pela rede local (por exemplo, ESP32 + outro computador), defina uma senha separada para o dashboard e faça bind em todas as interfaces:

```cmd
set "PURA_DASHBOARD_PASSWORD=senha-dashboard-com-pelo-menos-16-caracteres"
python -m pura.server --host 0.0.0.0 --port 8000
```

O navegador solicitará usuário `pura` e essa senha via Basic Auth. Libere a porta apenas na rede necessária pelo Firewall do Windows; não exponha o gateway diretamente à Internet sem TLS.

### Log opcional de tráfego

O registro em disco fica **desativado por padrão**. Para habilitá-lo, use `--traffic-log`. O limite padrão é 5 MiB por arquivo, com três backups rotativos (aproximadamente 20 MiB no total; máximo configurável de 10 backups):

```cmd
python -m pura.server --host 127.0.0.1 --port 8000 --traffic-log logs\trafego.jsonl
```

Os limites podem ser ajustados com `--traffic-log-max-bytes` (mínimo 1024 bytes) e `--traffic-log-backups` (padrão 3; use 0 para não manter backups). Para analisar um arquivo:

```cmd
python -m pura.monitor logs\trafego.jsonl
```

A análise lê o JSONL em fluxo e mantém no máximo 4096 IPs detalhados em memória. Registros de IPs adicionais são contabilizados em `by_ip_omitted_events`.

## Dependências

| Arquivo | Conteúdo |
|---|---|
| `requirements.txt` | Nenhuma dependência externa obrigatória; núcleo baseado na biblioteca padrão. |
| `requirements-dev.txt` | Ruff para lint e desenvolvimento. |
| `requirements-graphics.txt` | Matplotlib opcional para gráficos PNG. |

## Retenção e armazenamento

- Telemetria em memória: últimas 600 amostras.
- Eventos recentes do monitor: até 20.000.
- Alertas em memória: até 200.
- IPs bloqueados em memória: até 4096; entradas expiradas são removidas.
- Nós monitorados: até 1024; registros inativos são removidos após 24 horas.
- Estado anti-replay: até 1024 identidades, com até 256 boots por nó. Ao atingir a capacidade, novos nós são recusados (fail-closed), em vez de descartar estado anti-replay existente.
- Estado físico reportado e override remoto do ventilador: até 1024 nós; decisão automática executada no ESP32.
- Logs de tráfego: desativados por padrão; quando habilitados, rotação com limite configurável.
- Demonstração de segurança: utiliza diretório temporário removido automaticamente.
- Experimentos: recriam os arquivos fixos em `results/`; não acrescentam linhas a cada execução.

Consulte `docs/DADOS_E_RETENCAO.md` para os limites e suas implicações.

## Estrutura

| Pasta/arquivo | Conteúdo |
|---|---|
| `pura/model.py` | Rede, fluxos, restrições e função objetivo |
| `pura/routers/` | Estratégias de roteamento: static, Dijkstra, ACO e memético |
| `pura/events.py` | Observer: eventos de rede e EventBus |
| `pura/bandwidth.py` | PSO e alocação proporcional de banda |
| `pura/simulator.py` | Simulador e validação de rotas |
| `pura/security.py`, `pura/server.py` | HMAC, anti-replay, gateway e API |
| `pura/monitor.py` | Monitoramento, alertas e bloqueio de IP |
| `tools/` | Demonstração de segurança, minilint e preparação de entrega |
| `web/index.html` | Dashboard de resultados e telemetria |
| `firmware/esp32_node/` | Firmware do nó ESP32 |
| `docs/` | Hardware, deploy, testes, ADRs e vulnerabilidades |

## Integração ESP32 + Render

O firmware em `firmware/esp32_node/` envia telemetria para o gateway via HTTPS/HMAC e consulta comandos autenticados. O controle automático da ventoinha roda localmente no ESP32; o dashboard pode forçar LIGADO/DESLIGADO ou devolver o modo AUTO. Para publicar no GitHub e implantar no Render, siga `docs/DEPLOY.md`; para configurar Wi-Fi, URL, segredo, TLS, sensores, relé e controle remoto, siga `docs/ESP32_RENDER.md`. O arquivo privado `firmware/esp32_node/secrets.h` não deve ser versionado.

## Segurança e nuvem

O gateway exige `PURA_SECRET` com pelo menos 16 caracteres. O dashboard e `/api/*` usam Basic Auth quando `PURA_DASHBOARD_PASSWORD` é definido; para bind fora de localhost essa senha é obrigatória (mínimo 16 caracteres). Em produção, use HTTPS/TLS e `PURA_REQUIRE_TS=1` quando o firmware estiver sincronizado por NTP. Só habilite `TRUST_PROXY=1` após configurar `PURA_TRUSTED_PROXY_CIDRS` com os CIDRs reais dos proxies. Consulte `docs/DEPLOY.md`, `docs/HARDWARE.md` e `docs/VULNERABILIDADES.md`.

## Licença

MIT (`LICENSE`).
## Controle remoto da ventoinha

Veja [docs/CONTROLE_REMOTO.md](docs/CONTROLE_REMOTO.md) para a localização do painel no dashboard, regras MANUAL/AUTO e verificação da telemetria.
