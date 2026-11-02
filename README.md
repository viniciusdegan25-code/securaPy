# SecuraPy — SIEM Simplificado

> Trabalho Final (Global Solution) — Coding for Security
> CyberShield Ltda. · MVP de um SIEM (Security Information and Event Management)

<!-- Trechos marcados com "PREENCHER" devem ser completados por cada integrante. -->

---

## Integrantes

| Nome | RM | Responsabilidade |
|---|---|---|
| PREENCHER | PREENCHER | Pessoa 1: Núcleo do sistema e banco de dados |
| GabrielDav07 | PREENCHER | Pessoa 2: Machine Learning e integridade (SHA-256) |
| PREENCHER | PREENCHER | Pessoa 3: API REST (Flask) e Docker |
| PREENCHER | PREENCHER | Pessoa 4: Dashboard web e assistente com LLM |

---

## Descrição do projeto

O **SecuraPy** lê logs de três fontes (autenticação, firewall e servidor web), transforma
cada linha em um **evento padronizado** e analisa esses eventos para encontrar ataques:
brute force, port scan, path traversal, XSS e reconhecimento web.

O sistema foi dividido em módulos independentes. Todos partem da mesma **lista de eventos**
gerada pelo coletor, e cada módulo devolve **alertas** num formato comum, para que as partes
se encaixem sem depender umas das outras.

```
logs/*.log ──► coletor.py ──► lista de eventos ──┬──► banco_dados.py (MongoDB)
                                                 ├──► correlacao.py  (alertas)
                                                 ├──► ML (Pessoa 2)
                                                 └──► regras / detector / API / dashboard
```

---

## Estrutura de pastas

```
securaPy/
├── coletor.py          # Pessoa 1 — leitura e normalização dos logs (Módulo 1)
├── banco_dados.py      # Pessoa 1 — persistência dos eventos no MongoDB
├── correlacao.py       # Pessoa 1 — BÔNUS: brute force por janela de tempo
├── gerador_logs.py     # Pessoa 1 — BÔNUS: geração automática de logs
├── logs/               # Logs de teste do enunciado
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── logs_gerados/       # Criada pelo gerador_logs.py
├── config/
├── saida/              # Relatórios gerados
├── PREENCHER           # arquivos da Pessoa 2
├── PREENCHER           # arquivos da Pessoa 3
├── PREENCHER           # arquivos da Pessoa 4
└── README.md
```

---

## Dependências

- **Python 3** (use o Python global, não o `.venv`: veja "Problemas comuns")
- **MongoDB** rodando em `localhost:27017` (conferir pelo MongoDB Compass)
- Bibliotecas Python:

```bash
python -m pip install pymongo
# PREENCHER: bibliotecas das outras partes (ex.: flask, requests, scikit-learn...)
```

`os`, `datetime` e `random` já vêm com o Python.

---

## Como executar

1. Abra o **MongoDB Compass** e conecte em `mongodb://localhost:27017`.
2. Instale as dependências (seção acima).
3. No terminal, entre na pasta do projeto:

```bash
cd securaPy
```

4. Execute o sistema:

```bash
PREENCHER: comando principal do sistema (ex.: python main.py)
```

### Testar cada módulo da Pessoa 1 separadamente

| Comando | Resultado esperado |
|---|---|
| `python coletor.py` | `23 eventos de auth, 17 de firewall, 18 de web. Total: 58 eventos` |
| `python banco_dados.py` | 1ª execução: 58 eventos gravados. 2ª execução: 0 (não duplica) |
| `python correlacao.py` | `[ALTA] 185.220.101.1 — 11 falhas em 39s (janela de 60s)` |
| `python gerador_logs.py` | O IP de brute force do gabarito é o mesmo que o SIEM detecta |

---

## Divisão de tarefas

### Pessoa 1 — Núcleo do sistema e banco de dados

**Responsável:** PREENCHER

#### Coletor de logs (`coletor.py`) — Módulo 1

Lê os três arquivos de log, interpreta cada linha e transforma tudo em um **evento padronizado**:

```python
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | ALLOW | BLOCK | REQUEST
    "ip": "185.220.101.1",        # IP de origem
    "detalhes": "usuario=admin",
    "linha_original": "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"
}
```

| Função | O que faz |
|---|---|
| `parsear_linha_auth(linha)` | Interpreta uma linha do `auth.log` |
| `parsear_linha_firewall(linha)` | Interpreta uma linha do `firewall.log` (usa o IP de origem, `src`) |
| `parsear_linha_web(linha)` | Interpreta uma linha do `web_access.log` (tipo sempre `REQUEST`) |
| `extrair_valor(pedaco, chave)` | Separa `chave=valor` e confere se a chave é a esperada |
| `conferir_tamanho(pedacos, esperado)` | Confere se a linha tem a quantidade certa de campos |
| `carregar_log(caminho_arquivo, fonte)` | Lê um arquivo e devolve a lista de eventos |
| `carregar_todos_os_logs(pasta_logs)` | Lê todos os logs da pasta (`os.listdir`) e devolve uma lista única, em ordem de horário |
| `contar_por_fonte(eventos)` | Conta os eventos de cada fonte |

Decisões de projeto:
- Um dicionário `PARSERS` liga cada fonte à sua função, evitando uma cadeia de `if/elif`.
- As funções `extrair_valor` e `conferir_tamanho` são usadas pelos três parsers, sem código repetido.
- `split("=", 1)` corta só no primeiro `=`, para que URLs como `/busca?q=teste` não quebrem.

**Tratamento de erros (cenários de teste do enunciado):**

| Cenário | Comportamento | Situação |
|---|---|---|
| 1. Carregar `auth.log` | 23 eventos com todos os campos | ✅ |
| 2. Arquivo inexistente | `[ERRO] Arquivo não encontrado`, devolve lista vazia, não trava | ✅ |
| 3. Linha mal formatada | `[AVISO] ... linha N ignorada`, as demais são lidas | ✅ |
| 4. Todos os logs da pasta | 58 eventos, campo `fonte` correto em cada um | ✅ |
| 5. Arquivo vazio | `[INFO] O arquivo ... está vazio`, devolve lista vazia | ✅ |

Exceções usadas: `FileNotFoundError` (arquivo ou pasta inexistente) e `ValueError` (linha inválida). Nenhum `except:` genérico.

#### Banco de dados (`banco_dados.py`)

Guarda os eventos no **MongoDB**, banco `securapy`, coleção `eventos`.

| Função | O que faz |
|---|---|
| `conectar_banco()` | Conecta ao MongoDB; se ele estiver desligado, avisa e devolve `None` (o SIEM continua em memória) |
| `salvar_eventos(colecao, eventos)` | Grava os eventos sem duplicar e devolve quantos eram novos |
| `buscar_por_ip(colecao, ip)` | Devolve todos os eventos de um IP, em ordem de horário |
| `contar_por_fonte_no_banco(colecao)` | Conta os eventos de cada fonte direto no banco |

**Sem duplicatas:** cada documento recebe um `_id` formado por `fonte|linha_original`.
A gravação usa `UpdateOne` com `$setOnInsert` e `upsert=True`: se o evento já existe, nada muda.
Rodar o programa várias vezes mantém sempre os mesmos 58 documentos.

#### BÔNUS — Correlação temporal (`correlacao.py`) · +0,30

Detecta brute force considerando o **tempo**: mais de 5 logins falhos do mesmo IP dentro de 60 segundos.
Para cada falha, o algoritmo conta quantas outras acontecem nos 60 segundos seguintes e guarda a maior contagem.

| Janela | Resultado com os logs do enunciado |
|---|---|
| 60 segundos | `185.220.101.1`: 11 falhas em 39s, severidade **ALTA** |
| 10 segundos | Nenhum ataque (as falhas estão espaçadas demais) |

A diferença entre as duas janelas comprova que o sistema considera **quando** as falhas aconteceram, e não só quantas foram.
Severidade: mais de 5 = MEDIA, mais de 10 = ALTA, mais de 20 = CRITICA. Os alertas seguem o formato padrão
(`timestamp`, `regra`, `severidade`, `ip`, `descricao`).

#### BÔNUS — Geração automática de logs (`gerador_logs.py`) · +0,20

Cria os três arquivos de log na pasta `logs_gerados/` (os logs do enunciado não são alterados), com:
- **tráfego normal:** funcionários de IP interno fazendo login, acessando portas permitidas e navegando;
- **ataques injetados:** brute force, port scan em portas críticas e acessos web maliciosos (path traversal, XSS, reconhecimento).

A função devolve um **gabarito** com o IP de cada atacante. Com `semente=42`, os logs saem sempre iguais.

Resultado verificado: 178 eventos lidos sem nenhum aviso, e o IP de brute force do gabarito (`91.159.204.172`)
é o mesmo detectado pela correlação temporal (18 falhas em 28s, ALTA).

---

### Pessoa 2 — Machine Learning e integridade (SHA-256)

**Responsável:** PREENCHER

PREENCHER: arquivos, funções, como o modelo foi treinado, métricas obtidas e verificação de hash dos logs.

---

### Pessoa 3 — API REST (Flask) e Docker

**Responsável:** PREENCHER

PREENCHER: rotas da API, como subir os containers.

---

### Pessoa 4 — Dashboard web e assistente com LLM

**Responsável:** PREENCHER

PREENCHER: telas do dashboard, como o assistente funciona.

---

## Bônus implementados

| Bônus | Pontos | Responsável | Situação |
|---|---|---|---|
| Correlação temporal | +0,30 | Pessoa 1 | ✅ |
| Geração automática de logs | +0,20 | Pessoa 1 | ✅ |
| Hash de integridade (SHA-256) | +0,20 | Pessoa 2 | PREENCHER |
| Regras customizadas pelo menu | +0,30 | PREENCHER | PREENCHER |

---

## Observações

- O enunciado indica 10 falhas de login para o IP `185.220.101.1`, mas o próprio `auth.log` contém **11**
  (08:15:01, :02, :06, :08, :16, :18, :22, :28, :33, :38, :40). O sistema reporta o valor correto, 11.
- MongoDB, Machine Learning, Flask e Docker foram escolhas do grupo, além do que o enunciado exige.

## Problemas comuns

| Mensagem | Solução |
|---|---|
| `No module named 'pymongo'` | `python -m pip install pymongo` no mesmo terminal em que o código roda |
| `SystemError: module bson._cbson uses unknown slot ID` | O VS Code está usando o `.venv`. Rode `deactivate` e escolha o Python global em `Python: Select Interpreter` |
| `ModuleNotFoundError: No module named 'coletor'` | O arquivo está fora da pasta `securaPy/` |
| `[AVISO] MongoDB não está rodando` | Abra o Compass e conecte em `localhost:27017` |
