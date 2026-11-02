# SecuraPy — SIEM Simplificado

> Trabalho Final (Global Solution) — Coding for Security
> CyberShield Ltda. · MVP de um SIEM (Security Information and Event Management)

<!-- Trechos marcados com "PREENCHER" devem ser completados por cada integrante. -->

---

## Integrantes

| Nome | RM | Responsabilidade |
|---|---|---|
| Vini | PREENCHER | Pessoa 1: Núcleo do sistema e banco de dados |
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
├── ml/                 # Pessoa 2 — Machine Learning e integridade
│   ├── __init__.py
│   ├── features.py
│   ├── treinar.py
│   ├── classificar.py
│   ├── requirements.txt
│   ├── test_ml.py
│   └── README.md
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

**Responsável:** GabrielDav07

O Módulo C fica na pasta `ml/` e complementa os eventos do coletor e os alertas do correlacionador dos módulos A/B.

#### Arquivos e funções

| Arquivo | Funções principais | Responsabilidade |
|---|---|---|
| `features.py` | `extrair_features()` e `features_de_ameaca()` | Extrai atributos dos eventos por IP e adapta alertas ao formato de entrada do classificador. |
| `treinar.py` | `treinar()`, `construir_pipeline()` e `sha256_arquivo()` | Treina e avalia o modelo, salva o artefato com `joblib` e gera seu hash SHA-256. |
| `classificar.py` | `carregar_modelo()`, `pontuar()` e `classificar_features()` | Confere o hash antes de carregar o modelo e classifica alertas, acrescentando score e faixa de risco. |
| `test_ml.py` | Testes de contrato e integridade | Verifica a extração de atributos, a adaptação de alertas B e se uma divergência no hash impede o carregamento do modelo. |
| `requirements.txt` | — | Lista as dependências de Machine Learning e testes. |

#### Atributos extraídos

Os eventos são agrupados por IP. O extrator usa os campos normalizados pelo coletor, como `fonte`, `tipo`, `ip` e `detalhes`.

| Atributo | Como é calculado |
|---|---|
| `falhas_auth` | Quantidade de eventos de autenticação com tipo `FAIL`. |
| `portas_distintas` | Quantidade de portas diferentes encontradas no campo `dport` dos eventos de firewall. |
| `ip_blacklist` | Indica se o IP aparece na blacklist informada ao sistema. |
| `erros_web` | Quantidade de eventos web cujo status HTTP é 400 ou superior. |
| `eventos_total` | Quantidade total de eventos associados ao IP. |
| `bloqueios_firewall` | Quantidade de eventos de firewall com tipo `BLOCK`. |

O alerta emitido pelo correlacionador B contém `timestamp`, `regra`, `severidade`, `ip` e `descricao`. Quando `pontuar()` recebe também os eventos originais, calcula os atributos completos do IP. Sem os eventos, consegue recuperar da descrição apenas a contagem explícita de falhas; os demais atributos ficam neutros.

#### Treinamento e avaliação

A função `treinar()` recebe os eventos e um mapa de rótulos revisados pela equipe, associando IPs às classes `ataque` ou `normal`. O modelo é um pipeline com `StandardScaler` e `RandomForestClassifier`. O pipeline é avaliado por validação cruzada estratificada, com até cinco divisões, limitado pela quantidade de exemplos da classe minoritária. São necessários pelo menos dois IPs rotulados em cada classe.

| Métrica | O que representa |
|---|---|
| Precisão | Entre os IPs classificados como ataque, quantos estavam rotulados como ataque. |
| Recall | Entre os IPs rotulados como ataque, quantos foram encontrados pelo modelo. |
| F1 | Equilíbrio entre precisão e recall. |

As métricas tratam `ataque` como classe positiva. O programa calcula e exibe a média dos folds durante o treinamento. **Os valores obtidos devem ser preenchidos após uma execução com dados e rótulos definidos pela equipe; esta documentação não informa resultados numéricos que ainda não foram medidos.**

Para instalar as dependências e executar os testes a partir da raiz do repositório:

```bash
python -m pip install -r ml/requirements.txt
python -m pytest ml/test_ml.py
```

Para treinar com arquivos próprios de eventos e rótulos:

```bash
python -m ml.treinar --eventos-json eventos.json --rotulos-json rotulos.json --modelo ml/modelo.pkl
```

O arquivo `rotulos.json` deve conter rótulos revisados, por exemplo, no formato `{ "IP": "ataque" }` ou `{ "IP": "normal" }`. Não se deve usar a previsão do próprio modelo como rótulo de referência.

#### Persistência e integridade

Após o treinamento, o modelo é salvo em formato `joblib`, por exemplo, `ml/modelo.pkl`. A função `sha256_arquivo()` calcula o SHA-256 desse arquivo, e o resultado é registrado ao lado dele em `ml/modelo.pkl.sha256`.

Antes de chamar `joblib.load()`, `carregar_modelo()` compara o hash atual do modelo com o valor registrado. Se os valores forem diferentes, o carregamento é interrompido. O hash permite detectar alterações no artefato, desde que o arquivo de referência seja mantido confiável.

**Nesta implementação, a verificação SHA-256 é feita sobre o arquivo do modelo, não sobre os logs.**

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
