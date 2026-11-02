# SecuraPy Platform

> Trabalho Final (Global Solution) — Coding for Security · 2º semestre
> CyberShield Ltda. · Evolução do SIEM SecuraPy para uma plataforma de segurança

<!-- Trechos marcados com PREENCHER devem ser completados por cada integrante. -->

---

## Integrantes

| Nome | RM | Responsabilidade | Módulos |
|---|---|---|---|
| Vinicius | 569279 | Núcleo + Persistência | A, B |
| Gabriel D | PREENCHER | Machine Learning | C |
| PREENCHER | PREENCHER | API REST + Docker | D, F |
| PREENCHER | PREENCHER | Web + LLM | E, G |

---

## Descrição

O **SecuraPy** é um SIEM (Security Information and Event Management): lê logs de três fontes
(autenticação, firewall e servidor web), transforma cada linha num **evento padronizado**,
aplica regras de detecção, identifica ataques (brute force, port scan, path traversal, XSS,
reconhecimento) e transmite alertas em tempo real.

No 2º semestre ele virou uma **plataforma**: persistência em MongoDB e MySQL, API REST,
machine learning para priorizar alertas, dashboard web, explicações com LLM e Docker.

---

## Arquitetura

```
securaPy_platform/
├── core/                       # NÚCLEO (Módulo A)
│   ├── coletor.py               # Leitura e normalização dos logs
│   ├── regras.py                # Motor de regras (config/regras.json)
│   ├── detector.py              # Brute force, port scan e blacklist
│   └── correlacao.py            # Bônus: brute force por janela de tempo
├── db/                         # PERSISTÊNCIA (Módulo B)
│   ├── configuracao.py          # Lê o .env
│   ├── mongo_repo.py            # Eventos e alertas no MongoDB
│   └── mysql_repo.py            # Usuários e login no MySQL
├── alertas/                     # TEMPO REAL (Módulo A)
│   ├── servidor_alertas.py      # Servidor TCP com broadcast
│   └── cliente_alertas.py       # Console do analista
├── ferramentas/
│   └── gerador_logs.py          # Gera logs de teste usados pelo ML
├── ml/                         # MACHINE LEARNING (Módulo C — Pessoa 2)
│   ├── __init__.py              # Identifica ml como pacote Python
│   ├── features.py              # Extrai características dos eventos por IP
│   ├── treinar.py               # Treina e avalia o modelo; salva modelo e métricas
│   ├── classificar.py           # Verifica o hash e classifica ameaças
│   ├── test_ml.py               # Testes automatizados do Módulo C
│   ├── requirements.txt         # Dependências específicas do ML
│   ├── metricas.json            # Métricas geradas pelo treinamento
│   ├── modelo.pkl               # Modelo treinado, gerado pelo treinamento
│   └── modelo.sha256            # Hash SHA-256 do modelo salvo
├── api/                        # Módulo D — ainda não incluído
├── web/                        # Módulo E — ainda não incluído
├── ia/                         # Módulo G — ainda não incluído
├── config/
│   └── regras.json              # Regras de detecção
├── logs/                        # auth.log, firewall.log e web_access.log
├── saida/                       # Relatórios gerados
├── analisar.py                  # Executa o fluxo de análise e salva no banco
├── migrar_logs.py               # Migra logs para o MongoDB
├── .env.exemplo                 # Modelo das variáveis de ambiente
├── requirements.txt             # Dependências gerais do projeto
└── README.md
```

**Fluxo de dados:**

```
logs/ → coletor → regras → detector → correlação → MongoDB (eventos + alertas)
                                         │
                                         ├→ servidor TCP → consoles dos analistas
                                         └→ relatório JSON (saida/)
```

---

## Dependências

- Python 3.12 ou superior
- MongoDB (Atlas no desenvolvimento, contêiner no Docker)
- MySQL 8 (contêiner Docker)

```bash
python -m pip install -r requirements.txt
python -m pip install -r ml/requirements.txt
```

---

## Como executar

### 1. Configurar as variáveis de ambiente

Copie o `.env.exemplo` para `.env` e preencha as senhas. O `.env` **não vai para o Git**.

```
MONGO_URI=mongodb+srv://securapy:SENHA_AQUI@siem-gs.bvdimvg.mongodb.net/
MONGO_BANCO=securapy
MYSQL_HOST=localhost
MYSQL_PORTA=3306
MYSQL_USUARIO=root
MYSQL_SENHA=SENHA_AQUI
MYSQL_BANCO=securapy
```

### 2. Subir o MySQL (Docker)

```bash
docker run -d --name securapy-mysql -e MYSQL_ROOT_PASSWORD=SENHA_AQUI -e MYSQL_DATABASE=securapy -p 3306:3306 mysql:8.0
```

### 3. Rodar (sempre a partir da raiz do projeto)

| Comando | O que faz |
|---|---|
| `python analisar.py` | Fluxo completo: coleta, regras, detector, correlação, grava no MongoDB e exporta o relatório |
| `python migrar_logs.py --limpar` | Migra os 3 logs para o MongoDB do zero |
| `python -m alertas.servidor_alertas` | Servidor de alertas (Enter transmite os alertas) |
| `python -m alertas.cliente_alertas` | Console do analista (`/status`, `/historico`, `/sair`) |
| `python -m ferramentas.gerador_logs` | Gera logs de teste em `logs_gerados/` |

### Execução com Docker

PREENCHER — Pessoa 3 (`docker-compose up`).

---

## Divisão de tarefas

### Pessoa 1 — Núcleo e Persistência (Módulos A e B)

**Responsável:** PREENCHER

#### Módulo A — Núcleo

| Arquivo | Responsabilidade |
|---|---|
| `core/coletor.py` | Lê os 3 logs, valida cada linha e normaliza em eventos (`timestamp`, `fonte`, `tipo`, `ip`, `detalhes`, `linha_original`) |
| `core/regras.py` | Carrega `config/regras.json` e aplica 5 regras: usuário privilegiado, porta crítica, path traversal, XSS e reconhecimento |
| `core/detector.py` | Brute force e port scan (dict e set), blacklist por interseção de sets (`&`) e resumo de ameaças por IP |
| `alertas/servidor_alertas.py` | Servidor TCP com uma thread por cliente, `lock` e broadcast dos alertas graves |
| `alertas/cliente_alertas.py` | Console com uma thread recebendo alertas e outra lendo comandos |

| Teste | Esperado | Resultado |
|---|---|---|
| A1 | Lista unificada dos 3 logs | ✅ 58 eventos (23 + 17 + 18) |
| A2 | Brute force do `185.220.101.1` (ALTA) | ✅ ALTA, com 11 falhas (ver Observações) |
| A3 | Port scan do `185.220.101.1` | ✅ 7 portas distintas |
| A4 | Interseção com a blacklist | ✅ 3 IPs (o `23.94.5.100` não aparece nos logs) |

#### Módulo B — Persistência

| Arquivo | Responsabilidade |
|---|---|
| `db/configuracao.py` | Lê as variáveis do `.env`; `esconder_senha()` permite exibir endereços sem vazar a senha |
| `db/mongo_repo.py` | Salva eventos e alertas sem duplicar (upsert por `_id`), busca com filtros (fonte, tipo, IP, período), agregações (top IPs, contagem por severidade) e índices em `ip` e `timestamp` |
| `db/mysql_repo.py` | CRUD de usuários com queries parametrizadas, email único, nível de acesso de 1 a 5 e login seguro |
| `migrar_logs.py` | Lê os logs pelo núcleo e popula o MongoDB |
| `analisar.py` | Integra todo o núcleo, salva eventos e alertas e exporta o relatório JSON |

| Teste | Esperado | Resultado |
|---|---|---|
| B1 | 58 eventos no MongoDB | ✅ |
| B2 | Top 5 IPs com `185.220.101.1` no topo | ✅ 25 eventos |
| B3 | Email duplicado tratado | ✅ `Email já cadastrado.` |
| B4 | SQL Injection `' OR '1'='1` no login | ✅ Bloqueado pela parametrização |

**Segurança aplicada:**
- Queries **parametrizadas** (`%s`) em todo o MySQL; no MongoDB, os filtros viram texto com `str()` (contra NoSQL Injection).
- Senhas com **PBKDF2-SHA256 + salt + 200 mil iterações**; comparação em tempo constante (`hmac.compare_digest`).
- Login com a **mesma resposta** para usuário inexistente e senha errada (anti-enumeração), inclusive no tempo de resposta.
- Segredos no **`.env`**, fora do código e do Git; mensagens de erro mostram só o tipo da exceção, sem vazar endereço ou senha.
- Nenhum `except:` genérico: todas as exceções são específicas.

#### Bônus

| Bônus | Arquivo | Pontos |
|---|---|---|
| Correlação temporal: mais de 5 falhas em 60 segundos | `core/correlacao.py` | +0,20 |

Com janela de 60 s, o `185.220.101.1` é detectado (11 falhas em 39 s, ALTA); com janela de 10 s, ninguém é
detectado, o que comprova que o tempo é considerado.

#### Reaproveitamento do 1º semestre

O núcleo segue o enunciado do SecuraPy do 1º semestre (coletor, regras, detector e servidor TCP),
reorganizado em camadas (`core/`, `alertas/`) e integrado à persistência (`db/`).

---

### Pessoa 2 — Machine Learning (Módulo C)

**Responsável:** Gabriel D

O Módulo C está na pasta `ml/` e complementa a análise do núcleo A/B. Ele transforma eventos em atributos numéricos por IP, treina um classificador, avalia suas métricas e usa o modelo para priorizar ameaças.

| Arquivo | Responsabilidade |
|---|---|
| `ml/features.py` | Monta seis atributos por IP: falhas de autenticação, maior rajada de falhas em 60 segundos, portas bloqueadas distintas, respostas web HTTP 4xx, total de eventos e presença na blacklist. Reaproveita funções de `core.detector`, `core.correlacao` e `core.regras`. |
| `ml/treinar.py` | Gera exemplos com `ferramentas/gerador_logs.py`, usa o gabarito do gerador para rotular os IPs como `ataque` ou `normal`, treina o modelo e calcula as métricas por validação cruzada estratificada. |
| `ml/classificar.py` | Confere o SHA-256 antes de carregar o modelo, classifica ameaças e permite consultar um IP individual com `classificar_ip()`. |
| `ml/test_ml.py` | Testa a extração de atributos, o relatório de métricas, a classificação dos IPs dos cenários C2/C3, a ordenação das ameaças e a rejeição de um modelo com hash incorreto. |
| `ml/requirements.txt` | Lista as dependências do Módulo C. |
| `ml/__init__.py` | Permite importar `ml` como pacote Python. |

O treinamento usa `RandomForestClassifier` dentro de um `Pipeline` com `StandardScaler`. Os dados são gerados com 40 sementes (`0` a `39`) e 50 exemplos de tráfego normal por geração. O gabarito do gerador fornece os rótulos de ataque; assim, o sistema não usa a blacklist para definir esses rótulos.

**Resultado desta execução:** 1.936 amostras, avaliadas em 5 folds.

| Métrica | Resultado |
|---|---:|
| Precisão média | 1,0000 |
| Recall médio | 1,0000 |
| F1 médio | 1,0000 |

Essas métricas foram obtidas com logs sintéticos gerados pelo próprio projeto e não demonstram o mesmo desempenho em logs reais. Os resultados reais dependem dos dados usados e podem ser diferentes.

Depois do treino, `ml/treinar.py` salva `ml/modelo.pkl`, registra o hash SHA-256 em `ml/modelo.sha256` e grava as métricas em `ml/metricas.json`. A classificação verifica o hash antes de carregar o arquivo do modelo. Essa verificação protege o modelo; **não calcula o hash dos arquivos de log**.

Nos cenários de classificação executados, `185.220.101.1` recebeu score `1,0000`, risco **ALTO** e rótulo **ataque**. `192.168.1.10` recebeu score `0,2600`, risco **BAIXO** e rótulo **normal**.

Os testes foram executados com `python -m pytest ml/test_ml.py`: **6 aprovados**. O aviso de depreciação exibido pelo plugin do `pytest` não impediu a execução.

---

### Pessoa 3 — API REST e Docker (Módulos D e F)

**Responsável:** PREENCHER

PREENCHER: rotas da API, autenticação por token, `Dockerfile` e `docker-compose.yml`.
Para a rota `POST /api/analisar`, basta chamar `analisar(pasta_logs)` de `analisar.py`.

---

### Pessoa 4 — Dashboard e LLM (Módulos E e G)

**Responsável:** PREENCHER

PREENCHER: dashboard, headers de segurança, login, `ia/assistente.py`.
Para o login, usar `autenticar(conexao, email, senha)` de `db/mysql_repo.py`.

---

## Formato de dados (contrato entre os módulos)

**Evento:**

```python
{"timestamp": "2025-02-20 08:15:01", "fonte": "auth", "tipo": "FAIL",
 "ip": "185.220.101.1", "detalhes": "usuario=admin",
 "linha_original": "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"}
```

| Fonte | `tipo` | Exemplo de `detalhes` |
|---|---|---|
| auth | OK, FAIL | `usuario=admin` |
| firewall | ALLOW, BLOCK | `proto=TCP dst=10.0.0.1 dport=22` |
| web | REQUEST | `metodo=GET url=/index.html status=200` |

**Alerta:**

```python
{"timestamp": "2025-02-20 08:15:01", "regra": "Brute Force Temporal", "regra_id": "BFT",
 "severidade": "ALTA", "ip": "185.220.101.1", "descricao": "11 falhas em 39s (janela de 60s)"}
```

Severidades: `CRITICA`, `ALTA`, `MEDIA`, `BAIXA`, `INFO`.

---

## Bônus implementados

| Bônus | Pontos | Responsável | Situação |
|---|---|---|---|
| Correlação temporal | +0,20 | Pessoa 1 | ✅ |
| Isolation Forest | +0,30 | Pessoa 2 | PREENCHER |
| Testes automatizados (pytest) | +0,30 | PREENCHER | PREENCHER |
| Autenticação JWT | +0,20 | PREENCHER | PREENCHER |

---

## Observações

- O enunciado indica 10 falhas de login para o IP `185.220.101.1`, mas o `auth.log` fornecido contém
  **11** (08:15:01, :02, :06, :08, :16, :18, :22, :28, :33, :38, :40). O sistema reporta o valor real.
- O MongoDB usa o Atlas durante o desenvolvimento, para o grupo compartilhar os mesmos dados; no Docker,
  basta trocar o `MONGO_URI` no `.env`, sem mudar o código.
