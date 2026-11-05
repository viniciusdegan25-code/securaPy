# SecuraPy Platform

> Trabalho Final (Global Solution) — Coding for Security · 2º semestre
> CyberShield Ltda. · Evolução do SIEM SecuraPy para uma plataforma de segurança

<!-- Os RMs marcados com PREENCHER devem ser completados por cada integrante. -->

---

## Integrantes

| Nome | RM | Responsabilidade | Módulos |
|---|---|---|---|
| Vinicius Degan Silva | 569279 | Núcleo + Persistência | A, B |
| Gabriel D | PREENCHER | Machine Learning | C |
| Lino | PREENCHER | API REST + Docker | D, F |
| Samuel Gonçalves | PREENCHER | Web + LLM | E, G |

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
│   ├── mysql_repo.py            # Usuários e login no MySQL
│   └── consultas_api.py         # Consultas paginadas do MongoDB para a API (Módulo D)
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
│   ├── anomalias.py             # Bônus: Isolation Forest (aprende só o tráfego normal)
│   ├── metricas.json            # Métricas geradas pelo treinamento
│   ├── modelo.pkl               # Modelo treinado, gerado pelo treinamento
│   └── modelo.sha256            # Hash SHA-256 do modelo salvo
├── api/                        # API REST (Módulo D — Pessoa 3)
│   ├── app.py                   # Fábrica create_app(): configuração, tratamento de erros, log de acesso
│   ├── rotas.py                 # Rotas /api/* (eventos, alertas, ip, analisar, login, saude)
│   ├── auth.py                  # Login e token JWT (HS256) com decorator @exige_token
│   ├── validacao.py             # Validação de toda entrada (IP, paginação, corpos do POST)
│   ├── servico.py               # Análise completa: núcleo + ML + banco
│   └── enriquecimento.py        # Geolocalização por IP (ipinfo.io) com cache
├── web/                        # DASHBOARD (Módulo E — Pessoa 4)
│   ├── app.py                   # Flask: login, CSRF, headers de segurança, log de acesso
│   ├── templates/               # login, visão geral, investigação de IP e erro (Jinja2 com escape)
│   └── static/style.css         # Estilo (arquivo local: a CSP bloqueia recursos externos)
├── ia/                         # LLM (Módulo G — Pessoa 4)
│   └── assistente.py            # Classifica NORMAL/SUSPEITO/CRITICO com fallback por regras
├── config/
│   └── regras.json              # Regras de detecção
├── logs/                        # auth.log, firewall.log e web_access.log
├── saida/                       # Relatórios gerados
├── scripts/                     # Apoio ao Docker (Módulo F — Pessoa 3)
│   ├── verificar_docker.py      # Confere com o SDK do Docker se api, mongo e mysql estão "running"
│   └── criar_operador.py        # Cria o primeiro operador no MySQL (senha pedida no terminal)
├── tests/                       # Testes automatizados (pytest) de todos os módulos
├── Dockerfile                   # Imagem da API (Python 3.12, gunicorn, usuário sem root)
├── docker-compose.yml           # API + dashboard + MongoDB + MySQL na mesma rede
├── analisar.py                  # Executa o fluxo de análise e salva no banco
├── migrar_logs.py               # Migra logs para o MongoDB
├── .env.exemplo                 # Modelo das variáveis de ambiente
├── requirements.txt             # Dependências do projeto (e da imagem Docker)
├── requirements-dev.txt         # Dependências só para testes (pytest, mongomock)
└── README.md
```

**Fluxo de dados:**

```
logs/ → coletor → regras → detector → correlação → ML (score + anomalias) → MongoDB (eventos + alertas)
                                                                               │
          API REST (/api/*) ←──────────────────────────────────────────────────┤
          Dashboard web (login → visão geral → IP com geo + score + LLM) ←─────┤
          Servidor TCP de alertas → consoles dos analistas                     │
          Relatório JSON (saida/) ←────────────────────────────────────────────┘
```

---

## Dependências

- Python 3.12 ou superior
- MongoDB (Atlas no desenvolvimento, contêiner no Docker)
- MySQL 8 (contêiner Docker)

- Docker e Docker Compose (para o Módulo F)

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt   # só para rodar os testes
```

O `scikit-learn` está fixado em `1.9.0`, a mesma versão que treinou o `ml/modelo.pkl`.

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
JWT_SECRET=               # mínimo 32 caracteres; gere com o comando abaixo
JWT_EXPIRA_MINUTOS=60
FLASK_SECRET_KEY=         # chave da sessão do dashboard
OPENAI_API_KEY=           # opcional: sem ela o assistente usa o fallback por regras
OPENAI_MODEL=gpt-4o-mini
MYSQL_ROOT_PASSWORD=      # usado só pelo Docker Compose
```

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"   # gera o JWT_SECRET
python -c "import secrets; print(secrets.token_hex(32))"       # gera o FLASK_SECRET_KEY
```

### 2. Subir o MySQL (Docker)

```bash
docker run -d --name securapy-mysql -e MYSQL_ROOT_PASSWORD=SENHA_AQUI -e MYSQL_DATABASE=securapy -p 3306:3306 mysql:8.0
```

### 3. Rodar (sempre a partir da raiz do projeto)

| Comando | O que faz |
|---|---|
| `python analisar.py` | Fluxo completo: coleta, regras, detector, correlação, score do ML, anomalias, grava no MongoDB e exporta o relatório |
| `python migrar_logs.py --limpar` | Migra os 3 logs para o MongoDB do zero |
| `python -m alertas.servidor_alertas` | Servidor de alertas (Enter transmite os alertas) |
| `python -m alertas.cliente_alertas` | Console do analista (`/status`, `/historico`, `/sair`) |
| `python -m ferramentas.gerador_logs` | Gera logs de teste em `logs_gerados/` |
| `python -m scripts.criar_operador --nome "Analista SOC" --email analista@securapy.com` | Cria o operador que entra no dashboard e na API |
| `python -m web.app` | Dashboard em http://127.0.0.1:5000 |
| `flask --app "api.app:create_app" run --port 8000` | API REST em http://127.0.0.1:8000 |
| `python -m ml.treinar` / `python -m ml.classificar` | Treina o modelo (C1) / classifica os IPs dos cenários C2 e C3 |
| `python -m ml.anomalias` | Bônus: Isolation Forest sobre os logs de teste |
| `python -m ia.assistente` | Demonstra os cenários G1 a G4 do assistente |
| `python -m pytest` | Roda todos os testes automatizados |

### Execução com Docker

Com o `.env` preenchido (`JWT_SECRET` e `MYSQL_ROOT_PASSWORD` são obrigatórios; sem eles o Compose avisa e não sobe):

Com o `.env` preenchido (`JWT_SECRET`, `FLASK_SECRET_KEY` e `MYSQL_ROOT_PASSWORD` são obrigatórios; sem eles o Compose avisa e não sobe):

```bash
docker compose up --build            # sobe api (8000), web (5000), mongo e mysql
python -m scripts.verificar_docker   # F2: lista api, web, mongo e mysql como "running"
curl http://localhost:8000/api/saude # F3: {"status":"ok"}
docker compose exec api python -m scripts.criar_operador --nome "Analista SOC" --email analista@securapy.com
docker compose down                  # para tudo (os dados ficam nos volumes)
```

**Teste ponta a ponta (roteiro do vídeo):**

1. `docker compose up --build` e `python -m scripts.verificar_docker`.
2. Criar o operador (comando acima) e pedir um token: `POST /api/login`.
3. Analisar os logs pela API (o MongoDB do contêiner começa vazio e é populado aqui):
   `curl -X POST localhost:8000/api/analisar -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"pasta":"."}'`
4. Abrir http://localhost:5000, entrar, ver o resumo e buscar `185.220.101.1`: eventos, alertas,
   geolocalização, score do ML e "Consultar assistente".
5. Em outro terminal: `python -m alertas.servidor_alertas` e dois `python -m alertas.cliente_alertas`
   para os alertas em tempo real.

Dentro do Compose a API e o dashboard usam o MongoDB e o MySQL dos contêineres (as variáveis do serviço têm
prioridade sobre o `.env`, então o Atlas do desenvolvimento não é tocado). Só as portas `8000` (API) e `5000`
(dashboard) são publicadas no computador; os bancos ficam acessíveis somente pela rede interna `securapy-net`.

---

## Divisão de tarefas

### Pessoa 1 — Núcleo e Persistência (Módulos A e B)

**Responsável:** Vinicius Degan Silva

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
| `analisar.py` | Integra todo o núcleo, pontua as ameaças com o ML, marca anomalias, salva eventos e alertas e exporta o relatório JSON |

| Teste | Esperado | Resultado |
|---|---|---|
| B1 | 58 eventos no MongoDB | ✅ |
| B2 | Top 5 IPs com `185.220.101.1` no topo | ✅ 25 eventos |
| B3 | Email duplicado tratado | ✅ `Email já cadastrado.` |
| B4 | SQL Injection `' OR '1'='1` no login | ✅ Bloqueado pela parametrização |

Testes automatizados: `tests/test_nucleo.py` (A1 a A4, regras, correlação e logs inexistentes ou malformados)
e `tests/test_persistencia.py` (B1 a B4, filtros, NoSQL Injection, banco fora do ar e validação do cadastro).

**Segurança aplicada:**
- Queries **parametrizadas** (`%s`) em todo o MySQL; no MongoDB, os filtros viram texto com `str()` (contra NoSQL Injection).
- Senhas com **PBKDF2-SHA256 + salt + 200 mil iterações**; comparação em tempo constante (`hmac.compare_digest`).
- Login com a **mesma resposta** para usuário inexistente e senha errada (anti-enumeração), inclusive no tempo de resposta.
- Segredos no **`.env`**, fora do código e do Git; mensagens de erro mostram só o tipo da exceção, sem vazar endereço ou senha.
- Nenhum `except:` genérico: todas as exceções são específicas.
- O `MongoClient` é criado **uma vez** e reaproveitado (pool de conexões), em vez de abrir um cliente novo a cada chamada.

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
| `ml/anomalias.py` | **Bônus:** Isolation Forest treinado só com tráfego normal; marca como anomalia o IP que foge desse padrão. |
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

**Bônus — Isolation Forest (`python -m ml.anomalias`):** o detector aprende só o tráfego normal gerado pelo
`gerador_logs.py` (20 sementes, numa pasta temporária) e, nos logs de teste, marca exatamente os 3 IPs
maliciosos (`185.220.101.1`, `91.240.118.172` e `45.33.32.156`) sem marcar nenhum IP interno.
O resultado também entra no relatório do `analisar.py` (campo `anomalias`). Teste: `tests/test_anomalias.py`.

---

### Pessoa 3 — API REST e Docker (Módulos D e F)

**Responsável:** Lino

#### Módulo D — API REST (Flask)

A API é a porta de entrada da plataforma: dashboards e automações consultam os dados por aqui, sem tocar
nos bancos. Ela reaproveita o núcleo, o ML e a persistência sem alterá-los.

| Rota | Auth | O que faz |
|---|---|---|
| `GET /api/saude` | não | Responde `{"status":"ok"}` (usada no healthcheck do Docker) |
| `POST /api/login` | não | Confere email e senha no MySQL e devolve um JWT com validade (padrão 60 min) |
| `GET /api/eventos` | não | Eventos com filtros `fonte`, `tipo`, `ip`, `inicio`, `fim` e paginação (`pagina`, `tamanho` de 1 a 100) |
| `GET /api/alertas` | não | Alertas com filtros `severidade` e `ip` e a mesma paginação |
| `GET /api/alertas/<id>` | não | Um alerta pelo `id` devolvido na listagem |
| `POST /api/alertas` | **Bearer** | Cria um alerta (201); se já existir, responde 200 com `"existente": true` |
| `POST /api/analisar` | **Bearer** | Analisa `{"pasta": "<subpasta de logs/>"}` ou `{"eventos": [...]}` (até 5000), pontua com o ML, grava no MongoDB e devolve o resumo |
| `GET /api/ip/<ip>` | não | Eventos, alertas, geolocalização e score de ML do IP |

```bash
# 1. login (devolve {"token": "...", "expira_em": 3600})
curl -X POST localhost:8000/api/login -H "Content-Type: application/json" \
     -d '{"email":"analista@securapy.com","senha":"..."}'

# 2. rota protegida
curl -X POST localhost:8000/api/analisar -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" -d '{"pasta":"."}'

# 3. consulta com filtro e paginação
curl "localhost:8000/api/alertas?severidade=critica&pagina=1&tamanho=5"
curl localhost:8000/api/ip/185.220.101.1
```

**Respostas de erro** (sempre `{"erro": "..."}`): `400` entrada inválida, `401` sem token válido ou
credenciais erradas, `404` não encontrado, `413` corpo maior que 1 MB, `503` banco indisponível e
`500` genérico (o traceback fica só no log do servidor).

**Segurança aplicada:**
- **JWT** HS256 com algoritmo fixo na validação (recusa `alg: none`), expiração curta e `JWT_SECRET` obrigatório
  com pelo menos 32 caracteres (senão a API nem inicia).
- Login com **a mesma resposta** para usuário inexistente e senha errada.
- **Validação de toda entrada** (`api/validacao.py`): IP com o módulo `ipaddress`, severidade e datas em lista
  fechada, paginação limitada, corpos que não são objeto JSON viram 400 e campos extras são descartados.
- `POST /api/analisar` só aceita pastas **dentro de `logs/`** (bloqueia path traversal) e nunca devolve caminhos do servidor.
- Filtros do MongoDB viram texto com `str()` (contra NoSQL Injection), reaproveitando o `db/mongo_repo.py`.
- Erros internos **não vazam** traceback, query, caminho nem segredo.
- Geolocalização com timeout de 3 s, cache de 1 h e sem consultar IP privado; se falhar, `geo` vem `null`.
- Cada requisição gera uma linha de log de acesso (OWASP A09).

#### Módulo F — Docker

| Arquivo | Responsabilidade |
|---|---|
| `Dockerfile` | Imagem `python:3.12-slim`, instala o `requirements.txt` antes do código (cache), roda com usuário sem root, `HEALTHCHECK` em `/api/saude` e gunicorn |
| `docker-compose.yml` | Serviços `api`, `mongo` (7) e `mysql` (8.0) na rede `securapy-net`, com healthchecks; a API só sobe quando os bancos estão saudáveis; volumes para os dados; segredos só do `.env` |
| `scripts/verificar_docker.py` | Usa o SDK `docker` para listar os contêineres do projeto e sair com código ≠ 0 se algum não estiver `running` |
| `scripts/criar_operador.py` | Cria o operador no MySQL; a senha é pedida no terminal ou vem de `OPERADOR_SENHA`, nunca da linha de comando |

| Teste | Esperado | Resultado |
|---|---|---|
| D1 | `GET /api/alertas?severidade=critica&pagina=1&tamanho=5` devolve alertas críticos paginados | ✅ `tests/test_rotas_leitura.py` |
| D2 | `GET /api/ip/185.220.101.1` traz eventos, alertas, geolocalização e score | ✅ `tests/test_rotas_leitura.py` |
| D3 | `POST /api/alertas` sem token devolve 401 | ✅ `tests/test_rotas_escrita.py` |
| D4 | `POST /api/alertas` com corpo inválido devolve 400 | ✅ `tests/test_rotas_escrita.py` |
| D5 | `GET /api/ip/<malformado>` devolve 400 amigável | ✅ `tests/test_rotas_leitura.py` |
| F1 | `docker compose up` sobe os serviços (api, web, mongo e mysql) | PREENCHER: conferir na máquina com Docker |
| F2 | `python -m scripts.verificar_docker` lista todos como `running` | PREENCHER: conferir na máquina com Docker |
| F3 | `GET /api/saude` dentro do Compose responde 200 | PREENCHER: conferir na máquina com Docker |

Os testes da API rodam sem Mongo, MySQL nem internet (bancos em memória): `python -m pytest`.

#### Reaproveitamento do 1º semestre e dos outros módulos

- `api/servico.py` usa `analisar.executar_nucleo()` (regras, detector e correlação) e `core.coletor`; o fluxo
  repete a ordem de `analisar.analisar()` porque precisa pontuar com o ML e gravar no banco já conectado da
  API, sem escrever relatório em disco. Dá para unificar depois.
- Login: `db.mysql_repo.autenticar()`. Score: `ml.classificar.pontuar()` e `classificar_ip()`.
- Consultas: `db.mongo_repo` (filtro anti-NoSQL-injection e `salvar_*`); a paginação fica em `db/consultas_api.py`.

---

### Pessoa 4 — Dashboard e LLM (Módulos E e G)

**Responsável:** Samuel Gonçalves

#### Módulo E — Dashboard e segurança web

| Rota | O que faz |
|---|---|
| `GET /login`, `POST /login` | Login do operador (MySQL, `mysql_repo.autenticar`) |
| `POST /logout` | Encerra a sessão |
| `GET /` | Visão geral: eventos por fonte, alertas por severidade, top 10 IPs, alertas recentes e busca por IP |
| `GET /ip/<ip>` | Investigação: score do ML, geolocalização, alertas com triagem e eventos do IP |
| `POST /ip/<ip>/assistente` | Explicação do alerta pelo assistente LLM |

**Segurança aplicada:**
- **XSS:** todo dado passa pelo escape automático do Jinja2; nenhum `|safe` nos templates.
- **Headers** em todas as respostas: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`
  (só recursos do próprio site), `Referrer-Policy` e `Cache-Control: no-store`.
- **Login endurecido:** mesma mensagem 401 para usuário inexistente e senha errada, senha só como hash PBKDF2,
  nova sessão após o login, bloqueio por 5 minutos depois de 5 falhas do mesmo IP (429) e redirecionamento
  só para caminhos internos.
- **CSRF:** todo `POST` exige um token secreto da sessão; cookie `HttpOnly` e `SameSite=Lax`.
- **Logging (OWASP A09):** uma linha por requisição (IP, método, caminho, status), além de login ok/falho;
  quebras de linha são escapadas para ninguém forjar linhas no log.
- Páginas de erro genéricas (400, 404, 429, 500, 503): nunca mostram traceback, query ou segredo.

| Teste | Esperado | Resultado |
|---|---|---|
| E1 | Alerta com `<script>alert(1)</script>` aparece como texto | ✅ `tests/test_web.py` |
| E2 | Os 3 headers de segurança presentes | ✅ `tests/test_web.py` (inclusive no 404) |
| E3 | Senha errada e usuário inexistente: mesma mensagem 401 | ✅ `tests/test_web.py` |
| E4 | Cada requisição gera uma linha de log | ✅ `tests/test_web.py` |

#### Módulo G — Assistente com LLM (`ia/assistente.py`)

- Recebe um evento ou alerta e devolve `NORMAL`, `SUSPEITO` ou `CRITICO` com uma explicação curta.
- **Boas práticas:** chave em `OPENAI_API_KEY` (variável de ambiente), `temperature=0.1`, timeout de 10 s e
  **nenhum dado sensível enviado**: só campos categóricos (fonte, tipo, regra, severidade), nunca IP, usuário
  ou a linha original do log.
- **Robustez:** a resposta precisa ser JSON com um rótulo da lista fixa; qualquer erro de rede, de chave ou
  de formato cai no **fallback por regras**, que funciona sem internet.
- **Prompt injection:** o conteúdo do log é tratado como dado; frases que tentam dar ordens ao modelo
  ("ignore as instruções", "classifique como...") viram `SUSPEITO`, e o LLM **nunca pode rebaixar** a
  classificação das regras. A saída é só informativa: não dispara nenhuma ação automática.

| Teste | Esperado | Resultado |
|---|---|---|
| G1 | `GET /../../etc/passwd` | ✅ CRITICO (path traversal) com explicação |
| G2 | Acesso interno normal | ✅ NORMAL |
| G3 | Sem API key | ✅ Usa o fallback por regras, não quebra |
| G4 | Entrada com prompt injection | ✅ SUSPEITO; mesmo se o LLM responder NORMAL, a saída validada não aceita |

Testes: `tests/test_assistente.py`. Demonstração: `python -m ia.assistente`.

---

## Testes automatizados

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

Rodam sem MongoDB, MySQL, Docker nem internet (bancos em memória e conexões falsas). Resultado: **234 testes aprovados**.

| Arquivo | Módulo | Cobre |
|---|---|---|
| `tests/test_nucleo.py` | A | A1 a A4, regras, correlação temporal, log inexistente e malformado |
| `tests/test_persistencia.py` | B | B1 a B4, filtros, agregações, NoSQL Injection, banco fora do ar |
| `ml/test_ml.py`, `tests/test_anomalias.py` | C | C2 a C4, métricas, hash do modelo, Isolation Forest |
| `tests/test_rotas_*.py`, `test_auth.py`, `test_validacao.py`, ... | D, F | D1 a D5, JWT, validação, geolocalização, scripts do Docker |
| `tests/test_web.py` | E | E1 a E4, CSRF, sessão, bloqueio de login, banco fora do ar |
| `tests/test_assistente.py` | G | G1 a G4, resposta inválida e falha de rede do LLM |

---

## Reaproveitamento do 1º semestre

O núcleo do SecuraPy CLI (coletor, motor de regras com `regras.json`, detector de brute force, port scan e
blacklist com dict e set, e o servidor TCP de alertas) foi mantido com o mesmo comportamento e reorganizado
em camadas (`core/` e `alertas/`). As camadas novas apenas **chamam** essas funções: `analisar.executar_nucleo()`
é usado pelo `analisar.py`, pela API e pelo ML, e o `hashlib` do 1º semestre virou a verificação de
integridade do modelo.

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
| Isolation Forest | +0,30 | Pessoa 2 | ✅ `ml/anomalias.py` |
| Testes automatizados (pytest) | +0,30 | Todos (`tests/` e `ml/test_ml.py`) | ✅ 234 testes |
| Autenticação JWT | +0,20 | Pessoa 3 | ✅ `api/auth.py` |

---

## Observações

- O enunciado indica 10 falhas de login para o IP `185.220.101.1`, mas o `auth.log` fornecido contém
  **11** (08:15:01, :02, :06, :08, :16, :18, :22, :28, :33, :38, :40). O sistema reporta o valor real.
- No Docker Compose o MongoDB roda **sem autenticação**, apenas na rede interna e sem porta publicada;
  é suficiente para a demonstração, mas um ambiente real deveria ativar usuário e senha.
- O cache de geolocalização é por processo: com 2 workers do gunicorn existem 2 caches.
- `GET /api/ip/<ip>` envia ao ML no máximo os 200 primeiros eventos do IP, então o score pode ser
  subestimado para IPs com mais eventos que isso.
- O dashboard (`web/`) e a API usam a mesma imagem Docker; no Compose são dois serviços (`web` e `api`).
- O bloqueio de login do dashboard é guardado em memória, por processo (cada worker do gunicorn conta à parte).
- O MongoDB usa o Atlas durante o desenvolvimento, para o grupo compartilhar os mesmos dados; no Docker,
  basta trocar o `MONGO_URI` no `.env`, sem mudar o código.
