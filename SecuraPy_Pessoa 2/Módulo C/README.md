# SecuraPy — Módulo C (`ml/`)

Esta pasta integra-se ao núcleo A/B recebido no ZIP `SecuraPy_SIEM - Módulos A e B.zip` e implementa somente o Módulo C: extração de atributos, treinamento/avaliação, persistência, verificação de integridade e classificação de risco. Os módulos D–G não fazem parte desta entrega.

## Contratos A/B verificados

`securaPy/coletor.py` normaliza cada evento com `timestamp`, `fonte`, `tipo`, `ip`, `detalhes` e `linha_original`. As fontes são `auth`, `firewall` e `web`; os tipos incluem `FAIL` e `OK` (auth), `ALLOW` e `BLOCK` (firewall) e `REQUEST` (web). `detalhes` é texto com pares como `usuario=...`, `dport=...` e `status=...`. O extrator usa esses campos; o tipo HTTP do coletor é `REQUEST`, mas para features web basta a fonte e o status.

`securaPy/correlacao.py` emite alertas com `timestamp`, `regra`, `severidade`, `ip` e `descricao` (por exemplo, descrição contendo a contagem de falhas e a duração). O classificador agora aceita essa estrutura. Passe também os eventos A/B para computar o vetor completo por IP; sem eles, o adaptador recupera apenas a contagem de falhas explícita na descrição e deixa os demais sinais neutros.

## Instalação, teste e treino

Execute os comandos na raiz do repositório, onde o diretório `securaPy/` está disponível:

```powershell
python -m pip install -r ml/requirements.txt
python -m pytest ml/test_ml.py
```

O ZIP A/B recebido traz os logs de exemplo em `securaPy/Logs/`. O coletor lê os arquivos da pasta informada; o treino importa `securaPy.coletor.carregar_todos_os_logs` diretamente:

```powershell
python -m ml.treinar --pasta-logs securaPy/Logs --rotulos-json rotulos.json --modelo ml/modelo.pkl
```

`rotulos.json` deve ser preparado pela equipe a partir de rótulos revisados, no formato `{ "IP": "ataque"|"normal" }`. Este pacote não cria nem presume rótulos. São necessárias ambas as classes, com pelo menos dois IPs rotulados em cada uma para validação cruzada. A saída reporta precisão, recall e F1 médios nos folds realmente executados; não há métricas pré-calculadas ou dataset de treino incluídos.

Também é possível passar diretamente um JSON exportado pelo coletor:

```powershell
python -m ml.treinar --eventos-json eventos.json --rotulos-json rotulos.json --modelo ml/modelo.pkl
```

Para incluir uma blacklist como lista JSON de IPs, acrescente `--blacklist-json blacklist.json`.

## Classificação dos alertas B

```python
from securaPy.coletor import carregar_todos_os_logs
from ml.classificar import carregar_modelo, pontuar
from securaPy.correlacao import detectar_brute_force_temporal

eventos = carregar_todos_os_logs("securaPy/Logs")
alertas = detectar_brute_force_temporal(eventos)
modelo = carregar_modelo("ml/modelo.pkl")
alertas_com_risco = pontuar(alertas, modelo=modelo, eventos=eventos)
```

Cada alerta mantém os campos B e recebe `score_risco` (0–100), `rotulo_ml` (`ataque`/`normal`) e `risco_ml` (`ALTO`/`MEDIO`/`BAIXO`). O score é uma probabilidade estimada para priorização de triagem, não um veredito.

## Features, integridade e limites

O vetor por IP contém falhas de autenticação, portas distintas vistas no firewall, presença na blacklist passada pelo chamador, erros web HTTP 4xx/5xx, total de eventos e bloqueios de firewall. O modelo é um `Pipeline` com `StandardScaler` e `RandomForestClassifier`; precisão, recall e F1 usam `ataque` como classe positiva e validação cruzada estratificada, limitada pela classe menor e a cinco folds.

O treinamento grava `modelo.pkl` e `modelo.pkl.sha256`. `carregar_modelo` compara o SHA-256 antes de chamar `joblib.load`; mantenha o manifesto em canal confiável, pois quem altera ambos pode recalcular o hash. Carregue apenas artefatos `joblib` confiáveis. Não há modelo treinado nesta pasta.

O núcleo B fornece o correlacionador temporal de brute force, não um detector geral que produz os resumos legados previstos no primeiro ZIP do Módulo C. A integração aqui usa o formato B verificado e os eventos originais do coletor. O módulo A/B recebido não inclui exportador de rótulos; a curadoria continua sendo uma entrada necessária da equipe.
