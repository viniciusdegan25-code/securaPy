"""
db/mongo_repo.py — Persistência de eventos e alertas no MongoDB (Módulo B).

Coleções do banco:
    eventos  -> eventos normalizados pelo coletor (core/coletor.py)
    alertas  -> alertas gerados por regras, detector e correlação

O endereço do banco vem do .env (MONGO_URI): Atlas no desenvolvimento,
contêiner do Docker na apresentação final. O código é o mesmo nos dois.
"""

from pymongo import ASCENDING, MongoClient, UpdateOne
from pymongo.errors import PyMongoError

from db.configuracao import ler_variavel

COLECAO_EVENTOS = "eventos"
COLECAO_ALERTAS = "alertas"


# --------------------------------------------------------------------
# Conexão e índices
# --------------------------------------------------------------------

def conectar():
    """
    Conecta ao MongoDB usando o MONGO_URI do .env.
    Retorna o banco (database) ou None se não for possível conectar.
    """
    endereco = ler_variavel("MONGO_URI")
    if endereco is None:
        print("[ERRO] MONGO_URI não definido no arquivo .env.")
        return None

    try:
        cliente = MongoClient(endereco, serverSelectionTimeoutMS=8000)
        cliente.admin.command("ping")
    except PyMongoError as erro:
        # Mostra só o tipo do erro: a mensagem completa pode conter o endereço
        print(f"[AVISO] MongoDB indisponível ({erro.__class__.__name__}). "
              "Os dados ficarão só em memória.")
        return None

    nome_banco = ler_variavel("MONGO_BANCO", "securapy")
    print(f"[OK] Conectado ao MongoDB (banco '{nome_banco}').")
    return cliente[nome_banco]


def criar_indices(banco):
    """
    Cria índices para buscas rápidas. Se já existirem, nada acontece.
    eventos: ip e timestamp | alertas: ip e severidade
    """
    if banco is None:
        return False
    try:
        banco[COLECAO_EVENTOS].create_index([("ip", ASCENDING)])
        banco[COLECAO_EVENTOS].create_index([("timestamp", ASCENDING)])
        banco[COLECAO_ALERTAS].create_index([("ip", ASCENDING)])
        banco[COLECAO_ALERTAS].create_index([("severidade", ASCENDING)])
    except PyMongoError as erro:
        print(f"[ERRO] Falha ao criar índices: {erro.__class__.__name__}")
        return False
    return True


# --------------------------------------------------------------------
# Gravação (sem duplicar)
# --------------------------------------------------------------------

def id_evento(evento):
    """Identificador único de um evento: fonte + linha original do log."""
    return f"{evento['fonte']}|{evento['linha_original']}"


def id_alerta(alerta):
    """Identificador único de um alerta: horário + regra + IP."""
    return f"{alerta['timestamp']}|{alerta['regra']}|{alerta['ip']}"


def _salvar_sem_duplicar(colecao, documentos, gerar_id):
    """
    Grava a lista de documentos usando 'upsert': o que já existe
    (mesmo _id) não é gravado de novo. Retorna quantos eram novos.
    Função compartilhada por salvar_eventos e salvar_alertas.
    """
    if colecao is None or len(documentos) == 0:
        return 0

    operacoes = []
    for documento in documentos:
        copia = dict(documento)          # não altera o dicionário original
        copia["_id"] = gerar_id(documento)
        operacoes.append(UpdateOne({"_id": copia["_id"]},
                                   {"$setOnInsert": copia}, upsert=True))
    try:
        resultado = colecao.bulk_write(operacoes)
    except PyMongoError as erro:
        print(f"[ERRO] Falha ao gravar no MongoDB: {erro.__class__.__name__}")
        return 0
    return resultado.upserted_count


def salvar_eventos(banco, eventos):
    """Grava os eventos sem duplicar. Retorna quantos eram novos."""
    if banco is None:
        return 0
    return _salvar_sem_duplicar(banco[COLECAO_EVENTOS], eventos, id_evento)


def salvar_alertas(banco, alertas):
    """Grava os alertas sem duplicar. Retorna quantos eram novos."""
    if banco is None:
        return 0
    return _salvar_sem_duplicar(banco[COLECAO_ALERTAS], alertas, id_alerta)


def apagar_eventos(banco):
    """Apaga TODOS os eventos (usado para refazer a migração do zero)."""
    if banco is None:
        return 0
    try:
        return banco[COLECAO_EVENTOS].delete_many({}).deleted_count
    except PyMongoError as erro:
        print(f"[ERRO] Falha ao apagar eventos: {erro.__class__.__name__}")
        return 0


# --------------------------------------------------------------------
# Buscas com filtros
# --------------------------------------------------------------------

def _montar_filtro(campos):
    """
    Monta o filtro do MongoDB só com os campos preenchidos (não None).
    Converte cada valor para texto com str(): se alguém mandar algo
    como {"$ne": ""} pela API, vira texto comum e não um operador
    (proteção contra NoSQL Injection).
    """
    return {campo: str(valor) for campo, valor in campos.items() if valor is not None}


def _buscar(colecao, filtro, limite):
    """Executa a busca, ordenada por horário, sem o campo _id."""
    try:
        cursor = colecao.find(filtro, {"_id": 0}).sort("timestamp", ASCENDING)
        return list(cursor.limit(int(limite)))
    except PyMongoError as erro:
        print(f"[ERRO] Falha na busca: {erro.__class__.__name__}")
        return []


def buscar_eventos(banco, fonte=None, tipo=None, ip=None,
                   inicio=None, fim=None, limite=100):
    """
    Busca eventos com filtros opcionais (None = sem filtro).
    - inicio/fim: período no formato "AAAA-MM-DD HH:MM:SS"
    """
    if banco is None:
        return []
    filtro = _montar_filtro({"fonte": fonte, "tipo": tipo, "ip": ip})
    periodo = _montar_filtro({"$gte": inicio, "$lte": fim})
    if periodo:
        filtro["timestamp"] = periodo
    return _buscar(banco[COLECAO_EVENTOS], filtro, limite)


def buscar_alertas(banco, severidade=None, ip=None, limite=100):
    """Busca alertas com filtros opcionais por severidade e IP."""
    if banco is None:
        return []
    filtro = _montar_filtro({"severidade": severidade, "ip": ip})
    return _buscar(banco[COLECAO_ALERTAS], filtro, limite)


# --------------------------------------------------------------------
# Agregações (contagens feitas pelo próprio banco)
# --------------------------------------------------------------------

def _contar_por_campo(colecao, campo):
    """Agrupa os documentos pelo campo e conta. Retorna {valor: total}."""
    etapas = [{"$group": {"_id": f"${campo}", "total": {"$sum": 1}}}]
    try:
        return {linha["_id"]: linha["total"] for linha in colecao.aggregate(etapas)}
    except PyMongoError as erro:
        print(f"[ERRO] Falha na agregação: {erro.__class__.__name__}")
        return {}


def contar_eventos_por_fonte(banco):
    """Retorna {"auth": 23, "firewall": 17, "web": 18}."""
    if banco is None:
        return {}
    return _contar_por_campo(banco[COLECAO_EVENTOS], "fonte")


def contar_alertas_por_severidade(banco):
    """Retorna {"CRITICA": n, "ALTA": n, ...}."""
    if banco is None:
        return {}
    return _contar_por_campo(banco[COLECAO_ALERTAS], "severidade")


def top_ips(banco, n=10):
    """
    Retorna os N IPs com mais eventos: [{"ip": ..., "total": ...}, ...].
    Empate: ordem alfabética do IP, para o resultado ser sempre igual.
    """
    if banco is None:
        return []
    etapas = [
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1, "_id": 1}},
        {"$limit": int(n)},
    ]
    try:
        resultado = banco[COLECAO_EVENTOS].aggregate(etapas)
        return [{"ip": linha["_id"], "total": linha["total"]} for linha in resultado]
    except PyMongoError as erro:
        print(f"[ERRO] Falha na agregação: {erro.__class__.__name__}")
        return []


# --------------------------------------------------------------------
# Teste do módulo: python -m db.mongo_repo
# --------------------------------------------------------------------
if __name__ == "__main__":
    banco = conectar()
    if banco is not None:
        print("\nEventos por fonte:", contar_eventos_por_fonte(banco))

        print("\nTop 5 IPs:")
        for posicao, linha in enumerate(top_ips(banco, 5), start=1):
            print(f"  {posicao}. {linha['ip']:<16} {linha['total']:>3} eventos")

        print("\nFalhas de login do 185.220.101.1 entre 08:15:00 e 08:15:20:")
        resultado = buscar_eventos(banco, fonte="auth", tipo="FAIL", ip="185.220.101.1",
                                   inicio="2025-02-20 08:15:00", fim="2025-02-20 08:15:20")
        for evento in resultado:
            print(f"  {evento['timestamp']} | {evento['detalhes']}")