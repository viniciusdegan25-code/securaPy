"""
db/consultas_api.py — Consultas do MongoDB feitas para a API REST (Módulo D).

Complementa o db/mongo_repo.py (que só tem busca com limite) com paginação
com total, busca de alerta por id e criação de alerta. Reaproveita o filtro
anti-NoSQL-injection do mongo_repo: todo valor vira texto com str().

Se o banco estiver fora do ar, todas as funções levantam
BancoIndisponivelError, que a API transforma em resposta 503.
"""

import base64
import re

from pymongo import ASCENDING
from pymongo.errors import PyMongoError

from db.mongo_repo import COLECAO_ALERTAS, COLECAO_EVENTOS, _montar_filtro, id_alerta

ORDEM = [("timestamp", ASCENDING), ("_id", ASCENDING)]   # _id desempata: paginação estável
PADRAO_ID = re.compile(r"^[A-Za-z0-9_-]{1,512}$")


class BancoIndisponivelError(Exception):
    """O MongoDB não respondeu (ou não foi configurado)."""


def _exigir_banco(banco):
    if banco is None:
        raise BancoIndisponivelError("MongoDB indisponível")
    return banco


# --------------------------------------------------------------------
# Identificador público do alerta (o _id do Mongo, em base64url)
# --------------------------------------------------------------------

def codificar_id(id_mongo):
    """Transforma o _id do Mongo ('horário|regra|ip') em texto seguro para URL."""
    return base64.urlsafe_b64encode(id_mongo.encode("utf-8")).decode("ascii").rstrip("=")


def decodificar_id(valor):
    """Desfaz codificar_id. Levanta ValueError se o texto não for um id válido."""
    if not isinstance(valor, str) or not PADRAO_ID.match(valor):
        raise ValueError("id inválido")
    preenchido = valor + "=" * (-len(valor) % 4)
    return base64.urlsafe_b64decode(preenchido).decode("utf-8")


def _alerta_publico(documento):
    """Troca o _id do Mongo pelo campo 'id' (codificado) na resposta."""
    copia = dict(documento)
    copia["id"] = codificar_id(copia.pop("_id"))
    return copia


# --------------------------------------------------------------------
# Listagens paginadas
# --------------------------------------------------------------------

def _paginar(colecao, filtro, pagina, tamanho, projecao):
    """Busca uma página ordenada por horário e conta o total do filtro."""
    try:
        total = colecao.count_documents(filtro)
        cursor = (colecao.find(filtro, projecao).sort(ORDEM)
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        return {"itens": list(cursor), "total": total}
    except PyMongoError as erro:
        raise BancoIndisponivelError(erro.__class__.__name__) from None


def listar_eventos(banco, fonte=None, tipo=None, ip=None, inicio=None, fim=None,
                   pagina=1, tamanho=20):
    """Eventos filtrados e paginados: {"itens": [...], "total": n}."""
    _exigir_banco(banco)
    filtro = _montar_filtro({"fonte": fonte, "tipo": tipo, "ip": ip})
    periodo = _montar_filtro({"$gte": inicio, "$lte": fim})
    if periodo:
        filtro["timestamp"] = periodo
    return _paginar(banco[COLECAO_EVENTOS], filtro, pagina, tamanho, {"_id": 0})


def listar_alertas(banco, severidade=None, ip=None, pagina=1, tamanho=20):
    """Alertas filtrados e paginados; cada item traz o campo 'id'."""
    _exigir_banco(banco)
    filtro = _montar_filtro({"severidade": severidade, "ip": ip})
    resultado = _paginar(banco[COLECAO_ALERTAS], filtro, pagina, tamanho, None)
    resultado["itens"] = [_alerta_publico(item) for item in resultado["itens"]]
    return resultado


def buscar_alerta_por_id(banco, id_codificado):
    """Um alerta pelo id público, ou None. Levanta ValueError se o id for inválido."""
    id_mongo = decodificar_id(id_codificado)
    _exigir_banco(banco)
    try:
        documento = banco[COLECAO_ALERTAS].find_one({"_id": id_mongo})
    except PyMongoError as erro:
        raise BancoIndisponivelError(erro.__class__.__name__) from None
    return _alerta_publico(documento) if documento else None


def criar_alerta(banco, alerta):
    """Grava um alerta. Retorna True se era novo e False se já existia (mesmo _id)."""
    _exigir_banco(banco)
    documento = dict(alerta)
    documento["_id"] = id_alerta(alerta)
    try:
        resultado = banco[COLECAO_ALERTAS].update_one(
            {"_id": documento["_id"]}, {"$setOnInsert": documento}, upsert=True)
    except PyMongoError as erro:
        raise BancoIndisponivelError(erro.__class__.__name__) from None
    return resultado.upserted_id is not None


def alertas_e_eventos_do_ip(banco, ip, limite=200):
    """Eventos e alertas de um IP (até 'limite' de cada). Retorna (eventos, alertas)."""
    _exigir_banco(banco)
    filtro = _montar_filtro({"ip": ip})
    try:
        eventos = list(banco[COLECAO_EVENTOS].find(filtro, {"_id": 0}).sort(ORDEM).limit(limite))
        alertas = list(banco[COLECAO_ALERTAS].find(filtro).sort(ORDEM).limit(limite))
    except PyMongoError as erro:
        raise BancoIndisponivelError(erro.__class__.__name__) from None
    return eventos, [_alerta_publico(alerta) for alerta in alertas]
