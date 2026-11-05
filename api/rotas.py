"""
api/rotas.py — Rotas da API REST do SecuraPy (Módulo D).

As rotas são finas: validam a entrada (api/validacao.py), chamam as camadas
de baixo (db/, ml/, core/) e devolvem JSON. Erros viram respostas pelo
tratamento central em api/app.py.
"""

from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from api.auth import emitir_token, exige_token
from api.servico import analisar_com_ml
from api.validacao import (ValidacaoError, validar_corpo_alerta, validar_corpo_analise,
                           validar_ip, validar_paginacao, validar_periodo, validar_severidade,
                           validar_texto_utf8)
from core.coletor import carregar_todos_os_logs
from db import consultas_api, mysql_repo
from db.configuracao import PASTA_LOGS
from db.mongo_repo import id_alerta
from ml.classificar import IntegridadeModeloError

bp = Blueprint("api", __name__, url_prefix="/api")


def _deps():
    return current_app.config["DEPS"]


def _filtro_texto(nome):
    """Lê um filtro de texto livre da query string (até 50 caracteres)."""
    valor = request.args.get(nome)
    if valor is not None and len(valor) > 50:
        raise ValidacaoError(f"{nome} inválido")
    return valor


def _filtro_ip():
    valor = request.args.get("ip")
    return None if valor is None else validar_ip(valor)


def _pagina(resultado, pagina, tamanho):
    return jsonify({"itens": resultado["itens"], "total": resultado["total"],
                    "pagina": pagina, "tamanho": tamanho})


def corpo_json():
    """Corpo da requisição já em JSON, ou None se não for JSON válido."""
    return request.get_json(silent=True)


@bp.get("/saude")
def saude():
    return jsonify({"status": "ok"})


@bp.post("/login")
def login():
    corpo = corpo_json()
    if (not isinstance(corpo, dict) or not isinstance(corpo.get("email"), str)
            or not isinstance(corpo.get("senha"), str)):
        raise ValidacaoError("envie email e senha")
    validar_texto_utf8(corpo["email"])
    validar_texto_utf8(corpo["senha"])

    conexao = _deps().mysql()
    if conexao is None:
        raise consultas_api.BancoIndisponivelError("MySQL indisponível")
    try:
        usuario = mysql_repo.autenticar(conexao, corpo["email"], corpo["senha"])
    finally:
        conexao.close()

    if usuario is None:   # mesma resposta para email inexistente e senha errada
        return jsonify({"erro": "credenciais inválidas"}), 401

    token, expira_em = emitir_token(usuario["email"], usuario["nivel_acesso"],
                                    current_app.config["JWT_SECRET"],
                                    current_app.config["JWT_EXPIRA_MINUTOS"])
    return jsonify({"token": token, "expira_em": expira_em})


# --------------------------------------------------------------------
# Leitura
# --------------------------------------------------------------------

@bp.get("/eventos")
def listar_eventos():
    pagina, tamanho = validar_paginacao(request.args)
    resultado = consultas_api.listar_eventos(
        _deps().mongo(), fonte=_filtro_texto("fonte"), tipo=_filtro_texto("tipo"),
        ip=_filtro_ip(), inicio=validar_periodo(request.args.get("inicio")),
        fim=validar_periodo(request.args.get("fim")), pagina=pagina, tamanho=tamanho)
    return _pagina(resultado, pagina, tamanho)


@bp.get("/alertas")
def listar_alertas():
    pagina, tamanho = validar_paginacao(request.args)
    severidade = request.args.get("severidade")
    if severidade is not None:
        severidade = validar_severidade(severidade.upper())
    resultado = consultas_api.listar_alertas(
        _deps().mongo(), severidade=severidade, ip=_filtro_ip(), pagina=pagina, tamanho=tamanho)
    return _pagina(resultado, pagina, tamanho)


@bp.get("/alertas/<id_alerta>")
def obter_alerta(id_alerta):
    try:
        alerta = consultas_api.buscar_alerta_por_id(_deps().mongo(), id_alerta)
    except ValueError:
        raise ValidacaoError("id inválido") from None
    if alerta is None:
        return jsonify({"erro": "não encontrado"}), 404
    return jsonify(alerta)


@bp.get("/ip/<ip>")
def consultar_ip(ip):
    ip = validar_ip(ip)
    eventos, alertas = consultas_api.alertas_e_eventos_do_ip(_deps().mongo(), ip)

    try:
        geo = _deps().enriquecer(ip)
    except Exception:   # a geolocalização é um extra: nunca derruba a consulta
        current_app.logger.warning("Falha ao enriquecer IP", exc_info=True)
        geo = None

    try:
        ml = {**_deps().classificar_ip(ip, eventos), "disponivel": True}
    except (IntegridadeModeloError, FileNotFoundError, ValueError) as erro:
        current_app.logger.warning("ML indisponível: %s", erro.__class__.__name__)
        ml = {"disponivel": False}

    return jsonify({"ip": ip, "eventos": eventos, "alertas": alertas, "geo": geo, "ml": ml})


# --------------------------------------------------------------------
# Escrita (exige token)
# --------------------------------------------------------------------

@bp.post("/alertas")
@exige_token
def criar_alerta():
    alerta = validar_corpo_alerta(corpo_json())
    novo = consultas_api.criar_alerta(_deps().mongo(), alerta)
    resposta = {"id": consultas_api.codificar_id(id_alerta(alerta))}
    if novo:
        return jsonify(resposta), 201
    return jsonify({**resposta, "existente": True}), 200


@bp.post("/analisar")
@exige_token
def analisar():
    pedido = validar_corpo_analise(corpo_json(), Path(PASTA_LOGS))
    if "eventos" in pedido:
        return jsonify(analisar_com_ml(pedido["eventos"], _deps(), eventos_confiaveis=False))
    eventos = carregar_todos_os_logs(str(pedido["pasta"]))
    return jsonify(analisar_com_ml(eventos, _deps()))
