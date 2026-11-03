"""
api/rotas.py — Rotas da API REST do SecuraPy (Módulo D).

As rotas são finas: validam a entrada (api/validacao.py), chamam as camadas
de baixo (db/, ml/, core/) e devolvem JSON. Erros viram respostas pelo
tratamento central em api/app.py.
"""

from flask import Blueprint, current_app, jsonify, request

from api.auth import emitir_token
from api.validacao import ValidacaoError
from db import consultas_api, mysql_repo

bp = Blueprint("api", __name__, url_prefix="/api")


def _deps():
    return current_app.config["DEPS"]


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
