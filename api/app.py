"""
api/app.py — Fábrica da aplicação Flask da API REST (Módulo D).

    create_app(config, deps)

'deps' reúne tudo que a API usa de fora (bancos, ML, geolocalização). Em
produção vem de Deps.padrao(); nos testes entram versões falsas em memória.
Execução: gunicorn "api.app:create_app()"  ou  flask --app "api.app:create_app" run
"""

import os
from dataclasses import dataclass
from typing import Callable

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from api.validacao import ValidacaoError
from db.consultas_api import BancoIndisponivelError

TAMANHO_MINIMO_SEGREDO = 32
MAXIMO_CORPO_BYTES = 1024 * 1024
MENSAGENS_HTTP = {
    400: "requisição inválida", 401: "não autorizado", 404: "não encontrado",
    405: "método não permitido", 413: "corpo da requisição muito grande",
    415: "tipo de conteúdo não suportado",
}


@dataclass
class Deps:
    """Dependências externas da API, trocáveis nos testes."""
    mongo: Callable          # () -> banco do Mongo ou None
    mysql: Callable          # () -> conexão do MySQL ou None (quem usa fecha)
    pontuar: Callable        # (ameacas, eventos) -> ameaças com score de ML
    classificar_ip: Callable  # (ip, eventos) -> {"score_ml", "rotulo_ml", "risco_ml", ...}
    enriquecer: Callable     # (ip) -> dict de geolocalização ou None

    @classmethod
    def padrao(cls):
        """Dependências reais. O Mongo é conectado uma vez e reaproveitado."""
        from api import enriquecimento
        from db import mongo_repo, mysql_repo
        from ml import classificar

        banco = {"conexao": None}

        def mongo():
            if banco["conexao"] is None:
                banco["conexao"] = mongo_repo.conectar()
            return banco["conexao"]

        return cls(mongo=mongo, mysql=mysql_repo.conectar, pontuar=classificar.pontuar,
                   classificar_ip=classificar.classificar_ip, enriquecer=enriquecimento.enriquecer)


def _ler_minutos(valor):
    try:
        minutos = int(valor)
    except (TypeError, ValueError):
        return 60
    return minutos if minutos > 0 else 60


def _registrar_tratamento_de_erros(app):
    def resposta(codigo, mensagem):
        retorno = jsonify({"erro": mensagem})
        retorno.status_code = codigo
        return retorno

    @app.errorhandler(ValidacaoError)
    def entrada_invalida(erro):
        return resposta(400, str(erro))

    @app.errorhandler(BancoIndisponivelError)
    def banco_fora(erro):
        app.logger.error("Banco indisponível: %s", erro)
        return resposta(503, "serviço indisponível")

    @app.errorhandler(HTTPException)
    def erro_http(erro):
        return resposta(erro.code, MENSAGENS_HTTP.get(erro.code, "erro na requisição"))

    @app.errorhandler(Exception)
    def erro_inesperado(erro):
        app.logger.exception("Erro inesperado em %s %s", request.method, request.path)
        return resposta(500, "erro interno")   # o traceback fica só no log do servidor


def create_app(config=None, deps=None):
    """Monta a aplicação. Se o JWT_SECRET faltar ou for fraco, a API não inicia."""
    from api.rotas import bp   # import tardio: rotas usa current_app

    app = Flask(__name__)
    app.logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())   # log de acesso (OWASP A09)
    app.config["MAX_CONTENT_LENGTH"] = MAXIMO_CORPO_BYTES
    app.json.ensure_ascii = False   # acentos legíveis nas respostas em português
    app.json.sort_keys = False
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "")
    app.config["JWT_EXPIRA_MINUTOS"] = _ler_minutos(os.environ.get("JWT_EXPIRA_MINUTOS"))
    if config:
        app.config.update(config)

    segredo = app.config["JWT_SECRET"]
    if not isinstance(segredo, str) or len(segredo) < TAMANHO_MINIMO_SEGREDO:
        raise RuntimeError(
            f"JWT_SECRET ausente ou com menos de {TAMANHO_MINIMO_SEGREDO} caracteres.")

    app.config["DEPS"] = deps if deps is not None else Deps.padrao()
    app.register_blueprint(bp)
    _registrar_tratamento_de_erros(app)

    @app.after_request
    def registrar_acesso(resposta):
        # unicode_escape: quebra de linha vinda da URL não pode forjar linhas no log
        caminho = request.path.encode("unicode_escape").decode("ascii")
        app.logger.info("%s %s %s", request.method, caminho, resposta.status_code)
        return resposta

    return app
