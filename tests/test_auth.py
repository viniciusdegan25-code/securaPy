"""Testes da fábrica da app, do login e da autenticação por JWT."""

import base64
import json
import logging

import jwt
import pytest
from flask import g, jsonify

from api.app import create_app
from api.auth import emitir_token, exige_token
from tests.conftest import SEGREDO, cabecalho

USUARIO = {"id": 1, "nome": "Analista", "email": "analista@securapy.com", "nivel_acesso": 3}


def test_segredo_curto_impede_a_api_de_iniciar(deps):
    with pytest.raises(RuntimeError):
        create_app({"JWT_SECRET": "curto"}, deps)


def test_segredo_ausente_impede_a_api_de_iniciar(deps, monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        create_app({}, deps)


def test_saude_responde_200(cliente):
    resposta = cliente.get("/api/saude")
    assert resposta.status_code == 200
    assert resposta.get_json() == {"status": "ok"}


def test_rota_inexistente_e_metodo_errado_devolvem_json(cliente):
    assert cliente.get("/api/nao-existe").get_json() == {"erro": "não encontrado"}
    assert cliente.post("/api/saude").status_code == 405


def test_login_correto_devolve_token_com_claims(cliente, monkeypatch):
    monkeypatch.setattr("api.rotas.mysql_repo.autenticar", lambda conexao, e, s: USUARIO)
    resposta = cliente.post("/api/login", json={"email": "analista@securapy.com", "senha": "x"})
    assert resposta.status_code == 200
    corpo = resposta.get_json()
    claims = jwt.decode(corpo["token"], SEGREDO, algorithms=["HS256"])
    assert claims["sub"] == "analista@securapy.com" and claims["nivel"] == 3 and "exp" in claims
    assert corpo["expira_em"] == 3600


def test_login_falho_tem_sempre_a_mesma_resposta(cliente, monkeypatch):
    monkeypatch.setattr("api.rotas.mysql_repo.autenticar", lambda conexao, e, s: None)
    a = cliente.post("/api/login", json={"email": "existe@x.com", "senha": "errada"})
    b = cliente.post("/api/login", json={"email": "naoexiste@x.com", "senha": "qualquer"})
    assert a.status_code == b.status_code == 401
    assert a.data == b.data
    assert a.get_json() == {"erro": "credenciais inválidas"}


@pytest.mark.parametrize("corpo", [None, [], "texto", {"email": "a@x.com"}, {"email": "a@x.com", "senha": 1}])
def test_login_com_corpo_invalido_devolve_400(cliente, corpo):
    resposta = cliente.post("/api/login", json=corpo) if corpo is not None else cliente.post("/api/login")
    assert resposta.status_code == 400


def test_login_com_mysql_indisponivel_devolve_503(app, cliente, deps):
    deps.mysql = lambda: None
    resposta = cliente.post("/api/login", json={"email": "a@x.com", "senha": "x"})
    assert resposta.status_code == 503
    assert resposta.get_json() == {"erro": "serviço indisponível"}


@pytest.fixture
def cliente_protegido(app):
    @app.get("/_protegida")
    @exige_token
    def protegida():
        return jsonify({"usuario": g.usuario["sub"]})
    return app.test_client()


def _alg_none():
    def b64(dados):
        return base64.urlsafe_b64encode(json.dumps(dados).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'x', 'exp': 9999999999})}."


@pytest.mark.parametrize("cabecalho_auth", [
    None, "", "Bearer", "Bearer ", "bearer abc.def.ghi", "Basic abc", "Bearer a b", "Bearer a\tb",
    "Bearer " + "x" * 10,
])
def test_cabecalho_authorization_estranho_devolve_401(cliente_protegido, cabecalho_auth):
    cabecalhos = {} if cabecalho_auth is None else {"Authorization": cabecalho_auth}
    resposta = cliente_protegido.get("/_protegida", headers=cabecalhos)
    assert resposta.status_code == 401
    assert resposta.headers["WWW-Authenticate"] == "Bearer"


def test_token_expirado_assinatura_errada_e_alg_none_devolvem_401(cliente_protegido):
    expirado = emitir_token("a@x.com", 1, SEGREDO, -1)[0]
    outra_chave = emitir_token("a@x.com", 1, "outra" * 10, 60)[0]
    for token in (expirado, outra_chave, _alg_none()):
        assert cliente_protegido.get("/_protegida", headers=cabecalho(token)).status_code == 401


def test_token_valido_passa_e_expoe_o_usuario(cliente_protegido, token_valido):
    resposta = cliente_protegido.get("/_protegida", headers=cabecalho(token_valido))
    assert resposta.status_code == 200
    assert resposta.get_json() == {"usuario": "analista@securapy.com"}


def test_erro_inesperado_devolve_500_generico_sem_vazar(app):
    @app.get("/_quebra")
    def quebra():
        raise RuntimeError("segredo-xyz")
    resposta = app.test_client().get("/_quebra")
    assert resposta.status_code == 500
    assert resposta.get_json() == {"erro": "erro interno"}
    assert b"segredo-xyz" not in resposta.data


def test_cada_requisicao_gera_linha_de_log_de_acesso(cliente, caplog):
    with caplog.at_level(logging.INFO):
        cliente.get("/api/saude")
    assert any("GET /api/saude 200" in r.getMessage() for r in caplog.records)
