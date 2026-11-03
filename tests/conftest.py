"""Fixtures compartilhadas dos testes da API: bancos falsos em memória, sem rede."""

import mongomock
import pytest

from api.app import Deps, create_app
from api.auth import emitir_token

SEGREDO = "s" * 40


class ConexaoMysqlFalsa:
    """Marcador no lugar da conexão do MySQL (os testes trocam o autenticar)."""

    def close(self):
        pass


def cabecalho(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def banco():
    return mongomock.MongoClient().securapy


@pytest.fixture
def deps(banco):
    return Deps(
        mongo=lambda: banco,
        mysql=lambda: ConexaoMysqlFalsa(),
        pontuar=lambda ameacas, eventos=None: ameacas,
        classificar_ip=lambda ip, eventos=None: {
            "ip": ip, "score_ml": 0.9, "rotulo_ml": "ataque", "risco_ml": "ALTO"},
        enriquecer=lambda ip: {"pais": "RU", "regiao": "Moscow", "cidade": "Moscow", "org": "AS1"},
    )


@pytest.fixture
def app(deps):
    return create_app({"JWT_SECRET": SEGREDO}, deps)


@pytest.fixture
def cliente(app):
    return app.test_client()


@pytest.fixture
def token_valido():
    return emitir_token("analista@securapy.com", 3, SEGREDO, 60)[0]
