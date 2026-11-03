"""Testes das consultas paginadas do Mongo (db/consultas_api.py), com mongomock."""

import mongomock
import pytest

from db import consultas_api as consultas
from db.mongo_repo import COLECAO_ALERTAS, COLECAO_EVENTOS, id_alerta


def _evento(n, ip="185.220.101.1", fonte="auth", tipo="FAIL"):
    linha = f"linha {n}"
    return {"_id": f"{fonte}|{linha}", "timestamp": f"2025-02-20 08:{n:02d}:00", "fonte": fonte,
            "tipo": tipo, "ip": ip, "detalhes": "usuario=root", "linha_original": linha}


def _alerta(n, severidade, ip="185.220.101.1"):
    alerta = {"timestamp": f"2025-02-20 09:{n:02d}:00", "regra": f"Regra {n}",
              "severidade": severidade, "ip": ip, "descricao": "d"}
    alerta["_id"] = id_alerta(alerta)
    return alerta


@pytest.fixture
def banco():
    db = mongomock.MongoClient().securapy
    db[COLECAO_EVENTOS].insert_many(
        [_evento(n) for n in range(20)] + [_evento(n, ip="10.0.0.5", fonte="web", tipo="GET")
                                           for n in range(20, 25)])
    severidades = ["CRITICA", "CRITICA", "ALTA", "ALTA", "MEDIA", "BAIXA", "INFO"]
    db[COLECAO_ALERTAS].insert_many([_alerta(n, s) for n, s in enumerate(severidades)])
    return db


def test_listar_eventos_pagina_dois(banco):
    resultado = consultas.listar_eventos(banco, pagina=2, tamanho=10)
    assert resultado["total"] == 25
    assert [e["timestamp"][11:16] for e in resultado["itens"]] == [f"08:{n:02d}" for n in range(10, 20)]
    assert all("_id" not in e for e in resultado["itens"])


def test_listar_eventos_filtros_ip_e_periodo(banco):
    assert consultas.listar_eventos(banco, ip="10.0.0.5")["total"] == 5
    periodo = consultas.listar_eventos(banco, inicio="2025-02-20 08:00:00",
                                       fim="2025-02-20 08:04:00")
    assert periodo["total"] == 5


def test_filtro_malicioso_vira_texto_e_nao_retorna_tudo(banco):
    assert consultas.listar_eventos(banco, ip={"$ne": ""})["total"] == 0


def test_listar_alertas_por_severidade_traz_id(banco):
    resultado = consultas.listar_alertas(banco, severidade="CRITICA")
    assert resultado["total"] == 2
    assert all(a["severidade"] == "CRITICA" and a["id"] for a in resultado["itens"])
    assert all("_id" not in a for a in resultado["itens"])


def test_codificar_e_decodificar_id_com_pipe_e_espaco():
    original = "2025-02-20 08:15:00|Regra 1|185.220.101.1"
    assert consultas.decodificar_id(consultas.codificar_id(original)) == original


@pytest.mark.parametrize("invalido", ["***", "////", "_w", ""])
def test_decodificar_id_invalido_levanta_value_error(invalido):
    with pytest.raises(ValueError):
        consultas.decodificar_id(invalido)


def test_buscar_alerta_por_id_existente_e_inexistente(banco):
    alerta = consultas.listar_alertas(banco, severidade="ALTA")["itens"][0]
    achado = consultas.buscar_alerta_por_id(banco, alerta["id"])
    assert achado["regra"] == alerta["regra"] and achado["id"] == alerta["id"]
    assert consultas.buscar_alerta_por_id(banco, consultas.codificar_id("nao|existe|x")) is None


def test_criar_alerta_novo_e_duplicado(banco):
    novo = {"timestamp": "2025-03-01 10:00:00", "regra": "Manual", "ip": "1.2.3.4",
            "severidade": "ALTA", "descricao": "teste"}
    assert consultas.criar_alerta(banco, novo) is True
    assert consultas.criar_alerta(banco, novo) is False
    assert banco[COLECAO_ALERTAS].count_documents({}) == 8


def test_alertas_e_eventos_do_ip(banco):
    eventos, alertas = consultas.alertas_e_eventos_do_ip(banco, "10.0.0.5")
    assert len(eventos) == 5 and alertas == []


def test_banco_none_levanta_banco_indisponivel():
    with pytest.raises(consultas.BancoIndisponivelError):
        consultas.listar_eventos(None)
    with pytest.raises(consultas.BancoIndisponivelError):
        consultas.criar_alerta(None, {})
