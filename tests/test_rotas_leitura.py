"""Testes das rotas de leitura: eventos, alertas, alerta por id e consulta por IP (D1, D2, D5)."""

import pytest

from db.consultas_api import codificar_id
from db.mongo_repo import COLECAO_ALERTAS, COLECAO_EVENTOS, id_alerta

IP_ATACANTE = "185.220.101.1"


def _alerta(n, severidade, ip=IP_ATACANTE):
    alerta = {"timestamp": f"2025-02-20 09:{n:02d}:00", "regra": f"Regra {n}",
              "severidade": severidade, "ip": ip, "descricao": "d"}
    alerta["_id"] = id_alerta(alerta)
    return alerta


@pytest.fixture(autouse=True)
def dados(banco):
    banco[COLECAO_EVENTOS].insert_many([
        {"_id": f"auth|l{n}", "timestamp": f"2025-02-20 08:{n:02d}:00", "fonte": "auth",
         "tipo": "FAIL", "ip": IP_ATACANTE, "detalhes": "usuario=root", "linha_original": f"l{n}"}
        for n in range(12)])
    banco[COLECAO_ALERTAS].insert_many(
        [_alerta(n, "CRITICA") for n in range(8)] + [_alerta(n + 8, "ALTA") for n in range(3)])


def test_d1_alertas_criticos_paginados(cliente):
    resposta = cliente.get("/api/alertas?severidade=critica&pagina=1&tamanho=5")
    corpo = resposta.get_json()
    assert resposta.status_code == 200
    assert len(corpo["itens"]) == 5 and corpo["total"] == 8
    assert corpo["pagina"] == 1 and corpo["tamanho"] == 5
    assert all(a["severidade"] == "CRITICA" and a["id"] for a in corpo["itens"])


def test_eventos_com_filtros_e_segunda_pagina(cliente):
    corpo = cliente.get(f"/api/eventos?ip={IP_ATACANTE}&fonte=auth&pagina=2&tamanho=10").get_json()
    assert corpo["total"] == 12 and len(corpo["itens"]) == 2


def test_eventos_filtra_por_periodo(cliente):
    corpo = cliente.get("/api/eventos?inicio=2025-02-20 08:00:00&fim=2025-02-20 08:02:00").get_json()
    assert corpo["total"] == 3


def test_filtros_invalidos_devolvem_400(cliente):
    assert cliente.get("/api/eventos?ip=abc").status_code == 400
    assert cliente.get("/api/eventos?inicio=ontem").status_code == 400
    assert cliente.get("/api/alertas?severidade=XYZ").status_code == 400


@pytest.mark.parametrize("consulta", ["pagina=0", "pagina=-1", "tamanho=abc", "tamanho=1000000000"])
@pytest.mark.parametrize("rota", ["/api/eventos", "/api/alertas"])
def test_paginacao_absurda_devolve_400(cliente, rota, consulta):
    resposta = cliente.get(f"{rota}?{consulta}")
    assert resposta.status_code == 400
    assert "erro" in resposta.get_json()


def test_alerta_por_id_existente_inexistente_e_invalido(cliente):
    existente = cliente.get("/api/alertas?severidade=ALTA").get_json()["itens"][0]
    achado = cliente.get(f"/api/alertas/{existente['id']}")
    assert achado.status_code == 200 and achado.get_json()["regra"] == existente["regra"]
    assert cliente.get(f"/api/alertas/{codificar_id('nao|existe|x')}").status_code == 404
    for invalido in ("***", "_w", "a" * 600):
        assert cliente.get(f"/api/alertas/{invalido}").status_code == 400


def test_d2_consulta_por_ip_traz_eventos_alertas_geo_e_score(cliente):
    corpo = cliente.get(f"/api/ip/{IP_ATACANTE}").get_json()
    assert corpo["ip"] == IP_ATACANTE
    assert len(corpo["eventos"]) == 12 and len(corpo["alertas"]) == 11
    assert corpo["geo"]["pais"] == "RU"
    assert corpo["ml"]["score_ml"] == 0.9 and corpo["ml"]["risco_ml"] == "ALTO"


def test_ip_sem_dados_responde_200_com_listas_vazias(cliente):
    corpo = cliente.get("/api/ip/8.8.8.8").get_json()
    assert corpo["eventos"] == [] and corpo["alertas"] == []


@pytest.mark.parametrize("ip", ["abc", "010.0.0.1", "1.1.1.1%20x", "1.2.3", "999.1.1.1"])
def test_d5_ip_malformado_devolve_400_amigavel(cliente, ip):
    resposta = cliente.get(f"/api/ip/{ip}")
    assert resposta.status_code == 400
    assert resposta.get_json() == {"erro": "ip inválido"}


def test_ip_v6_valido_funciona(cliente):
    assert cliente.get("/api/ip/2001:db8::1").status_code == 200


@pytest.mark.parametrize("erro", [FileNotFoundError("x"), ValueError("x")])
def test_ml_indisponivel_nao_derruba_a_rota(cliente, deps, erro):
    def falha(ip, eventos=None):
        raise erro

    deps.classificar_ip = falha
    resposta = cliente.get(f"/api/ip/{IP_ATACANTE}")
    assert resposta.status_code == 200
    assert resposta.get_json()["ml"] == {"disponivel": False}


def test_geolocalizacao_que_falha_vira_geo_nulo(cliente, deps):
    deps.enriquecer = lambda ip: None
    assert cliente.get(f"/api/ip/{IP_ATACANTE}").get_json()["geo"] is None


def test_banco_indisponivel_devolve_503(cliente, deps):
    deps.mongo = lambda: None
    for rota in ("/api/eventos", "/api/alertas", f"/api/ip/{IP_ATACANTE}"):
        assert cliente.get(rota).status_code == 503
