"""Testes de api/servico.py: núcleo + ML + persistência sobre os logs reais do projeto."""

import pytest

from api.servico import analisar_com_ml
from core.coletor import carregar_todos_os_logs
from db.configuracao import PASTA_LOGS
from ml.classificar import IntegridadeModeloError


@pytest.fixture
def eventos():
    return carregar_todos_os_logs(PASTA_LOGS)


def test_analise_dos_logs_reais_tem_os_totais_esperados(eventos, deps):
    resultado = analisar_com_ml(eventos, deps, persistir=lambda ev, al: {"banco_disponivel": True})
    assert resultado["total_eventos"] == 58
    assert resultado["eventos_por_fonte"] == {"auth": 23, "firewall": 17, "web": 18}
    assert resultado["ameacas"][0]["ip"] == "185.220.101.1"
    assert resultado["ml_disponivel"] is True
    assert resultado["total_alertas"] == len(resultado["alertas"]) > 0


def test_ameacas_saem_pontuadas_pelo_ml(eventos, deps):
    deps.pontuar = lambda ameacas, evs=None: [{**a, "score_ml": 0.5} for a in ameacas]
    resultado = analisar_com_ml(eventos, deps, persistir=lambda ev, al: {})
    assert all(a["score_ml"] == 0.5 for a in resultado["ameacas"])


@pytest.mark.parametrize("erro", [IntegridadeModeloError("hash"), FileNotFoundError("x"), ValueError("x")])
def test_falha_do_ml_nao_impede_a_analise(eventos, deps, erro):
    def quebra(ameacas, evs=None):
        raise erro

    deps.pontuar = quebra
    resultado = analisar_com_ml(eventos, deps, persistir=lambda ev, al: {})
    assert resultado["ml_disponivel"] is False
    assert resultado["total_eventos"] == 58 and resultado["ameacas"]
    assert not any("score_ml" in a for a in resultado["ameacas"])


def test_persistir_e_chamado_uma_vez_com_eventos_e_alertas(eventos, deps):
    chamadas = []

    def gravar(evs, alertas):
        chamadas.append((len(evs), len(alertas)))
        return {"banco_disponivel": True, "eventos_novos": 1, "alertas_novos": 1}

    resultado = analisar_com_ml(eventos, deps, persistir=gravar)
    assert chamadas == [(58, resultado["total_alertas"])]
    assert resultado["persistencia"]["eventos_novos"] == 1


def test_persistencia_padrao_grava_no_banco_das_dependencias(eventos, deps, banco):
    resultado = analisar_com_ml(eventos, deps)
    assert resultado["persistencia"]["banco_disponivel"] is True
    assert banco["eventos"].count_documents({}) == 58
    assert analisar_com_ml(eventos, deps)["persistencia"]["eventos_novos"] == 0   # sem duplicar


def test_sem_banco_a_analise_continua_e_avisa(eventos, deps):
    deps.mongo = lambda: None
    resultado = analisar_com_ml(eventos, deps)
    assert resultado["persistencia"] == {"banco_disponivel": False, "eventos_novos": 0,
                                         "alertas_novos": 0}


def test_lista_vazia_devolve_tudo_zerado(deps):
    resultado = analisar_com_ml([], deps, persistir=lambda ev, al: {})
    assert resultado["total_eventos"] == 0 and resultado["total_alertas"] == 0
