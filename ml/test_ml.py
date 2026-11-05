"""Testes de integração do Módulo C com o núcleo e os artefatos treinados."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.coletor import carregar_todos_os_logs
from db.configuracao import PASTA_LOGS
from ml import classificar
from ml.features import FEATURES, montar_features

PASTA_ML = Path(classificar.__file__).resolve().parent


def test_features_usam_o_contrato_e_os_logs_reais():
    eventos = carregar_todos_os_logs(PASTA_LOGS)
    features_por_ip = montar_features(eventos)

    assert len(eventos) == 58
    assert tuple(FEATURES) == (
        "falhas_auth",
        "maior_rajada_60s",
        "portas_distintas",
        "erros_web_4xx",
        "eventos_total",
        "ip_blacklist",
    )
    assert features_por_ip["185.220.101.1"] == [
        11.0, 11.0, 7.0, 6.0, 25.0, 1.0
    ]


def test_relatorio_c1_foi_salvo_com_metricas_validas():
    caminho = PASTA_ML / "metricas.json"
    relatorio = json.loads(caminho.read_text(encoding="utf-8"))
    metricas = relatorio["validacao_cruzada"]

    assert relatorio["amostras"] > 0
    assert relatorio["amostras_por_classe"]["ataque"] > 0
    assert relatorio["amostras_por_classe"]["normal"] > 0
    assert metricas["folds"] >= 2
    for nome in ("precisao_media", "recall_medio", "f1_medio"):
        assert 0.0 <= metricas[nome] <= 1.0


def test_c2_classifica_ip_de_ataque_como_alto():
    resultado = classificar.classificar_ip("185.220.101.1")

    assert resultado["rotulo_ml"] == "ataque"
    assert resultado["risco_ml"] == "ALTO"
    assert resultado["score_ml"] >= 0.7


def test_c3_classifica_ip_normal():
    resultado = classificar.classificar_ip("192.168.1.10")

    assert resultado["rotulo_ml"] == "normal"


def test_pontuar_ordena_ameacas_por_score():
    ameacas = [
        {"ip": "192.168.1.10", "motivos": [], "severidade": "BAIXA"},
        {"ip": "185.220.101.1", "motivos": ["Brute force"], "severidade": "ALTA"},
    ]

    pontuadas = classificar.pontuar(ameacas)

    assert pontuadas[0]["ip"] == "185.220.101.1"
    assert pontuadas[0]["score_ml"] >= pontuadas[1]["score_ml"]


def test_c4_hash_incorreto_interrompe_antes_de_carregar(tmp_path, monkeypatch):
    modelo_teste = tmp_path / "modelo.pkl"
    hash_teste = tmp_path / "modelo.sha256"
    modelo_teste.write_bytes((PASTA_ML / "modelo.pkl").read_bytes())
    hash_teste.write_text("0" * 64, encoding="ascii")

    def nao_deve_carregar(_caminho):
        pytest.fail("joblib.load não deve rodar quando o hash diverge")

    monkeypatch.setattr("ml.classificar.joblib.load", nao_deve_carregar)
    with pytest.raises(classificar.IntegridadeModeloError):
        classificar.carregar_modelo(modelo_teste)