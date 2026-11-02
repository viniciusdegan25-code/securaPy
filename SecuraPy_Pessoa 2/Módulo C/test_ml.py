"""Focused contract tests; these do not claim model quality or use a dataset."""

import hashlib

import pytest

from .features import FEATURES, extrair_features, features_de_ameaca
from .classificar import IntegridadeModeloError, carregar_modelo
from .treinar import sha256_arquivo, treinar


def test_extrai_features_do_contrato_documentado_no_modulo_c():
    eventos = [
        {"timestamp": "2025-02-20 08:15:01", "fonte": "auth", "tipo": "FAIL",
         "ip": "203.0.113.10", "detalhes": "usuario=exemplo"},
        {"timestamp": "2025-02-20 08:15:02", "fonte": "firewall", "tipo": "BLOCK",
         "ip": "203.0.113.10", "detalhes": "dport=443"},
        {"timestamp": "2025-02-20 08:15:03", "fonte": "web", "tipo": "REQUEST",
         "ip": "203.0.113.10", "detalhes": "status=404"},
    ]
    obtidas = extrair_features(eventos, {"203.0.113.10"})["203.0.113.10"]
    assert tuple(obtidas) == FEATURES
    assert obtidas == {
        "falhas_auth": 1.0,
        "portas_distintas": 1.0,
        "ip_blacklist": 1.0,
        "erros_web": 1.0,
        "eventos_total": 3.0,
        "bloqueios_firewall": 1.0,
    }


def test_nao_treina_sem_amostras_rotuladas(tmp_path):
    with pytest.raises(ValueError, match="amostras rotuladas"):
        treinar([], {}, tmp_path / "modelo.pkl")


def test_adapta_formato_de_alerta_temporal_do_modulo_b():
    alerta_b = {
        "timestamp": "2025-02-20 08:15:01",
        "regra": "Brute Force Temporal",
        "severidade": "ALTA",
        "ip": "185.220.101.1",
        "descricao": "12 falhas em 30s (janela de 60s)",
    }
    obtidas = features_de_ameaca(alerta_b)
    assert obtidas["falhas_auth"] == 12.0
    assert obtidas["portas_distintas"] == 0.0
    assert obtidas["eventos_total"] == 0.0


def test_confere_hash_antes_de_carregar_joblib(tmp_path, monkeypatch):
    modelo = tmp_path / "modelo.pkl"
    modelo.write_bytes(b"conteudo de teste")
    (tmp_path / "modelo.pkl.sha256").write_text("0" * 64, encoding="ascii")

    def nao_deve_carregar(_caminho):
        pytest.fail("joblib.load foi chamado antes da verificação do hash")

    monkeypatch.setattr("ml.classificar.joblib.load", nao_deve_carregar)
    with pytest.raises(IntegridadeModeloError):
        carregar_modelo(modelo)


def test_hash_sha256_do_arquivo_e_estavel(tmp_path):
    # Confirma o formato do manifesto gerado pelo treinamento sem declarar
    # métricas nem criar rótulos ou amostras de treinamento.
    conteudo = b"artefato"
    caminho = tmp_path / "artefato.bin"
    caminho.write_bytes(conteudo)
    assert sha256_arquivo(caminho) == hashlib.sha256(conteudo).hexdigest()
