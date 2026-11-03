"""Testes da geolocalização (api/enriquecimento.py), sem acessar a internet."""

import pytest
import requests

from api import enriquecimento


class RespostaFalsa:
    def __init__(self, status=200, dados=None):
        self.status_code = status
        self._dados = dados if dados is not None else {}

    def json(self):
        return self._dados


DADOS = {"ip": "185.220.101.1", "country": "DE", "region": "Brandenburg",
         "city": "Brandenburg", "org": "AS60729 Zwiebelfreunde", "hostname": "x", "readme": "y"}


@pytest.fixture(autouse=True)
def cache_limpo():
    enriquecimento.limpar_cache()


def test_ip_publico_devolve_so_os_campos_esperados(monkeypatch):
    monkeypatch.setattr(enriquecimento.requests, "get", lambda *a, **k: RespostaFalsa(200, DADOS))
    assert enriquecimento.enriquecer("185.220.101.1") == {
        "pais": "DE", "regiao": "Brandenburg", "cidade": "Brandenburg",
        "org": "AS60729 Zwiebelfreunde"}


def test_segunda_consulta_do_mesmo_ip_usa_o_cache(monkeypatch):
    chamadas = []

    def falso(*args, **kwargs):
        chamadas.append(args)
        return RespostaFalsa(200, DADOS)

    monkeypatch.setattr(enriquecimento.requests, "get", falso)
    enriquecimento.enriquecer("185.220.101.1")
    enriquecimento.enriquecer("185.220.101.1")
    assert len(chamadas) == 1


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.10", "127.0.0.1", "169.254.1.1", "::1"])
def test_ip_privado_ou_reservado_nao_sai_para_a_internet(monkeypatch, ip):
    def proibido(*args, **kwargs):
        raise AssertionError("não deveria consultar")

    monkeypatch.setattr(enriquecimento.requests, "get", proibido)
    assert enriquecimento.enriquecer(ip) is None


def test_timeout_e_erro_de_rede_viram_none(monkeypatch):
    def falha(*args, **kwargs):
        raise requests.Timeout("lento")

    monkeypatch.setattr(enriquecimento.requests, "get", falha)
    assert enriquecimento.enriquecer("8.8.8.8") is None


def test_status_diferente_de_200_e_json_estranho_viram_none(monkeypatch):
    monkeypatch.setattr(enriquecimento.requests, "get", lambda *a, **k: RespostaFalsa(429))
    assert enriquecimento.enriquecer("8.8.8.8") is None
    enriquecimento.limpar_cache()
    monkeypatch.setattr(enriquecimento.requests, "get", lambda *a, **k: RespostaFalsa(200, ["x"]))
    assert enriquecimento.enriquecer("8.8.4.4") is None


def test_falha_nao_e_guardada_por_uma_hora(monkeypatch):
    monkeypatch.setattr(enriquecimento.requests, "get", lambda *a, **k: RespostaFalsa(429))
    assert enriquecimento.enriquecer("8.8.8.8") is None
    monkeypatch.setattr(enriquecimento.requests, "get", lambda *a, **k: RespostaFalsa(200, DADOS))
    assert enriquecimento.enriquecer("8.8.8.8")["pais"] == "DE"
