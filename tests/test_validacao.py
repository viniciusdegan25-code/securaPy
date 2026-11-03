"""Testes da validação de entrada da API (Módulo D)."""

import pytest

from api.validacao import (ValidacaoError, validar_corpo_alerta, validar_corpo_analise,
                           validar_ip, validar_paginacao, validar_periodo, validar_severidade)


@pytest.mark.parametrize("valor", ["185.220.101.1", "2001:db8::1"])
def test_validar_ip_aceita_ipv4_e_ipv6(valor):
    assert validar_ip(valor) == valor


@pytest.mark.parametrize("valor", ["010.0.0.1", "1.2.3", "a/b", "1.1.1.1 ", "%00", "", None])
def test_validar_ip_rejeita_malformados(valor):
    with pytest.raises(ValidacaoError):
        validar_ip(valor)


def test_paginacao_padrao_e_valores_validos():
    assert validar_paginacao({}) == (1, 20)
    assert validar_paginacao({"pagina": "2", "tamanho": "5"}) == (2, 5)


@pytest.mark.parametrize("args", [
    {"pagina": "0"}, {"pagina": "-1"}, {"pagina": "abc"},
    {"tamanho": "0"}, {"tamanho": "101"}, {"tamanho": "abc"}, {"tamanho": "1000000000"},
])
def test_paginacao_rejeita_valores_absurdos(args):
    with pytest.raises(ValidacaoError):
        validar_paginacao(args)


def test_severidade_aceita_somente_valores_conhecidos():
    assert validar_severidade("CRITICA") == "CRITICA"
    for invalida in ("critica", "X", None, 5):
        with pytest.raises(ValidacaoError):
            validar_severidade(invalida)


def test_periodo_aceita_formato_e_none():
    assert validar_periodo(None) is None
    assert validar_periodo("2025-02-20 08:15:00") == "2025-02-20 08:15:00"
    with pytest.raises(ValidacaoError):
        validar_periodo("ontem")


CORPO_ALERTA = {"timestamp": "2025-02-20 08:15:00", "regra": "Teste", "ip": "185.220.101.1",
                "severidade": "ALTA", "descricao": "descrição"}


def test_corpo_alerta_valido_devolve_so_as_cinco_chaves():
    resultado = validar_corpo_alerta({**CORPO_ALERTA, "admin": True, "_id": "x"})
    assert resultado == CORPO_ALERTA


@pytest.mark.parametrize("corpo", [None, [], "txt", 3])
def test_corpo_alerta_rejeita_o_que_nao_e_objeto(corpo):
    with pytest.raises(ValidacaoError):
        validar_corpo_alerta(corpo)


@pytest.mark.parametrize("campo,valor", [
    ("ip", "abc"), ("severidade", "X"), ("timestamp", "ontem"),
    ("descricao", "a" * 501), ("regra", ""), ("regra", "r" * 101),
])
def test_corpo_alerta_rejeita_campo_invalido(campo, valor):
    with pytest.raises(ValidacaoError):
        validar_corpo_alerta({**CORPO_ALERTA, campo: valor})


def test_corpo_alerta_rejeita_campo_faltando():
    corpo = dict(CORPO_ALERTA)
    del corpo["ip"]
    with pytest.raises(ValidacaoError):
        validar_corpo_alerta(corpo)


EVENTO = {"fonte": "auth", "ip": "1.2.3.4", "timestamp": "2025-02-20 08:15:00",
          "tipo": "FAIL", "detalhes": "usuario=root", "linha_original": "linha"}


def test_corpo_analise_pasta_dentro_da_base(tmp_path):
    (tmp_path / "sub").mkdir()
    resultado = validar_corpo_analise({"pasta": "sub"}, tmp_path)
    assert resultado == {"pasta": (tmp_path / "sub").resolve()}


@pytest.mark.parametrize("pasta", ["../fora", "/etc", "sub/../../fora"])
def test_corpo_analise_rejeita_pasta_fora_da_base(tmp_path, pasta):
    with pytest.raises(ValidacaoError) as erro:
        validar_corpo_analise({"pasta": pasta}, tmp_path)
    assert str(tmp_path) not in str(erro.value)


def test_corpo_analise_exige_exatamente_uma_chave(tmp_path):
    with pytest.raises(ValidacaoError):
        validar_corpo_analise({"pasta": ".", "eventos": []}, tmp_path)
    with pytest.raises(ValidacaoError):
        validar_corpo_analise({}, tmp_path)


def test_corpo_analise_eventos_validos_e_limites(tmp_path):
    assert validar_corpo_analise({"eventos": [EVENTO]}, tmp_path) == {"eventos": [EVENTO]}
    with pytest.raises(ValidacaoError):
        validar_corpo_analise({"eventos": [EVENTO] * 5001}, tmp_path)
    sem_ip = {k: v for k, v in EVENTO.items() if k != "ip"}
    with pytest.raises(ValidacaoError):
        validar_corpo_analise({"eventos": [sem_ip]}, tmp_path)
    with pytest.raises(ValidacaoError):
        validar_corpo_analise({"eventos": [{**EVENTO, "ip": "zzz"}]}, tmp_path)


@pytest.mark.parametrize("alteracao", [
    {"fonte": "desconhecida"},
    {"timestamp": "ontem"},
    {"fonte": "firewall", "tipo": "BLOCK", "detalhes": "proto=TCP dst=10.0.0.1 dport=abc"},
    {"fonte": "firewall", "tipo": "BLOCK", "detalhes": "proto=TCP dst=10.0.0.1"},
    {"fonte": "firewall", "tipo": "BLOCK", "detalhes": "proto=TCP dst=10.0.0.1 dport=70000"},
])
def test_corpo_analise_rejeita_evento_que_quebraria_o_nucleo(tmp_path, alteracao):
    with pytest.raises(ValidacaoError):
        validar_corpo_analise({"eventos": [{**EVENTO, **alteracao}]}, tmp_path)


def test_corpo_analise_aceita_evento_de_firewall_bem_formado(tmp_path):
    bloqueio = {**EVENTO, "fonte": "firewall", "tipo": "BLOCK",
                "detalhes": "proto=TCP dst=10.0.0.1 dport=22"}
    assert validar_corpo_analise({"eventos": [bloqueio]}, tmp_path) == {"eventos": [bloqueio]}
