"""Testes das rotas de escrita: POST /api/alertas (D3, D4) e POST /api/analisar."""

import pytest

from tests.conftest import cabecalho

ALERTA = {"timestamp": "2025-03-01 10:00:00", "regra": "Manual", "ip": "185.220.101.1",
          "severidade": "ALTA", "descricao": "criado pela API"}


def test_d3_post_alerta_sem_token_devolve_401(cliente):
    resposta = cliente.post("/api/alertas", json=ALERTA)
    assert resposta.status_code == 401


def test_d4_post_alerta_com_corpo_invalido_devolve_400(cliente, token_valido):
    resposta = cliente.post("/api/alertas", json={}, headers=cabecalho(token_valido))
    assert resposta.status_code == 400
    assert "erro" in resposta.get_json()


def test_post_alerta_cria_e_depois_le_pelo_id(cliente, token_valido):
    criado = cliente.post("/api/alertas", json=ALERTA, headers=cabecalho(token_valido))
    assert criado.status_code == 201
    lido = cliente.get(f"/api/alertas/{criado.get_json()['id']}")
    assert lido.status_code == 200 and lido.get_json()["descricao"] == "criado pela API"


def test_post_alerta_repetido_devolve_200_existente(cliente, token_valido):
    cliente.post("/api/alertas", json=ALERTA, headers=cabecalho(token_valido))
    repetido = cliente.post("/api/alertas", json=ALERTA, headers=cabecalho(token_valido))
    assert repetido.status_code == 200 and repetido.get_json()["existente"] is True


def test_campos_extras_do_corpo_nao_sao_gravados(cliente, token_valido, banco):
    cliente.post("/api/alertas", json={**ALERTA, "_id": "forjado", "admin": True},
                 headers=cabecalho(token_valido))
    documento = banco["alertas"].find_one({})
    assert documento["_id"] != "forjado" and "admin" not in documento


@pytest.mark.parametrize("rota", ["/api/alertas", "/api/analisar"])
def test_corpo_que_nao_e_objeto_json_devolve_400(cliente, token_valido, rota):
    for enviado in ({"json": []}, {"json": None, "data": "null", "content_type": "application/json"},
                    {"json": "texto"}, {"data": "{quebrado", "content_type": "application/json"},
                    {"data": b"\xff\xfe", "content_type": "application/json"},
                    {"data": "x=1", "content_type": "text/plain"}):
        resposta = cliente.post(rota, headers=cabecalho(token_valido), **enviado)
        assert resposta.status_code == 400, enviado


def test_analisar_exige_token(cliente):
    assert cliente.post("/api/analisar", json={"pasta": "."}).status_code == 401


def test_analisar_pasta_de_logs_devolve_resumo_com_ml(cliente, token_valido, banco):
    resposta = cliente.post("/api/analisar", json={"pasta": "."}, headers=cabecalho(token_valido))
    corpo = resposta.get_json()
    assert resposta.status_code == 200
    assert corpo["total_eventos"] == 58 and corpo["ml_disponivel"] is True
    assert corpo["persistencia"]["banco_disponivel"] is True
    assert banco["eventos"].count_documents({}) == 58


def test_analisar_lote_de_eventos(cliente, token_valido):
    eventos = [{"fonte": "auth", "ip": "1.2.3.4", "timestamp": f"2025-02-20 08:00:{n:02d}",
                "tipo": "FAIL", "detalhes": "usuario=root", "linha_original": f"l{n}"}
               for n in range(8)]
    resposta = cliente.post("/api/analisar", json={"eventos": eventos}, headers=cabecalho(token_valido))
    assert resposta.status_code == 200
    assert resposta.get_json()["total_eventos"] == 8


@pytest.mark.parametrize("pasta", ["../fora", "/etc", "..", "sub/../../x"])
def test_analisar_rejeita_pasta_fora_de_logs_sem_ecoar_caminho(cliente, token_valido, pasta):
    resposta = cliente.post("/api/analisar", json={"pasta": pasta}, headers=cabecalho(token_valido))
    assert resposta.status_code == 400
    assert b"/home" not in resposta.data and b"securapy" not in resposta.data


def test_corpo_maior_que_1mb_devolve_413(cliente, token_valido):
    resposta = cliente.post("/api/alertas", data=b"x" * (1024 * 1024 + 1),
                            content_type="application/json", headers=cabecalho(token_valido))
    assert resposta.status_code == 413


def test_erro_no_nucleo_nao_vaza_detalhes(cliente, token_valido, monkeypatch):
    def quebra(*args, **kwargs):
        raise RuntimeError("segredo-xyz")

    monkeypatch.setattr("api.rotas.analisar_com_ml", quebra)
    resposta = cliente.post("/api/analisar", json={"pasta": "."}, headers=cabecalho(token_valido))
    assert resposta.status_code == 500
    assert resposta.get_json() == {"erro": "erro interno"} and b"segredo-xyz" not in resposta.data


def test_banco_indisponivel_no_post_alerta_devolve_503(cliente, token_valido, deps):
    deps.mongo = lambda: None
    resposta = cliente.post("/api/alertas", json=ALERTA, headers=cabecalho(token_valido))
    assert resposta.status_code == 503


def _lote():
    return [{"fonte": "auth", "ip": "1.2.3.4", "timestamp": "2025-02-20 08:00:00",
             "tipo": "FAIL", "detalhes": "usuario=root", "linha_original": "l"}]


def test_erro_de_persistencia_em_lote_nao_vira_400(cliente, token_valido, monkeypatch):
    def quebra(*args, **kwargs):
        raise TypeError("bug na gravação")

    monkeypatch.setattr("api.servico._persistir_no_banco", quebra)
    resposta = cliente.post("/api/analisar", json={"eventos": _lote()}, headers=cabecalho(token_valido))
    assert resposta.status_code == 500


def test_lote_que_quebra_o_nucleo_devolve_400_e_pasta_devolve_500(cliente, token_valido, monkeypatch):
    def quebra(eventos):
        raise KeyError("campo")

    monkeypatch.setattr("api.servico.executar_nucleo", quebra)
    lote = cliente.post("/api/analisar", json={"eventos": _lote()}, headers=cabecalho(token_valido))
    assert lote.status_code == 400
    assert lote.get_json() == {"erro": "eventos em formato inesperado"}
    pasta = cliente.post("/api/analisar", json={"pasta": "."}, headers=cabecalho(token_valido))
    assert pasta.status_code == 500


def test_surrogate_solitario_no_json_devolve_400_nos_posts(cliente, token_valido):
    alerta = ('{"timestamp":"2025-03-01 10:00:00","regra":"\\ud800","ip":"1.2.3.4",'
              '"severidade":"ALTA","descricao":"x"}')
    lote = ('{"eventos":[{"fonte":"auth","ip":"1.2.3.4","timestamp":"2025-02-20 08:00:00",'
            '"tipo":"FAIL","detalhes":"\\ud800","linha_original":"l"}]}')
    for rota, corpo in (("/api/alertas", alerta), ("/api/analisar", lote)):
        resposta = cliente.post(rota, data=corpo, content_type="application/json",
                                headers=cabecalho(token_valido))
        assert resposta.status_code == 400, rota


def test_analisar_pasta_que_e_arquivo_ou_nao_existe_devolve_400(cliente, token_valido):
    for pasta in ("auth.log", "nao_existe"):
        resposta = cliente.post("/api/analisar", json={"pasta": pasta},
                                headers=cabecalho(token_valido))
        assert resposta.status_code == 400, pasta
