"""Testes do dashboard web (Módulo E), com bancos em memória e sem rede."""

import logging
import re

import pytest

from api.app import create_app
from api.auth import emitir_token
from db import consultas_api, mongo_repo
from tests.conftest import SEGREDO, cabecalho
from web import app as modulo_web

OPERADOR = {"id": 1, "nome": "Analista SOC", "email": "analista@securapy.com", "nivel_acesso": 3}
SENHA = "Senha@Forte123"


def autenticar_falso(conexao, email, senha):
    """Só existe o analista@securapy.com com a SENHA acima."""
    return dict(OPERADOR) if (email, senha) == (OPERADOR["email"], SENHA) else None


@pytest.fixture
def web(deps, monkeypatch):
    monkeypatch.setattr(modulo_web.mysql_repo, "autenticar", autenticar_falso)
    aplicacao = modulo_web.criar_app({"SECRET_KEY": "teste", "TESTING": False}, deps)
    return aplicacao.test_client()


def csrf(cliente, caminho="/login"):
    pagina = cliente.get(caminho).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', pagina).group(1)


def entrar(cliente, email=OPERADOR["email"], senha=SENHA):
    return cliente.post("/login", data={"email": email, "senha": senha,
                                        "csrf_token": csrf(cliente)})


@pytest.fixture
def logado(web):
    assert entrar(web).status_code == 302
    return web


@pytest.fixture
def com_dados(banco):
    from analisar import executar_nucleo
    from core.coletor import carregar_todos_os_logs
    from db.configuracao import PASTA_LOGS

    eventos = carregar_todos_os_logs(PASTA_LOGS)
    alertas, _ = executar_nucleo(eventos)
    mongo_repo.salvar_eventos(banco, eventos)
    mongo_repo.salvar_alertas(banco, alertas)
    return banco


# --------------------------------------------------------------------
# Cenários do enunciado
# --------------------------------------------------------------------

def test_e1_script_na_descricao_aparece_como_texto(deps, banco, logado):
    # Cadastra o alerta pela API (como no enunciado) e abre o dashboard
    api = create_app({"JWT_SECRET": SEGREDO}, deps).test_client()
    token = emitir_token("analista@securapy.com", 3, SEGREDO, 60)[0]
    resposta = api.post("/api/alertas", headers=cabecalho(token), json={
        "timestamp": "2025-02-20 09:00:00", "regra": "Teste XSS", "severidade": "ALTA",
        "ip": "203.0.113.9", "descricao": "<script>alert(1)</script>"})
    assert resposta.status_code == 201

    for caminho in ("/", "/ip/203.0.113.9"):
        html = logado.get(caminho).get_data(as_text=True)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


@pytest.mark.parametrize("caminho", ["/login", "/", "/ip/185.220.101.1", "/rota-que-nao-existe"])
def test_e2_headers_de_seguranca_em_todas_as_respostas(web, caminho):
    resposta = web.get(caminho)
    assert resposta.headers["X-Content-Type-Options"] == "nosniff"
    assert resposta.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resposta.headers["Content-Security-Policy"]


def test_e3_mesma_mensagem_401_para_senha_errada_e_usuario_inexistente(web):
    senha_errada = entrar(web, senha="errada123")
    inexistente = entrar(web, email="ninguem@securapy.com", senha="errada123")
    assert senha_errada.status_code == inexistente.status_code == 401
    for resposta in (senha_errada, inexistente):
        assert "Email ou senha inválidos." in resposta.get_data(as_text=True)


def test_e4_cada_requisicao_gera_linha_de_log(web, caplog):
    with caplog.at_level(logging.INFO):
        web.get("/login")
        web.get("/qualquer/rota")
    linhas = [registro.getMessage() for registro in caplog.records]
    assert any("method=GET path=/login status=200" in linha for linha in linhas)
    assert any("path=/qualquer/rota status=404" in linha for linha in linhas)


# --------------------------------------------------------------------
# Dashboard e investigação de IP
# --------------------------------------------------------------------

def test_dashboard_mostra_fontes_severidades_e_top_ips(com_dados, logado):
    html = logado.get("/").get_data(as_text=True)
    for texto in ("auth", "firewall", "web", "CRITICA", "185.220.101.1", "Pesquisar endereço IP"):
        assert texto in html


def test_severidades_da_mais_grave_para_a_mais_leve(com_dados, logado):
    html = logado.get("/").get_data(as_text=True)
    assert html.index(">CRITICA<") < html.index(">ALTA<") < html.index(">MEDIA<")


def test_dashboard_sem_banco_avisa_e_nao_quebra(deps, logado):
    deps.mongo = lambda: None
    resposta = logado.get("/")
    assert resposta.status_code == 200
    assert "MongoDB está indisponível" in resposta.get_data(as_text=True)


def test_pagina_do_ip_tem_eventos_alertas_geo_e_score(com_dados, logado):
    html = logado.get("/ip/185.220.101.1").get_data(as_text=True)
    for texto in ("Score de risco", "ALTO", "0.90", "Moscow", "Brute Force", "usuario=admin"):
        assert texto in html


def test_busca_de_ip_invalido_volta_ao_painel(logado):
    resposta = logado.get("/ip?ip=999.1.1.1", follow_redirects=True)
    assert "Informe um endereço IP válido." in resposta.get_data(as_text=True)
    assert logado.get("/ip/nao-e-ip").status_code == 404


def test_assistente_explica_o_alerta(com_dados, logado):
    html = logado.get("/ip/185.220.101.1").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    alerta_id = re.search(r'name="alerta_id" value="([^"]+)"', html).group(1)
    resposta = logado.post("/ip/185.220.101.1/assistente", follow_redirects=True,
                           data={"csrf_token": token, "alerta_id": alerta_id})
    assert "Assistente (" in resposta.get_data(as_text=True)


def test_assistente_nao_aceita_alerta_de_outro_ip(com_dados, logado):
    html = logado.get("/ip/185.220.101.1").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    alerta_id = re.search(r'name="alerta_id" value="([^"]+)"', html).group(1)
    resposta = logado.post("/ip/10.0.0.5/assistente",
                           data={"csrf_token": token, "alerta_id": alerta_id})
    assert resposta.status_code == 404


def test_banco_fora_do_ar_na_pagina_do_ip_responde_503_sem_detalhes(deps, logado):
    deps.mongo = lambda: None
    resposta = logado.get("/ip/185.220.101.1")
    assert resposta.status_code == 503
    assert "Traceback" not in resposta.get_data(as_text=True)


# --------------------------------------------------------------------
# Sessão, CSRF e login endurecido
# --------------------------------------------------------------------

def test_rotas_exigem_login(web):
    resposta = web.get("/ip/185.220.101.1")
    assert resposta.status_code == 302 and "/login" in resposta.headers["Location"]


def test_post_sem_token_csrf_e_recusado(logado):
    assert logado.post("/logout").status_code == 400


def test_login_nao_redireciona_para_outro_site(web):
    token = csrf(web)
    resposta = web.post("/login?proxima=//site-malicioso.com", data={
        "email": OPERADOR["email"], "senha": SENHA, "csrf_token": token})
    assert resposta.headers["Location"] == "/"


def test_login_bloqueado_depois_de_5_falhas(web):
    for _ in range(modulo_web.MAXIMO_FALHAS_LOGIN):
        assert entrar(web, senha="errada123").status_code == 401
    assert entrar(web).status_code == 429   # nem a senha certa passa durante o bloqueio


def test_log_nao_aceita_quebra_de_linha_forjada(web, caplog):
    with caplog.at_level(logging.INFO):
        web.get("/x%0Afalso status=200")
    assert all("\n" not in registro.getMessage() for registro in caplog.records)


def test_logout_encerra_a_sessao(logado):
    token = re.search(r'name="csrf_token" value="([^"]+)"',
                      logado.get("/").get_data(as_text=True)).group(1)
    logado.post("/logout", data={"csrf_token": token})
    assert logado.get("/").status_code == 302


def test_id_do_alerta_usa_o_mesmo_formato_da_api(com_dados):
    alerta = mongo_repo.buscar_alertas(com_dados, limite=1)[0]
    codificado = consultas_api.codificar_id(mongo_repo.id_alerta(alerta))
    assert consultas_api.buscar_alerta_por_id(com_dados, codificado)["ip"] == alerta["ip"]
