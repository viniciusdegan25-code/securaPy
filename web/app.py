"""Aplicação Flask do dashboard SecuraPy (Módulo E).

Execução local: ``python -m web.app`` (ou ``flask --app web.app run``) a partir
da raiz do projeto. No Docker roda com gunicorn na porta 5000.

O dashboard usa as mesmas dependências da API (``api.app.Deps``): MongoDB
reaproveitado, MySQL para o login, geolocalização e score do ML. Nos testes
essas dependências são trocadas por versões em memória.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)

from api.app import Deps
from db import consultas_api, mongo_repo, mysql_repo
from db.consultas_api import BancoIndisponivelError
from ia.assistente import classificar_alerta
from ml.classificar import IntegridadeModeloError

# Login endurecido: depois de 5 falhas do mesmo IP em 5 minutos, o login
# fica bloqueado para esse IP até a janela passar (contra brute force).
MAXIMO_FALHAS_LOGIN = 5
JANELA_FALHAS_SEGUNDOS = 300
MENSAGEM_LOGIN_INVALIDO = "Email ou senha inválidos."


def _exigir_login(funcao):
    @wraps(funcao)
    def protegida(*args, **kwargs):
        if "operador" not in session:
            return redirect(url_for("login", proxima=request.path))
        return funcao(*args, **kwargs)
    return protegida


def _ip_valido(texto):
    """Normaliza o IP com o módulo ipaddress. Levanta ValueError se for inválido."""
    return str(ipaddress.ip_address(str(texto).strip()))


def _texto_para_log(texto):
    """Escapa quebras de linha: um atacante não pode forjar linhas no log."""
    return str(texto).encode("unicode_escape").decode("ascii")


def _ordenar_severidades(contagem):
    """Mostra da mais grave para a mais leve (CRITICA primeiro)."""
    ordem = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")
    return dict(sorted(contagem.items(),
                       key=lambda item: ordem.index(item[0]) if item[0] in ordem else len(ordem)))


def criar_app(configuracao=None, deps=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", ""),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=1800,
    )
    app.logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    if configuracao:
        app.config.update(configuracao)
    if not app.config.get("SECRET_KEY"):
        # Facilita execução local, mas sessão não persiste após reinício.
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning("FLASK_SECRET_KEY ausente; chave temporária de sessão em uso.")

    deps = deps if deps is not None else Deps.padrao()
    falhas_login = defaultdict(deque)   # {ip: horários das últimas falhas}

    def login_bloqueado(ip):
        agora = time.monotonic()
        falhas = falhas_login[ip]
        while falhas and agora - falhas[0] > JANELA_FALHAS_SEGUNDOS:
            falhas.popleft()
        return len(falhas) >= MAXIMO_FALHAS_LOGIN

    # ------------------------------------------------------------------
    # Segurança e log em todas as requisições
    # ------------------------------------------------------------------

    @app.before_request
    def conferir_csrf():
        if request.method == "POST":
            enviado = request.form.get("csrf_token", "")
            esperado = session.get("csrf_token", "")
            if not esperado or not hmac.compare_digest(enviado, esperado):
                abort(400)

    @app.after_request
    def protecoes_e_log(resposta):
        resposta.headers["X-Content-Type-Options"] = "nosniff"
        resposta.headers["X-Frame-Options"] = "DENY"
        resposta.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        resposta.headers["Referrer-Policy"] = "same-origin"
        resposta.headers["Cache-Control"] = "no-store"
        # Log de acesso (OWASP A09): quem, o quê, onde e o resultado
        app.logger.info("access ip=%s method=%s path=%s status=%s",
                        request.remote_addr or "-", request.method,
                        _texto_para_log(request.path), resposta.status_code)
        return resposta

    @app.errorhandler(BancoIndisponivelError)
    def banco_fora(erro):
        app.logger.error("Banco indisponível: %s", erro)
        return render_template("erro.html", codigo=503,
                               mensagem="O banco de dados está indisponível no momento."), 503

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(429)
    @app.errorhandler(500)
    def erro_generico(erro):
        # Página simples: nunca mostra traceback, query ou caminho do servidor
        codigo = getattr(erro, "code", 500) or 500
        mensagens = {400: "Requisição inválida. Recarregue a página e tente de novo.",
                     404: "Página não encontrada.",
                     429: "Muitas tentativas. Aguarde alguns minutos.",
                     500: "Erro interno. Tente novamente."}
        return render_template("erro.html", codigo=codigo,
                               mensagem=mensagens.get(codigo, "Erro na requisição.")), codigo

    # ------------------------------------------------------------------
    # Login e logout
    # ------------------------------------------------------------------

    @app.get("/login")
    def login():
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("login.html", csrf_token=session["csrf_token"])

    @app.post("/login")
    def autenticar_operador():
        ip_cliente = request.remote_addr or "-"
        if login_bloqueado(ip_cliente):
            app.logger.warning("login bloqueado ip=%s (muitas falhas)", ip_cliente)
            flash("Muitas tentativas de login. Aguarde alguns minutos.", "erro")
            return render_template("login.html", csrf_token=session["csrf_token"]), 429

        email = request.form.get("email", "")
        senha = request.form.get("senha", "")
        conexao = deps.mysql()
        operador = None
        if conexao is not None:
            try:
                operador = mysql_repo.autenticar(conexao, email, senha)
            finally:
                conexao.close()
        if operador is None:
            # Mesma mensagem para usuário inexistente e senha errada (anti-enumeração)
            falhas_login[ip_cliente].append(time.monotonic())
            app.logger.warning("login falhou ip=%s", ip_cliente)
            flash(MENSAGEM_LOGIN_INVALIDO, "erro")
            return render_template("login.html", csrf_token=session["csrf_token"]), 401

        falhas_login.pop(ip_cliente, None)
        session.clear()   # nova sessão depois do login (contra session fixation)
        session["operador"] = {"id": operador["id"], "nome": operador["nome"],
                               "email": operador["email"]}
        session["csrf_token"] = secrets.token_urlsafe(32)
        app.logger.info("login ok ip=%s operador_id=%s", ip_cliente, operador["id"])
        destino = request.args.get("proxima", "")
        # Só aceita caminhos internos: bloqueia redirecionamento para outro site
        if (not destino.startswith("/") or destino.startswith("//")
                or any(caractere in destino for caractere in "\\\r\n")):
            destino = url_for("dashboard")
        return redirect(destino)

    @app.post("/logout")
    @_exigir_login
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------------------
    # Painel
    # ------------------------------------------------------------------

    @app.get("/")
    @_exigir_login
    def dashboard():
        banco = deps.mongo()
        return render_template(
            "dashboard.html",
            banco_disponivel=banco is not None,
            fontes=mongo_repo.contar_eventos_por_fonte(banco),
            severidades=_ordenar_severidades(mongo_repo.contar_alertas_por_severidade(banco)),
            top_ips=mongo_repo.top_ips(banco, 10),
            alertas=mongo_repo.buscar_alertas(banco, limite=20, mais_recentes=True),
            operador=session["operador"], csrf_token=session["csrf_token"])

    @app.get("/ip")
    @_exigir_login
    def buscar_ip():
        try:
            ip = _ip_valido(request.args.get("ip", ""))
        except ValueError:
            flash("Informe um endereço IP válido.", "erro")
            return redirect(url_for("dashboard"))
        return redirect(url_for("detalhe_ip", ip=ip))

    @app.get("/ip/<ip>")
    @_exigir_login
    def detalhe_ip(ip):
        try:
            ip = _ip_valido(ip)
        except ValueError:
            abort(404)
        eventos, alertas = consultas_api.alertas_e_eventos_do_ip(deps.mongo(), ip)

        try:
            geo = deps.enriquecer(ip)
        except Exception:   # a geolocalização é um extra: nunca derruba a página
            app.logger.warning("Falha ao enriquecer IP", exc_info=True)
            geo = None

        try:
            ml = deps.classificar_ip(ip, eventos)
        except (IntegridadeModeloError, FileNotFoundError, ValueError) as erro:
            app.logger.warning("ML indisponível: %s", erro.__class__.__name__)
            ml = None

        # Triagem rápida por regras (sem chamar o LLM a cada abertura da página)
        triagens = [{"alerta": alerta,
                     "resultado": classificar_alerta(alerta, usar_llm=False)}
                    for alerta in reversed(alertas)]
        return render_template("ip.html", ip=ip, eventos=eventos, triagens=triagens,
                               geo=geo, ml=ml, operador=session["operador"],
                               csrf_token=session["csrf_token"])

    @app.post("/ip/<ip>/assistente")
    @_exigir_login
    def consultar_assistente(ip):
        try:
            ip = _ip_valido(ip)
            alerta = consultas_api.buscar_alerta_por_id(deps.mongo(),
                                                        request.form.get("alerta_id", ""))
        except ValueError:
            abort(400)
        if alerta is None or alerta.get("ip") != ip:
            abort(404)
        resultado = classificar_alerta(alerta)
        flash(f"Assistente ({resultado['classificacao']}, via {resultado['provedor']}): "
              f"{resultado['explicacao']}", "triagem")
        return redirect(url_for("detalhe_ip", ip=ip))

    return app


app = criar_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORTA_WEB", "5000")), debug=False)
