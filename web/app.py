"""Aplicação Flask do dashboard SecuraPy.

Execução local: ``flask --app web.app run`` a partir da raiz do projeto.
O dashboard consulta os repositórios existentes; a API REST de D pode depois
assumir essas consultas sem alterar os templates ou o contrato visual.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)

from db import mongo_repo, mysql_repo
from ia.assistente import classificar_alerta


def _exigir_login(funcao):
    @wraps(funcao)
    def protegida(*args, **kwargs):
        if "operador" not in session:
            return redirect(url_for("login", proxima=request.path))
        return funcao(*args, **kwargs)
    return protegida


def criar_app(configuracao=None):
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

    @app.before_request
    def iniciar_requisicao():
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
        app.logger.info("access ip=%s method=%s path=%s status=%s",
                        request.remote_addr or "-", request.method,
                        request.path, resposta.status_code)
        return resposta

    @app.get("/login")
    def login():
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("login.html", csrf_token=session["csrf_token"])

    @app.post("/login")
    def autenticar_operador():
        email = request.form.get("email", "")
        senha = request.form.get("senha", "")
        conexao = mysql_repo.conectar()
        operador = None
        if conexao is not None:
            try:
                operador = mysql_repo.autenticar(conexao, email, senha)
            finally:
                conexao.close()
        if operador is None:
            flash("Email ou senha inválidos.", "erro")
            return render_template("login.html", csrf_token=session["csrf_token"]), 401
        session.clear()
        session["operador"] = {"id": operador["id"], "nome": operador["nome"],
                               "email": operador["email"]}
        session["csrf_token"] = secrets.token_urlsafe(32)
        destino = request.args.get("proxima", "")
        if not destino.startswith("/") or destino.startswith("//"):
            destino = url_for("dashboard")
        if "\\" in destino or "\r" in destino or "\n" in destino:
            destino = url_for("dashboard")
        return redirect(destino)

    @app.post("/logout")
    @_exigir_login
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @_exigir_login
    def dashboard():
        banco = mongo_repo.conectar()
        resumo_fontes = mongo_repo.contar_eventos_por_fonte(banco)
        severidades = mongo_repo.contar_alertas_por_severidade(banco)
        top = mongo_repo.top_ips_suspeitos(banco, 10)
        alertas = mongo_repo.buscar_alertas(banco, limite=20)
        alertas.reverse()
        return render_template("dashboard.html", fontes=resumo_fontes,
                               severidades=severidades, top_ips=top,
                               alertas=alertas, operador=session["operador"],
                               csrf_token=session["csrf_token"])

    @app.get("/ip")
    @_exigir_login
    def buscar_ip():
        ip = request.args.get("ip", "").strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            flash("Informe um endereço IP válido.", "erro")
            return redirect(url_for("dashboard"))
        return redirect(url_for("detalhe_ip", ip=ip))

    @app.get("/ip/<ip>")
    @_exigir_login
    def detalhe_ip(ip):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            abort(404)
        banco = mongo_repo.conectar()
        eventos = mongo_repo.buscar_eventos(banco, ip=ip, limite=100)
        alertas = mongo_repo.buscar_alertas(banco, ip=ip, limite=100)
        alertas.reverse()
        triagens = [{"alerta": alerta,
                     "resultado": classificar_alerta(alerta, usar_llm=False)}
                    for alerta in alertas]
        return render_template("ip.html", ip=ip, eventos=eventos,
                               triagens=triagens,
                               operador=session["operador"],
                               csrf_token=session["csrf_token"])

    @app.post("/ip/<ip>/assistente")
    @_exigir_login
    def consultar_assistente(ip):
        try:
            ip = str(ipaddress.ip_address(ip))
            indice = int(request.form.get("indice", "-1"))
        except (ValueError, TypeError):
            abort(400)
        banco = mongo_repo.conectar()
        alertas = mongo_repo.buscar_alertas(banco, ip=ip, limite=100)
        alertas.reverse()
        if indice < 0 or indice >= len(alertas):
            abort(404)
        resultado = classificar_alerta(alertas[indice])
        flash(f"Assistente ({resultado['classificacao']}): {resultado['explicacao']}",
              "triagem")
        return redirect(url_for("detalhe_ip", ip=ip))

    return app


app = criar_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORTA_WEB", "5000")), debug=False)
