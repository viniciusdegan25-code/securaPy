"""
api/auth.py — Autenticação da API por token JWT (Módulo D).

Fluxo: o operador faz POST /api/login com email e senha (conferidos no MySQL
por db/mysql_repo.autenticar) e recebe um JWT assinado (HS256) com validade
curta. As rotas de escrita exigem esse token em "Authorization: Bearer <token>".
"""

import re
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

ALGORITMO = "HS256"
PADRAO_CABECALHO = re.compile(r"Bearer ([A-Za-z0-9_\-\.]+)")


class TokenInvalidoError(Exception):
    """Token ausente, malformado, expirado ou com assinatura errada."""


def emitir_token(email, nivel, segredo, minutos):
    """Gera um JWT. Retorna (token, validade_em_segundos)."""
    agora = datetime.now(timezone.utc)
    claims = {"sub": email, "nivel": nivel, "iat": agora,
              "exp": agora + timedelta(minutes=minutos)}
    return jwt.encode(claims, segredo, algorithm=ALGORITMO), minutos * 60


def validar_token(token, segredo):
    """Confere assinatura e validade. Retorna os claims ou levanta TokenInvalidoError."""
    try:
        # algorithms fixo: impede aceitar tokens "alg: none" ou trocar o algoritmo
        return jwt.decode(token, segredo, algorithms=[ALGORITMO],
                          options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        raise TokenInvalidoError("token inválido") from None


def _nao_autorizado():
    resposta = jsonify({"erro": "não autorizado"})
    resposta.status_code = 401
    resposta.headers["WWW-Authenticate"] = "Bearer"
    return resposta


def exige_token(funcao):
    """Decorator: exige Authorization: Bearer <jwt> válido; senão responde 401."""
    @wraps(funcao)
    def protegida(*args, **kwargs):
        encontrado = PADRAO_CABECALHO.fullmatch(request.headers.get("Authorization", ""))
        if encontrado is None:
            return _nao_autorizado()
        try:
            g.usuario = validar_token(encontrado.group(1), current_app.config["JWT_SECRET"])
        except TokenInvalidoError:
            return _nao_autorizado()
        return funcao(*args, **kwargs)
    return protegida
