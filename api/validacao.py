"""
api/validacao.py — Validação de toda entrada que chega pela API (Módulo D).

Cada função recebe o dado bruto e devolve o valor limpo, ou levanta
ValidacaoError com uma mensagem curta e segura para mostrar ao cliente
(nunca com caminhos do servidor ou detalhes internos).
"""

import ipaddress
import os
from datetime import datetime
from pathlib import Path

SEVERIDADES = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")
FORMATO_TIMESTAMP = "%Y-%m-%d %H:%M:%S"
TAMANHO_PADRAO = 20
TAMANHO_MAXIMO = 100
MAXIMO_EVENTOS = 5000
MAXIMO_TEXTO_EVENTO = 1000
FONTES = ("auth", "firewall", "web")
CAMPOS_EVENTO = ("fonte", "ip", "timestamp", "tipo", "detalhes", "linha_original")


class ValidacaoError(Exception):
    """Entrada inválida. str(erro) é a mensagem que o cliente pode ver."""


def validar_ip(valor):
    """Aceita IPv4 ou IPv6 e devolve a forma canônica. Qualquer outra coisa é erro."""
    if not isinstance(valor, str) or not valor or len(valor) > 45 or "%" in valor:
        raise ValidacaoError("ip inválido")
    try:
        return str(ipaddress.ip_address(valor))
    except ValueError:
        raise ValidacaoError("ip inválido") from None


def validar_severidade(valor):
    """Confere se a severidade é uma das cinco conhecidas."""
    if not isinstance(valor, str) or valor not in SEVERIDADES:
        raise ValidacaoError("severidade inválida")
    return valor


def validar_periodo(valor):
    """Valida um horário 'AAAA-MM-DD HH:MM:SS'. None significa sem filtro."""
    if valor is None:
        return None
    try:
        datetime.strptime(valor, FORMATO_TIMESTAMP)
    except (TypeError, ValueError):
        raise ValidacaoError("data inválida, use AAAA-MM-DD HH:MM:SS") from None
    return valor


def _inteiro_positivo(texto, nome, maximo=None):
    """Converte texto só com dígitos ASCII em inteiro ≥ 1 (sem '+', '_' ou espaços)."""
    if not (isinstance(texto, str) and texto.isascii() and texto.isdigit() and len(texto) <= 9):
        raise ValidacaoError(f"{nome} inválido")
    numero = int(texto)
    if numero < 1 or (maximo is not None and numero > maximo):
        raise ValidacaoError(f"{nome} inválido")
    return numero


def validar_paginacao(args):
    """Lê 'pagina' (≥ 1) e 'tamanho' (1–100) da query string. Retorna (pagina, tamanho)."""
    pagina = _inteiro_positivo(args.get("pagina", "1"), "pagina")
    tamanho = _inteiro_positivo(args.get("tamanho", str(TAMANHO_PADRAO)), "tamanho",
                                TAMANHO_MAXIMO)
    return pagina, tamanho


def _texto(corpo, campo, maximo, obrigatorio_nao_vazio=False):
    valor = corpo.get(campo)
    if not isinstance(valor, str) or len(valor) > maximo:
        raise ValidacaoError(f"{campo} inválido")
    if obrigatorio_nao_vazio and not valor.strip():
        raise ValidacaoError(f"{campo} inválido")
    return valor


def validar_corpo_alerta(corpo):
    """Valida o corpo do POST /api/alertas e devolve só os cinco campos permitidos."""
    if not isinstance(corpo, dict):
        raise ValidacaoError("o corpo deve ser um objeto JSON")
    return {
        "timestamp": validar_periodo(_texto(corpo, "timestamp", 19)),
        "regra": _texto(corpo, "regra", 100, obrigatorio_nao_vazio=True),
        "ip": validar_ip(corpo.get("ip")),
        "severidade": validar_severidade(corpo.get("severidade")),
        "descricao": _texto(corpo, "descricao", 500),
    }


def _validar_pasta(valor, pasta_base):
    """Resolve a pasta e garante que ela fica dentro de pasta_base (anti path traversal)."""
    if not isinstance(valor, str) or not valor.strip() or "\x00" in valor:
        raise ValidacaoError("pasta inválida")
    base = Path(os.path.realpath(pasta_base))
    alvo = Path(os.path.realpath(base / valor))
    if os.path.commonpath([base, alvo]) != str(base):
        raise ValidacaoError("pasta inválida")
    return alvo


def _validar_evento(evento):
    if not isinstance(evento, dict):
        raise ValidacaoError("evento inválido")
    limpo = {}
    for campo in CAMPOS_EVENTO:
        valor = evento.get(campo)
        if not isinstance(valor, str) or len(valor) > MAXIMO_TEXTO_EVENTO:
            raise ValidacaoError(f"evento inválido: {campo}")
        limpo[campo] = valor
    limpo["ip"] = validar_ip(limpo["ip"])
    if limpo["fonte"] not in FONTES:
        raise ValidacaoError("evento inválido: fonte")
    validar_periodo(limpo["timestamp"])
    if limpo["fonte"] == "firewall" and limpo["tipo"] == "BLOCK":
        _conferir_porta_do_bloqueio(limpo["detalhes"])   # o núcleo faz int() dessa porta
    return limpo


def _conferir_porta_do_bloqueio(detalhes):
    for pedaco in detalhes.split():
        if pedaco.startswith("dport="):
            porta = pedaco.split("=", 1)[1]
            if porta.isascii() and porta.isdigit() and 1 <= int(porta) <= 65535:
                return
            break
    raise ValidacaoError("evento inválido: porta")


def validar_corpo_analise(corpo, pasta_base):
    """
    Valida o corpo do POST /api/analisar. Exige exatamente uma das chaves:
    {"pasta": ...} (subpasta de pasta_base) ou {"eventos": [...]} (até 5000).
    """
    if not isinstance(corpo, dict):
        raise ValidacaoError("o corpo deve ser um objeto JSON")
    if ("pasta" in corpo) == ("eventos" in corpo):
        raise ValidacaoError("envie 'pasta' ou 'eventos' (apenas um)")
    if "pasta" in corpo:
        return {"pasta": _validar_pasta(corpo["pasta"], pasta_base)}

    eventos = corpo["eventos"]
    if not isinstance(eventos, list) or len(eventos) > MAXIMO_EVENTOS:
        raise ValidacaoError(f"'eventos' deve ser uma lista de até {MAXIMO_EVENTOS} itens")
    return {"eventos": [_validar_evento(evento) for evento in eventos]}
