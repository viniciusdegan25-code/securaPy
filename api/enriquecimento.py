"""
api/enriquecimento.py — Geolocalização de IPs pelo ipinfo.io (Módulo D).

Regras de segurança e robustez:
- IP privado, reservado ou de loopback nunca sai para a internet;
- timeout curto (3 s) e qualquer falha de rede devolve None, sem derrubar a API;
- resultados bem-sucedidos ficam em cache por 1 hora; falhas não são guardadas.
"""

import ipaddress
import os
import time

import requests

TEMPO_CACHE = 3600
TIMEOUT_SEGUNDOS = 3
MAXIMO_NO_CACHE = 1000
_cache = {}    # {ip: (expira_em, resultado)}


def limpar_cache():
    """Esvazia o cache (usado nos testes)."""
    _cache.clear()


def enriquecer(ip):
    """
    Retorna {"pais", "regiao", "cidade", "org"} do IP, ou None se o IP não for
    público ou a consulta falhar.
    """
    try:
        if not ipaddress.ip_address(ip).is_global:
            return None
    except ValueError:
        return None

    guardado = _cache.get(ip)
    if guardado and guardado[0] > time.time():
        return guardado[1]

    parametros = {"token": os.environ["IPINFO_TOKEN"]} if os.environ.get("IPINFO_TOKEN") else None
    try:
        resposta = requests.get(f"https://ipinfo.io/{ip}/json", params=parametros,
                                timeout=TIMEOUT_SEGUNDOS)
        dados = resposta.json() if resposta.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None
    if not isinstance(dados, dict):
        return None

    resultado = {"pais": dados.get("country"), "regiao": dados.get("region"),
                 "cidade": dados.get("city"), "org": dados.get("org")}
    if len(_cache) >= MAXIMO_NO_CACHE:
        _cache.clear()
    _cache[ip] = (time.time() + TEMPO_CACHE, resultado)
    return resultado
