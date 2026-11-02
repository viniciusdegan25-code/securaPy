"""Extração de características por IP a partir dos eventos do SecuraPy 1º sem."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, Mapping

FEATURES = (
    "falhas_auth",
    "portas_distintas",
    "ip_blacklist",
    "erros_web",
    "eventos_total",
    "bloqueios_firewall",
)

_CAMPO = re.compile(r"(?:^|\s)([a-zA-Z_]+)=([^\s]+)")
_FALHAS_ALERTA = re.compile(r"\b(\d+)\s+falhas\b", re.IGNORECASE)


def _campos(detalhes: str) -> dict[str, str]:
    return dict(_CAMPO.findall(detalhes or ""))


def extrair_features(eventos: Iterable[Mapping], blacklist: set[str] | None = None) -> dict[str, dict[str, float]]:
    """Retorna {ip: features}; aceita o dicionário normalizado do coletor.

    Contrato esperado: timestamp, fonte, tipo, ip, detalhes. Campos extras
    como linha_original são ignorados. Eventos sem IP são descartados.
    """
    blacklist = blacklist or set()
    acumulado: dict[str, dict] = defaultdict(
        lambda: {"falhas_auth": 0, "portas": set(), "erros_web": 0,
                 "eventos_total": 0, "bloqueios_firewall": 0}
    )

    for evento in eventos:
        ip = evento.get("ip")
        if not ip:
            continue
        fonte = str(evento.get("fonte", "")).lower()
        tipo = str(evento.get("tipo", "")).upper()
        detalhes = _campos(str(evento.get("detalhes", "")))
        item = acumulado[ip]
        item["eventos_total"] += 1
        if fonte == "auth" and tipo == "FAIL":
            item["falhas_auth"] += 1
        if fonte == "firewall" and tipo == "BLOCK":
            item["bloqueios_firewall"] += 1
        if fonte == "firewall" and detalhes.get("dport", "").isdigit():
            item["portas"].add(int(detalhes["dport"]))
        if fonte == "web":
            status = detalhes.get("status", "")
            if status.isdigit() and int(status) >= 400:
                item["erros_web"] += 1

    resultado = {}
    for ip, item in acumulado.items():
        resultado[ip] = {
            "falhas_auth": float(item["falhas_auth"]),
            "portas_distintas": float(len(item["portas"])),
            "ip_blacklist": float(ip in blacklist),
            "erros_web": float(item["erros_web"]),
            "eventos_total": float(item["eventos_total"]),
            "bloqueios_firewall": float(item["bloqueios_firewall"]),
        }
    return resultado


def features_de_ameaca(ameaca: Mapping) -> dict[str, float]:
    """Adapta o resumo legado ou o alerta temporal real do Módulo B.

    O alerta B contém apenas timestamp/regra/severidade/ip/descricao. Sem os
    eventos originais, somente a contagem explícita de falhas pode ser
    recuperada; os demais sinais ficam neutros (zero).
    """
    if "regra" in ameaca or "severidade" in ameaca:
        descricao = str(ameaca.get("descricao", ""))
        correspondencia = _FALHAS_ALERTA.search(descricao)
        falhas = float(correspondencia.group(1)) if correspondencia else 0.0
        return {
            "falhas_auth": falhas,
            "portas_distintas": 0.0,
            "ip_blacklist": 0.0,
            "erros_web": 0.0,
            "eventos_total": 0.0,
            "bloqueios_firewall": 0.0,
        }

    deteccoes = set(ameaca.get("deteccoes", []))
    detalhes = ameaca.get("detalhes", {}) or {}
    bruto = detalhes.get("brute_force", {}) or {}
    scan = detalhes.get("port_scan", {}) or {}
    return {
        "falhas_auth": float(bruto.get("tentativas", 0)),
        "portas_distintas": float(scan.get("quantidade", len(scan.get("portas", [])))),
        # O formato legado não carrega a blacklist completa: a detecção registrada
        # no próprio resumo serve como sinal de blacklist.
        "ip_blacklist": float("blacklist" in deteccoes),
        "erros_web": float(detalhes.get("erros_web", 0)),
        "eventos_total": float(detalhes.get("eventos_total", 0)),
        "bloqueios_firewall": float(detalhes.get("bloqueios_firewall", 0)),
    }
