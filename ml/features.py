"""Monta atributos numéricos por IP a partir dos eventos do núcleo SecuraPy."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping

from core.correlacao import agrupar_falhas_por_ip, maior_rajada
from core.detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
)
from core.regras import ler_detalhe

JANELA_BRUTE_FORCE_SEGUNDOS = 60

# Esta ordem é o contrato usado tanto no treinamento quanto na classificação.
FEATURES = (
    "falhas_auth",
    "maior_rajada_60s",
    "portas_distintas",
    "erros_web_4xx",
    "eventos_total",
    "ip_blacklist",
)


def montar_features(eventos: Iterable[Mapping]) -> dict[str, list[float]]:
    """Retorna {ip: vetor} com as features na ordem definida em ``FEATURES``.

    ``eventos`` deve conter os dicionários normalizados por
    ``core.coletor.carregar_todos_os_logs``. O cálculo de brute force,
    port scan, blacklist, rajada temporal e leitura dos detalhes reaproveita
    funções já existentes no núcleo A.
    """
    lista_eventos = list(eventos)
    if not lista_eventos:
        return {}

    brute_force = detectar_brute_force(lista_eventos, threshold=1)
    port_scan = detectar_port_scan(lista_eventos, threshold=1)
    ips_blacklist, _ = verificar_blacklist(lista_eventos)
    falhas_por_ip = agrupar_falhas_por_ip(lista_eventos)

    eventos_por_ip: dict[str, int] = defaultdict(int)
    erros_web_por_ip: dict[str, int] = defaultdict(int)
    for evento in lista_eventos:
        ip = evento["ip"]
        eventos_por_ip[ip] += 1

        if evento["fonte"] == "web":
            status = ler_detalhe(evento, "status")
            if status is not None and status.isdigit() and 400 <= int(status) <= 499:
                erros_web_por_ip[ip] += 1

    ips = eventos_por_ip.keys()
    features_por_ip: dict[str, list[float]] = {}
    for ip in ips:
        falhas = brute_force.get(ip, {}).get("tentativas", 0)
        horarios = falhas_por_ip.get(ip, [])
        maior_rajada_60s = maior_rajada(
            horarios, JANELA_BRUTE_FORCE_SEGUNDOS
        )[0] if horarios else 0
        portas_distintas = port_scan.get(ip, {}).get("quantidade", 0)
        erros_web = erros_web_por_ip.get(ip, 0)
        eventos_total = eventos_por_ip[ip]
        em_blacklist = int(ip in ips_blacklist)

        features_por_ip[ip] = [
            float(falhas),
            float(maior_rajada_60s),
            float(portas_distintas),
            float(erros_web),
            float(eventos_total),
            float(em_blacklist),
        ]

    return features_por_ip


if __name__ == "__main__":
    from pathlib import Path

    from core.coletor import carregar_todos_os_logs

    pasta_projeto = Path(__file__).resolve().parents[1]
    eventos = carregar_todos_os_logs(str(pasta_projeto / "logs"))
    dados = montar_features(eventos)
    print(f"Eventos lidos: {len(eventos)}")
    print(f"IPs com features: {len(dados)}")
    print(f"Ordem das colunas: {', '.join(FEATURES)}")
    print(f"Features de 185.220.101.1: {dados.get('185.220.101.1')}")