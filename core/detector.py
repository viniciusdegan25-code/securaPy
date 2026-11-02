"""
core/detector.py — Detector de anomalias e ataques (Módulo A).

Enquanto o motor de regras olha um evento por vez, o detector olha o
CONJUNTO de eventos e encontra padrões que só aparecem juntos:
    - brute force : muitas falhas de login do mesmo IP
    - port scan   : o mesmo IP tentando várias portas diferentes
    - blacklist   : IPs maliciosos já conhecidos
No final, junta tudo num resumo por IP, ordenado por gravidade.
"""

import os

# IPs maliciosos conhecidos (set: busca rápida e operações de conjunto)
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

# Níveis em ordem crescente (tupla: a ordem nunca muda)
NIVEIS = ("BAIXA", "MEDIA", "ALTA", "CRITICA")


def _ler_detalhe(evento, chave):
    """Pega um valor de 'detalhes' (ex.: 'dport' -> '22')."""
    for pedaco in evento["detalhes"].split():
        if pedaco.startswith(chave + "="):
            return pedaco.split("=", 1)[1]
    return None


# --------------------------------------------------------------------
# Brute force
# --------------------------------------------------------------------

def severidade_brute_force(tentativas):
    """>20: CRITICA, >=10: ALTA, >=5: MEDIA, abaixo: BAIXA."""
    if tentativas > 20:
        return "CRITICA"
    if tentativas >= 10:
        return "ALTA"
    if tentativas >= 5:
        return "MEDIA"
    return "BAIXA"


def detectar_brute_force(eventos, threshold=5):
    """
    Conta as falhas de login (auth + FAIL) por IP.
    Retorna só os IPs com 'threshold' falhas ou mais:
    {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    """
    falhas = {}
    for evento in eventos:
        if evento["fonte"] == "auth" and evento["tipo"] == "FAIL":
            dados = falhas.setdefault(evento["ip"], {"tentativas": 0, "usuarios": set()})
            dados["tentativas"] += 1
            dados["usuarios"].add(_ler_detalhe(evento, "usuario"))

    resultado = {}
    for ip, dados in falhas.items():
        if dados["tentativas"] >= threshold:
            resultado[ip] = {
                "tentativas": dados["tentativas"],
                "usuarios": sorted(dados["usuarios"]),
                "severidade": severidade_brute_force(dados["tentativas"]),
            }
    return resultado


# --------------------------------------------------------------------
# Port scan
# --------------------------------------------------------------------

def severidade_port_scan(quantidade):
    """>=10 portas: CRITICA, >=6: ALTA, abaixo: MEDIA."""
    if quantidade >= 10:
        return "CRITICA"
    if quantidade >= 6:
        return "ALTA"
    return "MEDIA"


def detectar_port_scan(eventos, threshold=3):
    """
    Conta as portas DISTINTAS bloqueadas por IP (o set elimina repetidas).
    Retorna só os IPs com 'threshold' portas ou mais:
    {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
    """
    portas_por_ip = {}
    for evento in eventos:
        if evento["fonte"] == "firewall" and evento["tipo"] == "BLOCK":
            porta = _ler_detalhe(evento, "dport")
            portas_por_ip.setdefault(evento["ip"], set()).add(int(porta))

    resultado = {}
    for ip, portas in portas_por_ip.items():
        if len(portas) >= threshold:
            resultado[ip] = {
                "portas": portas,
                "quantidade": len(portas),
                "severidade": severidade_port_scan(len(portas)),
            }
    return resultado


# --------------------------------------------------------------------
# Blacklist
# --------------------------------------------------------------------

def verificar_blacklist(eventos, blacklist=BLACKLIST):
    """
    Cruza os IPs dos eventos com a blacklist usando INTERSEÇÃO de sets (&).
    Retorna (set de IPs maliciosos encontrados, {ip: nº de eventos}).
    """
    ips_dos_eventos = {evento["ip"] for evento in eventos}
    encontrados = ips_dos_eventos & blacklist

    contagem = {ip: 0 for ip in encontrados}
    for evento in eventos:
        if evento["ip"] in encontrados:
            contagem[evento["ip"]] += 1
    return encontrados, contagem


# --------------------------------------------------------------------
# Resumo consolidado
# --------------------------------------------------------------------

def _juntar_deteccoes(brute_force, port_scan, ips_blacklist):
    """Monta {ip: [(motivo, severidade), ...]} com todas as detecções."""
    deteccoes = {}
    for ip, dados in brute_force.items():
        motivo = f"Brute force: {dados['tentativas']} falhas de login"
        deteccoes.setdefault(ip, []).append((motivo, dados["severidade"]))
    for ip, dados in port_scan.items():
        motivo = f"Port scan: {dados['quantidade']} portas ({', '.join(map(str, sorted(dados['portas'])))})"
        deteccoes.setdefault(ip, []).append((motivo, dados["severidade"]))
    for ip in ips_blacklist:
        deteccoes.setdefault(ip, []).append(("IP em blacklist", "ALTA"))
    return deteccoes


def gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist):
    """
    Consolida as detecções num resumo por IP.
    Severidade = a maior entre as detecções, subindo UM nível para cada
    detecção extra (até CRITICA). Ex.: 3 detecções ALTA -> CRITICA.
    Retorna lista de dicts ordenada da ameaça mais grave para a menor.
    """
    resumo = []
    for ip, lista in _juntar_deteccoes(brute_force, port_scan, ips_blacklist).items():
        maior = max(NIVEIS.index(severidade) for _, severidade in lista)
        nivel = min(maior + len(lista) - 1, len(NIVEIS) - 1)
        resumo.append({
            "ip": ip,
            "motivos": [motivo for motivo, _ in lista],
            "quantidade_deteccoes": len(lista),
            "severidade": NIVEIS[nivel],
            "pontuacao": nivel,
        })
    resumo.sort(key=lambda item: (item["pontuacao"], item["quantidade_deteccoes"]), reverse=True)
    return resumo


def resumo_para_alertas(resumo, eventos):
    """
    Converte o resumo em alertas no formato padrão do SIEM, para salvar
    no banco. O horário do alerta é o do primeiro evento daquele IP.
    """
    primeiro_horario = {}
    for evento in eventos:
        if evento["ip"] not in primeiro_horario:
            primeiro_horario[evento["ip"]] = evento["timestamp"]

    return [{
        "timestamp": primeiro_horario.get(item["ip"], ""),
        "regra": "Detector de Ameaças",
        "regra_id": "DET",
        "severidade": item["severidade"],
        "ip": item["ip"],
        "descricao": " | ".join(item["motivos"]),
    } for item in resumo]


# --------------------------------------------------------------------
# Teste do módulo: python -m core.detector
# --------------------------------------------------------------------
if __name__ == "__main__":
    from core.coletor import carregar_todos_os_logs

    pasta_logs = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    eventos = carregar_todos_os_logs(pasta_logs)

    brute_force = detectar_brute_force(eventos)
    print("Brute force (A2):")
    for ip, dados in brute_force.items():
        print(f"  {ip:<16} {dados['tentativas']:>2} falhas  [{dados['severidade']}]")

    port_scan = detectar_port_scan(eventos)
    print("\nPort scan (A3):")
    for ip, dados in port_scan.items():
        print(f"  {ip:<16} {dados['quantidade']:>2} portas  [{dados['severidade']}]  {sorted(dados['portas'])}")

    ips_blacklist, contagem = verificar_blacklist(eventos)
    print(f"\nBlacklist (A4): {sorted(ips_blacklist)}")
    print(f"  Fora dos logs: {sorted(BLACKLIST - ips_blacklist)}")

    print("\nResumo de ameaças:")
    for item in gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist):
        print(f"  [{item['severidade']:<7}] {item['ip']:<16} {item['quantidade_deteccoes']} detecções: "
              f"{' | '.join(item['motivos'])}")