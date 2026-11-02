"""
core/correlacao.py — BÔNUS: Correlação temporal de brute force (+0,20).

O detector comum (core/detector.py) conta o TOTAL de falhas por IP.
Aqui consideramos o TEMPO: mais de 5 logins falhos do mesmo IP
dentro de uma janela de 60 segundos.
(10 falhas em uma semana = alguém que esquece a senha;
 10 falhas em 30 segundos = robô testando senhas.)
"""

import os
from datetime import datetime

FORMATO_DATA = "%Y-%m-%d %H:%M:%S"
PASTA_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_LOGS = os.path.join(PASTA_PROJETO, "logs")


def agrupar_falhas_por_ip(eventos):
    """
    Junta os horários das falhas de login (auth + FAIL) de cada IP.
    Retorna dict: {ip: [datetime, datetime, ...]} em ordem de horário.
    """
    falhas_por_ip = {}
    for evento in eventos:
        if evento["fonte"] == "auth" and evento["tipo"] == "FAIL":
            horario = datetime.strptime(evento["timestamp"], FORMATO_DATA)
            falhas_por_ip.setdefault(evento["ip"], []).append(horario)

    for horarios in falhas_por_ip.values():
        horarios.sort()
    return falhas_por_ip


def maior_rajada(horarios, janela_segundos):
    """
    Descobre o maior número de falhas que cabem numa janela de tempo.
    Para cada falha, conta quantas acontecem nos 'janela_segundos' seguintes.
    Retorna (quantidade, horario_inicio, horario_fim).
    """
    melhor = (0, None, None)
    for i, inicio in enumerate(horarios):
        quantidade = 0
        fim = inicio
        for horario in horarios[i:]:
            if (horario - inicio).total_seconds() <= janela_segundos:
                quantidade += 1
                fim = horario
        if quantidade > melhor[0]:
            melhor = (quantidade, inicio, fim)
    return melhor


def classificar_severidade(quantidade):
    """Mesma escala do enunciado: >20 CRITICA, >10 ALTA, >5 MEDIA."""
    if quantidade > 20:
        return "CRITICA"
    if quantidade > 10:
        return "ALTA"
    if quantidade > 5:
        return "MEDIA"
    return "BAIXA"


def detectar_brute_force_temporal(eventos, janela_segundos=60, threshold=5):
    """
    Detecta IPs com MAIS de 'threshold' falhas dentro de 'janela_segundos'.
    Retorna lista de alertas no formato padrão do SIEM.
    """
    alertas = []
    for ip, horarios in agrupar_falhas_por_ip(eventos).items():
        quantidade, inicio, fim = maior_rajada(horarios, janela_segundos)
        if quantidade <= threshold:
            continue

        duracao = int((fim - inicio).total_seconds())
        alertas.append({
            "timestamp": inicio.strftime(FORMATO_DATA),
            "regra": "Brute Force Temporal",
            "regra_id": "BFT",
            "severidade": classificar_severidade(quantidade),
            "ip": ip,
            "descricao": f"{quantidade} falhas em {duracao}s (janela de {janela_segundos}s)",
        })
    return alertas


if __name__ == "__main__":
    from core.coletor import carregar_todos_os_logs

    eventos = carregar_todos_os_logs(PASTA_LOGS)
    for janela in (60, 10):
        print(f"\n=== Mais de 5 falhas em {janela} segundos ===")
        alertas = detectar_brute_force_temporal(eventos, janela_segundos=janela)
        if len(alertas) == 0:
            print("  Nenhum ataque detectado.")
        for alerta in alertas:
            print(f"  [{alerta['severidade']}] {alerta['ip']} — {alerta['descricao']}")