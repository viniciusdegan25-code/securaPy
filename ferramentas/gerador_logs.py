"""
ferramentas/gerador_logs.py — Geração automática de logs de teste.

Cria os 3 arquivos de log (auth, firewall, web) com tráfego normal
e ataques injetados (brute force, port scan e ataques web).
Grava em 'logs_gerados/' para NÃO apagar os logs do enunciado.
Útil para testar o SIEM e para gerar dados de treino do ML (Pessoa 2):
o 'gabarito' diz quais IPs são atacantes.

Uso (na raiz do projeto):
    python -m ferramentas.gerador_logs
"""

import os
import random
from datetime import datetime, timedelta

FORMATO_DATA = "%Y-%m-%d %H:%M:%S"

PASTA_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_SAIDA = os.path.join(PASTA_PROJETO, "logs_gerados")

USUARIOS_NORMAIS = ["carlos", "ana", "bruno", "diana", "eduardo"]
USUARIOS_ALVO = ["root", "admin", "sa", "oracle", "test", "guest"]
PORTAS_CRITICAS = [21, 22, 23, 139, 445, 1433, 3306, 3389, 5432, 8080]
URLS_NORMAIS = ["/index.html", "/login", "/api/data", "/contato"]
URLS_MALICIOSAS = ["/../../etc/passwd", "/search?q=<script>alert(1)</script>",
                   "/wp-admin", "/phpmyadmin", "/shell.php", "/.env"]


def ip_interno():
    """Gera um IP de rede interna (funcionário)."""
    return f"192.168.1.{random.randint(2, 254)}"


def ip_externo():
    """Gera um IP público aleatório (atacante)."""
    return (f"{random.choice([45, 91, 185, 203])}.{random.randint(0, 255)}."
            f"{random.randint(0, 255)}.{random.randint(1, 254)}")


def gerar_trafego_normal(inicio, quantidade):
    """
    Gera eventos legítimos. Retorna dict {fonte: [(horario, linha), ...]}.
    Cerca de 10% dos logins falham (alguém errou a senha): isso é NORMAL
    e deixa os dados mais realistas para o ML.
    """
    logs = {"auth": [], "firewall": [], "web": []}
    for _ in range(quantidade):
        horario = inicio + timedelta(seconds=random.randint(0, 3600))
        texto = horario.strftime(FORMATO_DATA)
        ip = ip_interno()
        tipo = "FAIL" if random.random() < 0.1 else "OK"

        logs["auth"].append((horario, f"{texto} {tipo} usuario={random.choice(USUARIOS_NORMAIS)} ip={ip}"))
        logs["firewall"].append((horario, f"{texto} ALLOW proto=TCP src={ip} dst=10.0.0.1 dport=443"))
        logs["web"].append((horario, f"{texto} GET url={random.choice(URLS_NORMAIS)} ip={ip} status=200"))
    return logs


def injetar_brute_force(logs, inicio):
    """Atacante tenta de 8 a 20 senhas em poucos segundos."""
    ip = ip_externo()
    horario = inicio
    for _ in range(random.randint(8, 20)):
        horario += timedelta(seconds=random.randint(1, 3))
        usuario = random.choice(USUARIOS_ALVO)
        logs["auth"].append((horario, f"{horario.strftime(FORMATO_DATA)} FAIL usuario={usuario} ip={ip}"))
    return ip


def injetar_port_scan(logs, inicio):
    """Atacante testa várias portas críticas diferentes."""
    ip = ip_externo()
    horario = inicio
    for porta in random.sample(PORTAS_CRITICAS, 6):
        horario += timedelta(seconds=random.randint(1, 3))
        logs["firewall"].append((horario, f"{horario.strftime(FORMATO_DATA)} BLOCK proto=TCP "
                                          f"src={ip} dst=10.0.0.1 dport={porta}"))
    return ip


def injetar_ataque_web(logs, inicio):
    """Atacante acessa URLs maliciosas (path traversal, XSS, reconhecimento)."""
    ip = ip_externo()
    horario = inicio
    for url in random.sample(URLS_MALICIOSAS, 4):
        horario += timedelta(seconds=random.randint(1, 3))
        logs["web"].append((horario, f"{horario.strftime(FORMATO_DATA)} GET url={url} ip={ip} status=404"))
    return ip


def salvar_logs(logs, pasta):
    """Ordena por horário e grava os 3 arquivos na pasta."""
    nomes = {"auth": "auth.log", "firewall": "firewall.log", "web": "web_access.log"}
    os.makedirs(pasta, exist_ok=True)

    for fonte, linhas in logs.items():
        linhas.sort()
        caminho = os.path.join(pasta, nomes[fonte])
        with open(caminho, "w", encoding="utf-8") as arquivo:
            for _, linha in linhas:
                arquivo.write(linha + "\n")


def gerar_logs(quantidade_normal=50, semente=None, pasta=PASTA_SAIDA):
    """
    Gera os logs completos (normal + ataques) e salva na pasta.
    A 'semente' faz os logs saírem sempre iguais (bom para o vídeo).
    Retorna o gabarito: {"brute_force": ip, "port_scan": ip, "ataque_web": ip}.
    """
    random.seed(semente)
    inicio = datetime(2025, 2, 20, 9, 0, 0)
    logs = gerar_trafego_normal(inicio, quantidade_normal)

    gabarito = {
        "brute_force": injetar_brute_force(logs, inicio + timedelta(minutes=random.randint(5, 50))),
        "port_scan": injetar_port_scan(logs, inicio + timedelta(minutes=random.randint(5, 50))),
        "ataque_web": injetar_ataque_web(logs, inicio + timedelta(minutes=random.randint(5, 50))),
    }

    salvar_logs(logs, pasta)
    return gabarito


if __name__ == "__main__":
    from core.coletor import carregar_todos_os_logs, contar_por_fonte
    from core.correlacao import detectar_brute_force_temporal
    from core.detector import detectar_port_scan

    gabarito = gerar_logs(quantidade_normal=50, semente=42)
    print("=== Logs gerados em 'logs_gerados/' ===")
    print("Ataques injetados (gabarito):")
    for tipo, ip in gabarito.items():
        print(f"  {tipo:<12} -> {ip}")

    eventos = carregar_todos_os_logs(PASTA_SAIDA)
    print(f"\nO coletor leu: {contar_por_fonte(eventos)} -> total {len(eventos)}")

    print("\nO SIEM detectou:")
    for alerta in detectar_brute_force_temporal(eventos):
        print(f"  Brute force [{alerta['severidade']}] {alerta['ip']} — {alerta['descricao']}")
    for ip, dados in detectar_port_scan(eventos).items():
        print(f"  Port scan   [{dados['severidade']}] {ip} — {dados['quantidade']} portas")