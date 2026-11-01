"""
coletor.py — Módulo 1: Coletor de Logs do SecuraPy.

Lê os arquivos de log (auth, firewall, web), interpreta cada linha
e transforma tudo em eventos normalizados (dicionários com as mesmas chaves).
"""

import os


def extrair_valor(pedaco, chave):
    """
    Recebe algo como 'ip=185.220.101.1' e a chave 'ip'.
    Retorna só o valor: '185.220.101.1'.
    Se o pedaço não começar com 'chave=', a linha está errada.
    """
    if not pedaco.startswith(chave + "="):
        raise ValueError(f"esperava '{chave}=...', veio '{pedaco}'")
    return pedaco.split("=", 1)[1]


def conferir_tamanho(pedacos, esperado):
    """Confere se a linha tem a quantidade certa de pedaços."""
    if len(pedacos) != esperado:
        raise ValueError(f"esperava {esperado} campos, veio {len(pedacos)}")


def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log e retorna dict normalizado."""
    pedacos = linha.strip().split()
    conferir_tamanho(pedacos, 5)

    tipo = pedacos[2]
    if tipo not in ("OK", "FAIL"):
        raise ValueError(f"tipo desconhecido: '{tipo}'")

    usuario = extrair_valor(pedacos[3], "usuario")
    ip = extrair_valor(pedacos[4], "ip")

    evento = {
        "timestamp": f"{pedacos[0]} {pedacos[1]}",
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": f"usuario={usuario}",
        "linha_original": linha.strip(),
    }
    return evento


def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log e retorna dict normalizado."""
    pedacos = linha.strip().split()
    conferir_tamanho(pedacos, 7)

    tipo = pedacos[2]
    if tipo not in ("ALLOW", "BLOCK"):
        raise ValueError(f"ação desconhecida: '{tipo}'")

    proto = extrair_valor(pedacos[3], "proto")
    ip = extrair_valor(pedacos[4], "src")
    destino = extrair_valor(pedacos[5], "dst")
    porta = extrair_valor(pedacos[6], "dport")

    evento = {
        "timestamp": f"{pedacos[0]} {pedacos[1]}",
        "fonte": "firewall",
        "tipo": tipo,
        "ip": ip,
        "detalhes": f"proto={proto} dst={destino} dport={porta}",
        "linha_original": linha.strip(),
    }
    return evento


def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log e retorna dict normalizado."""
    pedacos = linha.strip().split()
    conferir_tamanho(pedacos, 6)

    metodo = pedacos[2]
    url = extrair_valor(pedacos[3], "url")
    ip = extrair_valor(pedacos[4], "ip")
    status = extrair_valor(pedacos[5], "status")

    evento = {
        "timestamp": f"{pedacos[0]} {pedacos[1]}",
        "fonte": "web",
        "tipo": "REQUEST",
        "ip": ip,
        "detalhes": f"metodo={metodo} url={url} status={status}",
        "linha_original": linha.strip(),
    }
    return evento


# Dicionário que liga cada fonte à sua função de parsing
PARSERS = {
    "auth": parsear_linha_auth,
    "firewall": parsear_linha_firewall,
    "web": parsear_linha_web,
}

# Dicionário que diz qual fonte é cada arquivo da pasta logs/
ARQUIVOS_POR_FONTE = {
    "auth.log": "auth",
    "firewall.log": "firewall",
    "web_access.log": "web",
}


def carregar_log(caminho_arquivo, fonte):
    """
    Lê um arquivo de log e retorna lista de eventos normalizados.
    - caminho_arquivo: caminho do arquivo
    - fonte: "auth", "firewall" ou "web"
    Linhas mal formatadas são ignoradas com aviso.
    Retorna lista vazia se o arquivo não existir.
    """
    parser = PARSERS[fonte]
    eventos = []

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:
            for numero, linha in enumerate(arquivo, start=1):
                if linha.strip() == "":
                    continue
                try:
                    eventos.append(parser(linha))
                except ValueError as erro:
                    print(f"[AVISO] {caminho_arquivo}, linha {numero} ignorada: {erro}")
    except FileNotFoundError:
        print(f"[ERRO] Arquivo não encontrado: {caminho_arquivo}")
        return []

    if len(eventos) == 0:
        print(f"[INFO] O arquivo {caminho_arquivo} está vazio.")

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """
    Lê todos os arquivos de log da pasta e retorna lista unificada,
    ordenada por horário. Usa os.listdir() para encontrar os arquivos.
    """
    try:
        nomes_arquivos = os.listdir(pasta_logs)
    except FileNotFoundError:
        print(f"[ERRO] Pasta não encontrada: {pasta_logs}")
        return []

    todos_eventos = []
    for nome in nomes_arquivos:
        if nome not in ARQUIVOS_POR_FONTE:
            continue
        fonte = ARQUIVOS_POR_FONTE[nome]
        caminho = os.path.join(pasta_logs, nome)
        todos_eventos.extend(carregar_log(caminho, fonte))

    todos_eventos.sort(key=lambda evento: evento["timestamp"])
    return todos_eventos


def contar_por_fonte(eventos):
    """Retorna um dicionário com a quantidade de eventos de cada fonte."""
    contagem = {"auth": 0, "firewall": 0, "web": 0}
    for evento in eventos:
        contagem[evento["fonte"]] += 1
    return contagem


if __name__ == "__main__":
    eventos = carregar_todos_os_logs("logs")
    contagem = contar_por_fonte(eventos)

    print(f"{contagem['auth']} eventos de auth, "
          f"{contagem['firewall']} de firewall, "
          f"{contagem['web']} de web. Total: {len(eventos)} eventos")

    print("\nPrimeiros 3 eventos (em ordem de horário):")
    for evento in eventos[:3]:
        print(f"  {evento['timestamp']} | {evento['fonte']:<8} | {evento['tipo']:<7} | {evento['ip']}")