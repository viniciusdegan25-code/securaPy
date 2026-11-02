"""
alertas/servidor_alertas.py — Servidor TCP de alertas em tempo real (Módulo A).

Os analistas conectam um console (cliente_alertas.py) e recebem os
alertas na hora em que são gerados. Cada cliente roda numa THREAD
separada, e o dicionário de clientes é protegido por um LOCK.

Uso (na raiz do projeto):
    python -m alertas.servidor_alertas
Comandos no console do servidor:
    Enter  -> processa os logs e transmite os alertas ALTA e CRITICA
    status -> mostra clientes conectados e alertas da sessão
    sair   -> encerra o servidor (ou Ctrl+C)
"""

import os
import socket
import threading
import time
from datetime import datetime

from core.coletor import carregar_todos_os_logs
from core.detector import (detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas,
                           resumo_para_alertas, verificar_blacklist)
from core.regras import aplicar_regras, carregar_regras

PASTA_LOGS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
SEVERIDADES_TRANSMITIDAS = ("CRITICA", "ALTA")
TAMANHO_HISTORICO = 50

clientes = {}        # {conexao: "ip:porta"} -> quem está conectado
historico = []       # alertas já enviados nesta sessão (texto formatado)
lock = threading.Lock()


# --------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------

def registrar(mensagem):
    """Log de conexões e envios no console do servidor, com horário."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {mensagem}")


def enviar(conexao, texto):
    """Envia uma linha de texto. Retorna False se o cliente caiu."""
    try:
        conexao.sendall((texto + "\n").encode("utf-8"))
        return True
    except OSError:
        return False


def formatar_alerta(alerta_dict):
    """
    Converte o dict do alerta em texto para exibição.
    Formato: [HORA] [SEVERIDADE] REGRA — IP — Descrição
    """
    hora = alerta_dict["timestamp"][11:19] or alerta_dict["timestamp"]
    return (f"[{hora}] [{alerta_dict['severidade']}] {alerta_dict['regra']} — "
            f"{alerta_dict['ip']} — {alerta_dict['descricao']}")


def remover_cliente(conexao):
    """Tira o cliente do dicionário e fecha a conexão, sem travar."""
    with lock:
        endereco = clientes.pop(conexao, None)
    try:
        conexao.close()
    except OSError:
        pass  # já estava fechada
    if endereco:
        registrar(f"Cliente desconectado: {endereco}")


# --------------------------------------------------------------------
# Broadcast e comandos
# --------------------------------------------------------------------

def broadcast_alerta(alerta):
    """Envia o alerta formatado para TODOS os clientes conectados."""
    texto = formatar_alerta(alerta)
    with lock:
        historico.append(texto)
        del historico[:-TAMANHO_HISTORICO]      # guarda só os últimos 50
        destinos = list(clientes)

    caidos = [conexao for conexao in destinos if not enviar(conexao, texto)]
    for conexao in caidos:
        remover_cliente(conexao)

    entregues = len(destinos) - len(caidos)
    registrar(f"Alerta enviado para {entregues} clientes: [{alerta['severidade']}] "
              f"{alerta['regra']} — {alerta['ip']}")
    return entregues


def responder_comando(conexao, comando):
    """Executa um comando do cliente. Retorna False quando ele quer sair."""
    if comando == "/status":
        with lock:
            resposta = f"Clientes conectados: {len(clientes)} | Alertas na sessão: {len(historico)}"
        enviar(conexao, resposta)
    elif comando == "/historico":
        with lock:
            ultimos = historico[-10:]
        enviar(conexao, "\n".join(ultimos) if ultimos else "Nenhum alerta nesta sessão.")
    elif comando == "/sair":
        enviar(conexao, "Até logo!")
        return False
    else:
        enviar(conexao, "Comando desconhecido. Use: /status, /historico, /sair")
    return True


def tratar_cliente(conexao, endereco):
    """Conversa com UM cliente (roda numa thread própria)."""
    nome = f"{endereco[0]}:{endereco[1]}"
    with lock:
        clientes[conexao] = nome
    registrar(f"Cliente conectado: {nome}")
    enviar(conexao, "Conectado ao SecuraPy SIEM. Comandos: /status, /historico, /sair")

    try:
        ativo = True
        while ativo:
            dados = conexao.recv(1024)
            if not dados:           # cliente fechou a conexão
                break
            for comando in dados.decode("utf-8", errors="replace").split("\n"):
                if comando.strip() and ativo:
                    ativo = responder_comando(conexao, comando.strip())
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass  # cliente caiu: tratado no finally
    finally:
        remover_cliente(conexao)


# --------------------------------------------------------------------
# Servidor
# --------------------------------------------------------------------

def aceitar_conexoes(servidor):
    """Fica aceitando clientes e cria uma thread para cada um."""
    while True:
        try:
            conexao, endereco = servidor.accept()
        except OSError:
            break  # servidor foi fechado
        threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True).start()


def processar_e_transmitir(pasta_logs=PASTA_LOGS):
    """Roda o núcleo (coletor, regras, detector) e transmite os alertas graves."""
    eventos = carregar_todos_os_logs(pasta_logs)
    alertas = aplicar_regras(eventos, carregar_regras())
    brute_force, port_scan = detectar_brute_force(eventos), detectar_port_scan(eventos)
    ips_blacklist, _ = verificar_blacklist(eventos)
    alertas += resumo_para_alertas(gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist), eventos)

    graves = [a for a in alertas if a["severidade"] in SEVERIDADES_TRANSMITIDAS]
    graves.sort(key=lambda a: SEVERIDADES_TRANSMITIDAS.index(a["severidade"]))
    for alerta in graves:
        broadcast_alerta(alerta)
        time.sleep(0.3)  # espaça os envios, como alertas chegando em tempo real
    return len(graves)


def encerrar(servidor):
    """Avisa todos os clientes e fecha o servidor."""
    with lock:
        conexoes = list(clientes)
    for conexao in conexoes:
        enviar(conexao, "[SERVIDOR] Servidor encerrado. Desconectando...")
        remover_cliente(conexao)
    servidor.close()
    print("Servidor encerrado.")


def console_do_servidor():
    """Lê os comandos do operador no terminal do servidor."""
    while True:
        comando = input().strip().lower()
        if comando == "sair":
            return
        if comando == "status":
            with lock:
                print(f"Clientes: {len(clientes)} | Alertas na sessão: {len(historico)}")
        else:
            print(f"{processar_e_transmitir()} alertas transmitidos.")


def iniciar_servidor(host="0.0.0.0", porta=9999):
    """Inicia o servidor TCP e fica aguardando conexões."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        servidor.bind((host, porta))
    except OSError:
        print(f"[ERRO] A porta {porta} já está em uso. Feche o outro servidor.")
        return
    servidor.listen()

    print("=== Servidor de Alertas SecuraPy ===")
    print(f"Rodando em {host}:{porta}")
    print("Aguardando conexões... (Enter = transmitir alertas | status | sair)\n")
    threading.Thread(target=aceitar_conexoes, args=(servidor,), daemon=True).start()

    try:
        console_do_servidor()
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        encerrar(servidor)


if __name__ == "__main__":
    iniciar_servidor()