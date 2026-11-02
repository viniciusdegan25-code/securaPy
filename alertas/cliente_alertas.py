"""
alertas/cliente_alertas.py — Console do analista (Módulo A).

Conecta ao servidor de alertas e mostra cada alerta assim que chega.
Uma thread fica RECEBENDO; a principal fica lendo os comandos digitados.

Uso (na raiz do projeto):
    python -m alertas.cliente_alertas
Comandos: /status, /historico, /sair
"""

import socket
import threading

conectado = threading.Event()   # "bandeira" compartilhada entre as threads


def receber_alertas(cliente):
    """Thread que recebe e exibe as mensagens do servidor."""
    try:
        while True:
            dados = cliente.recv(4096)
            if not dados:
                break
            print(dados.decode("utf-8", errors="replace").rstrip(), flush=True)
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass  # conexão fechada
    if conectado.is_set():   # quem caiu foi o servidor, não o usuário
        conectado.clear()
        print("\n[!] Conexão com o servidor encerrada. Pressione Enter para sair.", flush=True)


def ler_comandos(cliente):
    """Lê o que o analista digita e envia ao servidor, até /sair."""
    while conectado.is_set():
        comando = input().strip()
        if not conectado.is_set():
            break
        if not comando:
            continue
        cliente.sendall((comando + "\n").encode("utf-8"))
        if comando == "/sair":
            break


def desconectar(cliente, receptor):
    """
    Encerra com segurança: fecha o socket e ESPERA a thread de recepção
    terminar antes de o programa sair (evita erro ao fechar o terminal).
    """
    conectado.clear()
    receptor.join(timeout=1)   # dá tempo de chegar a última resposta ("Até logo!")
    try:
        cliente.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # a conexão já tinha caído
    cliente.close()
    receptor.join(timeout=2)


def conectar_servidor(host="127.0.0.1", porta=9999):
    """Conecta ao servidor e fica recebendo alertas e enviando comandos."""
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, porta))
    except (ConnectionRefusedError, OSError):
        print(f"[ERRO] Não foi possível conectar em {host}:{porta}. O servidor está rodando?")
        return

    print(f"Conectado ao SecuraPy SIEM ({host}:{porta})")
    conectado.set()
    receptor = threading.Thread(target=receber_alertas, args=(cliente,))
    receptor.start()

    try:
        ler_comandos(cliente)
    except (KeyboardInterrupt, EOFError, OSError):
        pass
    finally:
        desconectar(cliente, receptor)


if __name__ == "__main__":
    conectar_servidor()