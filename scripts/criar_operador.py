"""
scripts/criar_operador.py — Cria o primeiro operador da plataforma no MySQL.

A senha nunca vai na linha de comando nem no código: ela é pedida no
terminal (getpass) ou lida da variável de ambiente OPERADOR_SENHA.

Uso (na raiz do projeto):
    python -m scripts.criar_operador --nome "Analista SOC" --email analista@securapy.com
    docker compose exec api python -m scripts.criar_operador --nome ... --email ...
"""

import argparse
import os
import sys
from getpass import getpass

from db import mysql_repo


def main(argumentos=None, ler_senha=getpass):
    analisador = argparse.ArgumentParser(description="Cria um operador no MySQL.")
    analisador.add_argument("--nome", required=True)
    analisador.add_argument("--email", required=True)
    analisador.add_argument("--nivel", type=int, default=3, help="nível de acesso de 1 a 5")
    dados = analisador.parse_args(argumentos)

    senha = os.environ.get("OPERADOR_SENHA") or ler_senha("Senha (mínimo 8 caracteres): ")

    conexao = mysql_repo.conectar()
    if conexao is None:
        print("[ERRO] Não foi possível conectar ao MySQL.")
        return 1
    try:
        sucesso, mensagem = mysql_repo.cadastrar_usuario(
            conexao, dados.nome, dados.email, senha, dados.nivel)
    finally:
        conexao.close()
    print(mensagem)
    return 0 if sucesso else 1


if __name__ == "__main__":
    sys.exit(main())
