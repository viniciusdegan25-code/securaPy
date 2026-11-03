"""Cadastro interativo do primeiro operador do dashboard."""

from getpass import getpass

from db import mysql_repo


def main() -> int:
    nome = input("Nome do operador: ").strip()
    email = input("Email: ").strip()
    senha = getpass("Senha (mínimo 8 caracteres): ")
    confirmacao = getpass("Repita a senha: ")
    if senha != confirmacao:
        print("As senhas não coincidem.")
        return 1

    conexao = mysql_repo.conectar()
    if conexao is None:
        print("Não foi possível conectar ao MySQL.")
        return 1
    try:
        sucesso, mensagem = mysql_repo.cadastrar_usuario(
            conexao, nome, email, senha, nivel=3
        )
        print(mensagem)
        return 0 if sucesso else 1
    finally:
        conexao.close()


if __name__ == "__main__":
    raise SystemExit(main())
