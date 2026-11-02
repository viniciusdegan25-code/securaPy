"""
db/configuracao.py — Leitura das configurações dos bancos.

Lê as variáveis do arquivo .env (na raiz do projeto).
Assim nenhuma senha fica escrita no código.
"""

import os

from dotenv import load_dotenv

# Raiz do projeto = a pasta acima de db/
PASTA_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_LOGS = os.path.join(PASTA_PROJETO, "logs")
ARQUIVO_ENV = os.path.join(PASTA_PROJETO, ".env")

load_dotenv(ARQUIVO_ENV)


def ler_variavel(nome, padrao=None):
    """
    Retorna o valor de uma variável de ambiente.
    Se ela não existir, retorna o 'padrao' (ou None).
    """
    return os.environ.get(nome, padrao)


def esconder_senha(endereco):
    """
    Troca a senha de um endereço por '****', para poder exibir com segurança.
    Ex.: mongodb+srv://user:abc123@host  ->  mongodb+srv://user:****@host
    """
    if endereco is None or "@" not in endereco or "://" not in endereco:
        return endereco
    protocolo, resto = endereco.split("://", 1)
    credenciais, servidor = resto.split("@", 1)
    usuario = credenciais.split(":", 1)[0]
    return f"{protocolo}://{usuario}:****@{servidor}"


if __name__ == "__main__":
    print("Arquivo .env encontrado:", os.path.exists(ARQUIVO_ENV))
    print("MONGO_URI  :", esconder_senha(ler_variavel("MONGO_URI")))
    print("MONGO_BANCO:", ler_variavel("MONGO_BANCO"))
    print("MYSQL_HOST :", ler_variavel("MYSQL_HOST"))