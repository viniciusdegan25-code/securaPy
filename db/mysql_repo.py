"""
db/mysql_repo.py — Usuários e autenticação de operadores no MySQL (Módulo B).

Tabela 'usuarios': cadastro (CRUD) dos analistas que usam o SecuraPy.
Regras de segurança:
- TODAS as queries são parametrizadas (%s): bloqueia SQL Injection.
- A senha NUNCA é guardada: guardamos só o hash PBKDF2 com salt.
- O login responde igual para "usuário não existe" e "senha errada"
  (não revela quais emails estão cadastrados).
"""

import hashlib
import hmac
import os

import pymysql
from pymysql.cursors import DictCursor

from db.configuracao import ler_variavel

ITERACOES_HASH = 200_000
NIVEIS_VALIDOS = range(1, 6)  # 1 a 5

SQL_CRIAR_TABELA = """
    CREATE TABLE IF NOT EXISTS usuarios (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        nome         VARCHAR(100) NOT NULL,
        email        VARCHAR(150) NOT NULL UNIQUE,
        senha_hash   VARCHAR(255) NOT NULL,
        nivel_acesso TINYINT      NOT NULL,
        criado_em    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK (nivel_acesso BETWEEN 1 AND 5)
    )
"""


# --------------------------------------------------------------------
# Conexão
# --------------------------------------------------------------------

def conectar():
    """
    Conecta ao MySQL com os dados do .env e garante a tabela 'usuarios'.
    Retorna a conexão ou None se não for possível conectar.
    """
    try:
        conexao = pymysql.connect(
            host=ler_variavel("MYSQL_HOST", "localhost"),
            port=int(ler_variavel("MYSQL_PORTA", "3306")),
            user=ler_variavel("MYSQL_USUARIO", "root"),
            password=ler_variavel("MYSQL_SENHA", ""),
            database=ler_variavel("MYSQL_BANCO", "securapy"),
            charset="utf8mb4",
            cursorclass=DictCursor,
            connect_timeout=5,
        )
    except pymysql.MySQLError as erro:
        # Mostra só o tipo do erro, sem detalhes de host ou senha
        print(f"[AVISO] MySQL indisponível ({erro.__class__.__name__}).")
        return None

    if _executar(conexao, SQL_CRIAR_TABELA) is None:
        conexao.close()
        return None
    print("[OK] Conectado ao MySQL (tabela 'usuarios' pronta).")
    return conexao


def _executar(conexao, sql, parametros=(), buscar=None):
    """
    Executa um comando SQL PARAMETRIZADO e confirma (commit).
    - buscar="um"    -> retorna uma linha (dict) ou None
    - buscar="todos" -> retorna lista de linhas
    - buscar=None    -> retorna quantas linhas foram afetadas
    Em caso de erro, desfaz (rollback) e retorna None.
    Erros de email duplicado (IntegrityError) são repassados.
    """
    try:
        with conexao.cursor() as cursor:
            afetadas = cursor.execute(sql, parametros)
            if buscar == "um":
                resultado = cursor.fetchone()
            elif buscar == "todos":
                resultado = cursor.fetchall()
            else:
                resultado = afetadas
        conexao.commit()
        return resultado
    except pymysql.IntegrityError:
        conexao.rollback()
        raise
    except pymysql.MySQLError as erro:
        conexao.rollback()
        print(f"[ERRO] Falha no MySQL ({erro.__class__.__name__}).")
        return None


# --------------------------------------------------------------------
# Hash de senha (PBKDF2 + salt)
# --------------------------------------------------------------------

def gerar_hash_senha(senha):
    """
    Gera o hash da senha com PBKDF2-SHA256, um salt aleatório e
    200 mil iterações (lento de propósito, para dificultar força bruta).
    Formato guardado: "pbkdf2_sha256$iteracoes$salt$hash"
    """
    salt = os.urandom(16)
    resumo = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, ITERACOES_HASH)
    return f"pbkdf2_sha256${ITERACOES_HASH}${salt.hex()}${resumo.hex()}"


def conferir_senha(senha, hash_guardado):
    """Confere a senha digitada contra o hash guardado. Retorna True/False."""
    try:
        _, iteracoes, salt_hex, resumo_hex = hash_guardado.split("$")
    except ValueError:
        return False
    resumo = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iteracoes))
    # compare_digest compara em tempo constante (não vaza pelo tempo)
    return hmac.compare_digest(resumo.hex(), resumo_hex)


# Hash "falso" usado quando o email não existe: assim o login demora
# o mesmo tempo nos dois casos e não revela se o usuário existe.
HASH_FALSO = gerar_hash_senha("senha-que-nao-existe")


# --------------------------------------------------------------------
# Validação de entrada
# --------------------------------------------------------------------

def validar_dados(nome, email, senha, nivel):
    """Retorna uma mensagem de erro, ou None se estiver tudo certo."""
    if not nome or not nome.strip():
        return "Nome é obrigatório."
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return "Email inválido."
    if not senha or len(senha) < 8:
        return "A senha deve ter pelo menos 8 caracteres."
    if nivel not in NIVEIS_VALIDOS:
        return "Nível de acesso deve ser de 1 a 5."
    return None


# --------------------------------------------------------------------
# CRUD de usuários
# --------------------------------------------------------------------

def cadastrar_usuario(conexao, nome, email, senha, nivel):
    """
    CREATE: cadastra um usuário. Retorna (True, mensagem) ou (False, motivo).
    Email repetido não quebra o programa: vira uma mensagem de erro.
    """
    problema = validar_dados(nome, email, senha, nivel)
    if problema:
        return False, problema

    sql = ("INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) "
           "VALUES (%s, %s, %s, %s)")
    try:
        afetadas = _executar(conexao, sql, (nome.strip(), email.strip().lower(),
                                            gerar_hash_senha(senha), nivel))
    except pymysql.IntegrityError:
        return False, "Email já cadastrado."
    if not afetadas:
        return False, "Não foi possível cadastrar."
    return True, "Usuário cadastrado."


def buscar_usuario(conexao, email):
    """READ: retorna os dados do usuário (sem o hash da senha) ou None."""
    sql = ("SELECT id, nome, email, nivel_acesso, criado_em "
           "FROM usuarios WHERE email = %s")
    return _executar(conexao, sql, (email.strip().lower(),), buscar="um")


def listar_usuarios(conexao):
    """READ: retorna todos os usuários (sem o hash da senha)."""
    sql = "SELECT id, nome, email, nivel_acesso FROM usuarios ORDER BY id"
    return _executar(conexao, sql, buscar="todos") or []


def atualizar_nivel(conexao, email, nivel):
    """UPDATE: muda o nível de acesso. Retorna True se alterou."""
    if nivel not in NIVEIS_VALIDOS:
        return False
    sql = "UPDATE usuarios SET nivel_acesso = %s WHERE email = %s"
    return bool(_executar(conexao, sql, (nivel, email.strip().lower())))


def remover_usuario(conexao, email):
    """DELETE: remove o usuário. Retorna True se removeu."""
    sql = "DELETE FROM usuarios WHERE email = %s"
    return bool(_executar(conexao, sql, (email.strip().lower(),)))


# --------------------------------------------------------------------
# Autenticação
# --------------------------------------------------------------------

def autenticar(conexao, email, senha):
    """
    Login do operador. Retorna os dados do usuário (sem hash) ou None.
    Mesma resposta (None) para email inexistente e senha errada.
    """
    sql = "SELECT id, nome, email, nivel_acesso, senha_hash FROM usuarios WHERE email = %s"
    usuario = _executar(conexao, sql, (str(email).strip().lower(),), buscar="um")

    hash_guardado = usuario["senha_hash"] if usuario else HASH_FALSO
    senha_confere = conferir_senha(str(senha), hash_guardado)
    if usuario is None or not senha_confere:
        return None

    del usuario["senha_hash"]   # nunca devolve o hash
    return usuario


# --------------------------------------------------------------------
# Teste do módulo: python -m db.mysql_repo
# --------------------------------------------------------------------
if __name__ == "__main__":
    conexao = conectar()
    if conexao is not None:
        print("\n1. Cadastro:", cadastrar_usuario(
            conexao, "Analista SOC", "analista@securapy.com", "Senha@Forte123", 3))
        print("2. Email duplicado (B3):", cadastrar_usuario(
            conexao, "Outro", "analista@securapy.com", "OutraSenha123", 1))
        print("3. Nível inválido:", cadastrar_usuario(
            conexao, "Teste", "teste@securapy.com", "Senha12345", 9))

        print("\n4. Login correto:", autenticar(conexao, "analista@securapy.com", "Senha@Forte123"))
        print("5. Senha errada:", autenticar(conexao, "analista@securapy.com", "errada123"))
        print("6. Usuário inexistente:", autenticar(conexao, "ninguem@securapy.com", "errada123"))
        print("7. SQL Injection (B4):", autenticar(conexao, "' OR '1'='1", "' OR '1'='1"))

        print("\n8. Atualizar nível para 5:", atualizar_nivel(conexao, "analista@securapy.com", 5))
        print("9. Usuários:", listar_usuarios(conexao))
        conexao.close()