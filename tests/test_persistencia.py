"""Testes da persistência (Módulo B): MongoDB em memória e MySQL com conexão falsa."""

import pymysql
import pytest

from core.coletor import carregar_todos_os_logs
from analisar import executar_nucleo
from db import mongo_repo, mysql_repo
from db.configuracao import PASTA_LOGS, esconder_senha


@pytest.fixture
def banco_populado(banco):
    eventos = carregar_todos_os_logs(PASTA_LOGS)
    alertas, _ = executar_nucleo(eventos)
    mongo_repo.salvar_eventos(banco, eventos)
    mongo_repo.salvar_alertas(banco, alertas)
    return banco


# --------------------------------------------------------------------
# MongoDB
# --------------------------------------------------------------------

def test_b1_ingestao_grava_58_eventos_sem_duplicar(banco):
    eventos = carregar_todos_os_logs(PASTA_LOGS)
    assert mongo_repo.salvar_eventos(banco, eventos) == 58
    assert mongo_repo.salvar_eventos(banco, eventos) == 0   # rodar de novo não duplica
    assert mongo_repo.contar_eventos_por_fonte(banco) == {"auth": 23, "firewall": 17, "web": 18}


def test_b2_top_5_ips_com_o_atacante_no_topo(banco_populado):
    top = mongo_repo.top_ips(banco_populado, 5)
    assert len(top) == 5
    assert top[0] == {"ip": "185.220.101.1", "total": 25}


def test_busca_com_filtros_de_fonte_tipo_ip_e_periodo(banco_populado):
    resultado = mongo_repo.buscar_eventos(
        banco_populado, fonte="auth", tipo="FAIL", ip="185.220.101.1",
        inicio="2025-02-20 08:15:00", fim="2025-02-20 08:15:20")
    assert [evento["timestamp"][-2:] for evento in resultado] == ["01", "02", "06", "08", "16", "18"]
    assert all("_id" not in evento for evento in resultado)


def test_contagem_de_alertas_por_severidade(banco_populado):
    assert mongo_repo.contar_alertas_por_severidade(banco_populado) == {
        "CRITICA": 3, "ALTA": 12, "MEDIA": 20}


def test_alertas_mais_recentes_primeiro(banco_populado):
    alertas = mongo_repo.buscar_alertas(banco_populado, limite=5, mais_recentes=True)
    horarios = [alerta["timestamp"] for alerta in alertas]
    assert horarios == sorted(horarios, reverse=True)


def test_filtro_nosql_injection_vira_texto(banco_populado):
    # {"$ne": ""} seria "qualquer IP"; com str() vira um texto que não casa com nada
    assert mongo_repo.buscar_eventos(banco_populado, ip={"$ne": ""}) == []


def test_banco_fora_do_ar_nao_quebra():
    assert mongo_repo.buscar_eventos(None) == []
    assert mongo_repo.top_ips(None) == []
    assert mongo_repo.contar_alertas_por_severidade(None) == {}
    assert mongo_repo.salvar_eventos(None, [{"fonte": "auth"}]) == 0


def test_criacao_dos_indices(banco):
    assert mongo_repo.criar_indices(banco) is True


def test_conexao_reaproveitada(monkeypatch):
    criados = []

    class ClienteFalso(dict):
        def __init__(self, *args, **kwargs):
            criados.append(1)
            self.admin = self

        def command(self, nome):
            return {"ok": 1}

        def __getitem__(self, nome):
            return f"banco:{nome}"

    monkeypatch.setattr(mongo_repo, "MongoClient", ClienteFalso)
    monkeypatch.setattr(mongo_repo, "_clientes", {})
    monkeypatch.setenv("MONGO_URI", "mongodb://teste")
    assert mongo_repo.conectar() == mongo_repo.conectar() == "banco:securapy"
    assert len(criados) == 1   # um único cliente para as duas chamadas


def test_endereco_do_banco_exibido_sem_senha():
    assert esconder_senha("mongodb+srv://user:abc123@host/") == "mongodb+srv://user:****@host/"


# --------------------------------------------------------------------
# MySQL (conexão falsa: confere o SQL e os parâmetros enviados)
# --------------------------------------------------------------------

class CursorFalso:
    def __init__(self, conexao):
        self.conexao = conexao

    def __enter__(self):
        return self

    def __exit__(self, *erro):
        return False

    def execute(self, sql, parametros=()):
        self.conexao.comandos.append((sql, parametros))
        if sql.startswith("INSERT") and parametros[1] in self.conexao.emails:
            raise pymysql.IntegrityError(1062, "Duplicate entry")
        if sql.startswith("INSERT"):
            self.conexao.emails[parametros[1]] = {
                "id": len(self.conexao.emails) + 1, "nome": parametros[0], "email": parametros[1],
                "senha_hash": parametros[2], "nivel_acesso": parametros[3]}
        return 1

    def fetchone(self):
        sql, parametros = self.conexao.comandos[-1]
        usuario = self.conexao.emails.get(parametros[0]) if parametros else None
        return dict(usuario) if usuario else None


class ConexaoFalsa:
    def __init__(self):
        self.comandos, self.emails = [], {}

    def cursor(self):
        return CursorFalso(self)

    def commit(self):
        pass

    def rollback(self):
        pass


def test_b3_email_duplicado_vira_mensagem_e_nao_quebra():
    conexao = ConexaoFalsa()
    assert mysql_repo.cadastrar_usuario(conexao, "Ana", "ana@securapy.com", "Senha@12345", 3) == (
        True, "Usuário cadastrado.")
    assert mysql_repo.cadastrar_usuario(conexao, "Outra", "ANA@securapy.com", "Senha@12345", 1) == (
        False, "Email já cadastrado.")


def test_b4_sql_injection_no_login_e_neutralizado():
    conexao = ConexaoFalsa()
    mysql_repo.cadastrar_usuario(conexao, "Ana", "ana@securapy.com", "Senha@12345", 3)
    ataque = "' OR '1'='1"
    assert mysql_repo.autenticar(conexao, ataque, ataque) is None
    sql, parametros = conexao.comandos[-1]
    assert ataque not in sql and "%s" in sql    # o texto do atacante não entra no SQL
    assert parametros == (ataque.lower(),)      # vai separado, como dado


def test_login_correto_nao_devolve_o_hash():
    conexao = ConexaoFalsa()
    mysql_repo.cadastrar_usuario(conexao, "Ana", "ana@securapy.com", "Senha@12345", 3)
    usuario = mysql_repo.autenticar(conexao, "ana@securapy.com", "Senha@12345")
    assert usuario["email"] == "ana@securapy.com" and "senha_hash" not in usuario
    assert mysql_repo.autenticar(conexao, "ana@securapy.com", "errada123") is None


def test_senha_guardada_so_como_hash():
    conexao = ConexaoFalsa()
    mysql_repo.cadastrar_usuario(conexao, "Ana", "ana@securapy.com", "Senha@12345", 3)
    guardado = conexao.emails["ana@securapy.com"]["senha_hash"]
    assert "Senha@12345" not in guardado and guardado.startswith("pbkdf2_sha256$200000$")


@pytest.mark.parametrize("dados, erro", [
    (("", "a@b.com", "Senha@12345", 3), "Nome é obrigatório."),
    (("Ana", "sem-arroba", "Senha@12345", 3), "Email inválido."),
    (("Ana", "a@b.com", "curta", 3), "A senha deve ter pelo menos 8 caracteres."),
    (("Ana", "a@b.com", "Senha@12345", 9), "Nível de acesso deve ser de 1 a 5."),
])
def test_validacao_do_cadastro(dados, erro):
    assert mysql_repo.cadastrar_usuario(ConexaoFalsa(), *dados) == (False, erro)
