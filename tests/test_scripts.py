"""Testes dos scripts de apoio: verificação do Docker (F2) e criação de operador."""

from types import SimpleNamespace

import pytest
from docker.errors import DockerException

from scripts import criar_operador, verificar_docker


def _container(servico, status):
    return SimpleNamespace(labels={"com.docker.compose.service": servico}, status=status)


class ClienteDockerFalso:
    def __init__(self, containers):
        self._containers = containers
        self.containers = SimpleNamespace(list=self._listar)
        self.filtros = None

    def _listar(self, all=False, filters=None):
        self.filtros = filters
        return self._containers

    def ping(self):
        return True


def test_tres_containers_rodando(monkeypatch, capsys):
    cliente = ClienteDockerFalso([_container("api", "running"), _container("mongo", "running"),
                                  _container("mysql", "running")])
    assert verificar_docker.verificar(cliente) == {
        "api": "running", "mongo": "running", "mysql": "running"}
    assert cliente.filtros == {"label": "com.docker.compose.project=securapy"}

    monkeypatch.setattr(verificar_docker.docker, "from_env", lambda: cliente)
    assert verificar_docker.main() == 0
    assert "mongo" in capsys.readouterr().out


def test_container_parado_ou_ausente_falha(monkeypatch):
    cliente = ClienteDockerFalso([_container("api", "running"), _container("mongo", "exited")])
    assert verificar_docker.verificar(cliente) == {
        "api": "running", "mongo": "exited", "mysql": "ausente"}
    monkeypatch.setattr(verificar_docker.docker, "from_env", lambda: cliente)
    assert verificar_docker.main() == 1


def test_docker_fora_do_ar_da_mensagem_amigavel(monkeypatch, capsys):
    def sem_docker():
        raise DockerException("daemon off")

    monkeypatch.setattr(verificar_docker.docker, "from_env", sem_docker)
    assert verificar_docker.main() == 2
    saida = capsys.readouterr().out
    assert "Docker" in saida and "Traceback" not in saida


class ConexaoFalsa:
    fechada = False

    def close(self):
        self.fechada = True


def test_criar_operador_usa_senha_do_getpass_e_nao_a_imprime(monkeypatch, capsys):
    conexao = ConexaoFalsa()
    recebido = {}

    def cadastrar(conn, nome, email, senha, nivel):
        recebido.update(nome=nome, email=email, senha=senha, nivel=nivel)
        return True, "Usuário cadastrado."

    monkeypatch.setattr(criar_operador.mysql_repo, "conectar", lambda: conexao)
    monkeypatch.setattr(criar_operador.mysql_repo, "cadastrar_usuario", cadastrar)
    monkeypatch.delenv("OPERADOR_SENHA", raising=False)
    codigo = criar_operador.main(["--nome", "Ana", "--email", "ana@x.com", "--nivel", "3"],
                                 ler_senha=lambda prompt: "SenhaForte123")
    assert codigo == 0 and conexao.fechada
    assert recebido == {"nome": "Ana", "email": "ana@x.com", "senha": "SenhaForte123", "nivel": 3}
    assert "SenhaForte123" not in capsys.readouterr().out


def test_criar_operador_mostra_motivo_em_vez_de_traceback(monkeypatch, capsys):
    monkeypatch.setattr(criar_operador.mysql_repo, "conectar", ConexaoFalsa)
    monkeypatch.setattr(criar_operador.mysql_repo, "cadastrar_usuario",
                        lambda *a: (False, "Email já cadastrado."))
    codigo = criar_operador.main(["--nome", "Ana", "--email", "ana@x.com"],
                                 ler_senha=lambda prompt: "SenhaForte123")
    assert codigo == 1 and "Email já cadastrado." in capsys.readouterr().out


def test_criar_operador_sem_mysql_devolve_erro_amigavel(monkeypatch, capsys):
    monkeypatch.setattr(criar_operador.mysql_repo, "conectar", lambda: None)
    codigo = criar_operador.main(["--nome", "Ana", "--email", "ana@x.com"],
                                 ler_senha=lambda prompt: "SenhaForte123")
    assert codigo == 1 and "MySQL" in capsys.readouterr().out
