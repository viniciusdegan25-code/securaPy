"""
scripts/verificar_docker.py — Confere se os serviços do Docker Compose estão no ar (Módulo F).

Usa o SDK do Docker (docker-py) para listar os contêineres do projeto
"securapy" e mostrar o status de cada serviço esperado.

Uso (na raiz do projeto, com a plataforma já iniciada):
    python -m scripts.verificar_docker

Código de saída: 0 = os três serviços estão "running"; 1 = algum não está;
2 = não foi possível falar com o Docker.
"""

import sys

import docker
from docker.errors import DockerException

PROJETO = "securapy"
SERVICOS_ESPERADOS = ("api", "mongo", "mysql")


def verificar(cliente, esperados=SERVICOS_ESPERADOS, projeto=PROJETO):
    """Retorna {serviço: status} ("running", "exited", ... ou "ausente")."""
    containers = cliente.containers.list(
        all=True, filters={"label": f"com.docker.compose.project={projeto}"})
    situacao = {nome: "ausente" for nome in esperados}
    for container in containers:
        servico = container.labels.get("com.docker.compose.service")
        if servico in situacao:
            situacao[servico] = container.status
    return situacao


def main():
    try:
        cliente = docker.from_env()
        cliente.ping()
    except DockerException:
        print("[ERRO] Não foi possível falar com o Docker. Ele está instalado e em execução?")
        return 2

    situacao = verificar(cliente)
    print(f"Serviços do projeto '{PROJETO}':")
    for nome, status in situacao.items():
        marca = "OK  " if status == "running" else "FALHA"
        print(f"  [{marca}] {nome:<6} {status}")
    return 0 if all(status == "running" for status in situacao.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
