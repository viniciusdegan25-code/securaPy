"""
migrar_logs.py — Migração dos logs para o MongoDB (Módulo B, requisito 3).

Lê os 3 arquivos de log pelo núcleo (core/coletor.py) e grava os
eventos no MongoDB, sem duplicar.

Uso (na raiz do projeto):
    python migrar_logs.py            -> grava só os eventos novos
    python migrar_logs.py --limpar   -> apaga os eventos e migra do zero
"""

import sys

from core.coletor import carregar_todos_os_logs, contar_por_fonte
from db import mongo_repo
from db.configuracao import PASTA_LOGS


def migrar(limpar=False):
    """
    Executa a migração completa. Retorna True se deu certo.
    - limpar=True apaga os eventos antes, para refazer do zero.
    """
    banco = mongo_repo.conectar()
    if banco is None:
        print("[ERRO] Migração cancelada: sem conexão com o MongoDB.")
        return False

    mongo_repo.criar_indices(banco)
    if limpar:
        print(f"Eventos apagados: {mongo_repo.apagar_eventos(banco)}")

    eventos = carregar_todos_os_logs(PASTA_LOGS)
    novos = mongo_repo.salvar_eventos(banco, eventos)

    print(f"\nEventos lidos dos logs : {len(eventos)} {contar_por_fonte(eventos)}")
    print(f"Eventos novos gravados : {novos}")
    print(f"Total no banco         : {mongo_repo.contar_eventos_por_fonte(banco)}")
    return True


if __name__ == "__main__":
    migrar(limpar="--limpar" in sys.argv)