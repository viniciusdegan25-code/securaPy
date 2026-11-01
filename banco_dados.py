"""
banco_dados.py — Persistência dos eventos no MongoDB Atlas (nuvem).

Guarda os eventos normalizados do coletor no banco 'securapy',
coleção 'eventos'. O endereço de conexão (com a senha) é lido de
config/segredos.json, que NÃO vai para o GitHub.
Se o banco estiver inacessível, avisa e o SIEM continua em memória.
"""

import json
import os

from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError

NOME_BANCO = "securapy"
NOME_COLECAO = "eventos"

# Pasta onde este arquivo está salvo (a pasta securaPy)
PASTA_PROJETO = os.path.dirname(os.path.abspath(__file__))
PASTA_LOGS = os.path.join(PASTA_PROJETO, "logs")
ARQUIVO_SEGREDOS = os.path.join(PASTA_PROJETO, "config", "segredos.json")


def ler_endereco_mongo():
    """
    Lê o endereço de conexão do arquivo config/segredos.json.
    Retorna None se o arquivo não existir ou estiver com erro.
    """
    try:
        with open(ARQUIVO_SEGREDOS, "r", encoding="utf-8") as arquivo:
            return json.load(arquivo)["mongo_uri"]
    except FileNotFoundError:
        print("[ERRO] config/segredos.json não encontrado. "
              "Copie o segredos.exemplo.json e coloque a senha.")
    except json.JSONDecodeError:
        print("[ERRO] config/segredos.json está com o JSON inválido.")
    except KeyError:
        print("[ERRO] config/segredos.json não tem a chave 'mongo_uri'.")
    return None


def conectar_banco():
    """
    Conecta ao MongoDB Atlas e retorna a coleção de eventos.
    Retorna None se não for possível conectar.
    """
    endereco = ler_endereco_mongo()
    if endereco is None:
        return None

    try:
        cliente = MongoClient(endereco, serverSelectionTimeoutMS=8000)
        cliente.admin.command("ping")
    except PyMongoError as erro:
        print(f"[AVISO] Não foi possível conectar ao MongoDB: {erro.__class__.__name__}")
        print("        Os dados ficarão só em memória.")
        return None

    colecao = cliente[NOME_BANCO][NOME_COLECAO]
    print(f"[OK] Conectado ao MongoDB Atlas (banco '{NOME_BANCO}').")
    return colecao


def gerar_id(evento):
    """Cria um identificador único para o evento: fonte + linha original."""
    return f"{evento['fonte']}|{evento['linha_original']}"


def salvar_eventos(colecao, eventos):
    """
    Grava a lista de eventos no MongoDB, sem duplicar.
    Retorna quantos eventos NOVOS foram gravados.
    """
    if colecao is None or len(eventos) == 0:
        return 0

    operacoes = []
    for evento in eventos:
        documento = dict(evento)
        documento["_id"] = gerar_id(evento)
        operacoes.append(
            UpdateOne({"_id": documento["_id"]}, {"$setOnInsert": documento}, upsert=True)
        )

    try:
        resultado = colecao.bulk_write(operacoes)
    except PyMongoError as erro:
        print(f"[ERRO] Falha ao gravar no MongoDB: {erro}")
        return 0

    return resultado.upserted_count


def buscar_por_ip(colecao, ip):
    """Retorna todos os eventos de um IP, em ordem de horário."""
    if colecao is None:
        return []
    try:
        return list(colecao.find({"ip": ip}, {"_id": 0}).sort("timestamp", 1))
    except PyMongoError as erro:
        print(f"[ERRO] Falha na busca: {erro}")
        return []


def contar_por_fonte_no_banco(colecao):
    """Retorna um dicionário {fonte: quantidade} contado direto no banco."""
    if colecao is None:
        return {}
    contagem = {}
    for fonte in ("auth", "firewall", "web"):
        contagem[fonte] = colecao.count_documents({"fonte": fonte})
    return contagem


if __name__ == "__main__":
    from coletor import carregar_todos_os_logs

    colecao = conectar_banco()
    eventos = carregar_todos_os_logs(PASTA_LOGS)

    novos = salvar_eventos(colecao, eventos)
    print(f"Eventos lidos dos logs: {len(eventos)}")
    print(f"Eventos novos gravados no banco: {novos}")
    print(f"Contagem no banco: {contar_por_fonte_no_banco(colecao)}")

    print("\nEventos do IP 185.220.101.1 (primeiros 3):")
    for evento in buscar_por_ip(colecao, "185.220.101.1")[:3]:
        print(f"  {evento['timestamp']} | {evento['fonte']:<8} | {evento['tipo']}")