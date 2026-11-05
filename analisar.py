"""
analisar.py — Análise completa do núcleo (Módulo A integrado ao Módulo B).

Executa o fluxo inteiro do SIEM, na ordem:
    1. coletor     -> lê e normaliza os logs
    2. regras      -> alertas evento a evento (regras.json)
    3. detector    -> brute force, port scan, blacklist + resumo por IP
    4. correlação  -> brute force por janela de tempo (bônus)
    5. ML          -> score de risco de cada IP suspeito (Módulo C)
                      + anomalias por Isolation Forest (bônus)
    6. MongoDB     -> grava eventos e alertas (sem duplicar)
    7. relatório   -> exporta tudo em JSON na pasta saida/

A API (Pessoa 3) reaproveita executar_nucleo() no POST /api/analisar
(arquivo api/servico.py).

Uso no terminal (na raiz do projeto):
    python analisar.py                 -> analisa a pasta logs/
    python analisar.py logs_gerados    -> analisa outra pasta
"""

import json
import os
import sys
from datetime import datetime

from core.coletor import carregar_todos_os_logs, contar_por_fonte
from core.correlacao import detectar_brute_force_temporal
from core.detector import (detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas,
                           resumo_para_alertas, verificar_blacklist)
from core.regras import aplicar_regras, carregar_regras
from db import mongo_repo
from db.configuracao import PASTA_LOGS, PASTA_PROJETO

PASTA_SAIDA = os.path.join(PASTA_PROJETO, "saida")
ORDEM_SEVERIDADE = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")


def contar_por_severidade(alertas):
    """Retorna {severidade: quantidade}, na ordem CRITICA -> INFO."""
    contagem = {severidade: 0 for severidade in ORDEM_SEVERIDADE}
    for alerta in alertas:
        contagem[alerta["severidade"]] = contagem.get(alerta["severidade"], 0) + 1
    return contagem


def executar_nucleo(eventos):
    """
    Roda regras, detector e correlação sobre os eventos.
    Retorna (lista de todos os alertas, resumo de ameaças por IP).
    """
    alertas = aplicar_regras(eventos, carregar_regras())

    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    ips_blacklist, _ = verificar_blacklist(eventos)
    resumo = gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist)

    alertas += resumo_para_alertas(resumo, eventos)
    alertas += detectar_brute_force_temporal(eventos)
    return alertas, resumo


def pontuar_com_ml(ameacas, eventos):
    """
    Acrescenta o score de risco do ML (Módulo C) a cada IP suspeito e ordena
    do maior risco para o menor. Se o modelo faltar ou o hash não conferir,
    devolve as ameaças sem score: a análise nunca para por causa do ML.
    Retorna (ameacas, ml_disponivel).
    """
    from ml.classificar import IntegridadeModeloError, pontuar

    try:
        return pontuar(ameacas, eventos), True
    except IntegridadeModeloError:
        print("[ALERTA] O hash do modelo de ML não confere: análise feita sem score.")
    except (FileNotFoundError, ValueError) as erro:
        print(f"[AVISO] ML indisponível ({erro.__class__.__name__}): análise feita sem score.")
    return ameacas, False


def detectar_anomalias(eventos):
    """IPs com comportamento fora do normal (Isolation Forest). [] se o ML falhar."""
    from ml.anomalias import detectar_anomalias as isolation_forest

    try:
        return [item for item in isolation_forest(eventos) if item["anomalia"]]
    except (OSError, ValueError) as erro:
        print(f"[AVISO] Detecção de anomalias indisponível ({erro.__class__.__name__}).")
        return []


def persistir(eventos, alertas):
    """Grava eventos e alertas no MongoDB. Retorna quantos eram novos."""
    banco = mongo_repo.conectar()
    if banco is None:
        return {"banco_disponivel": False, "eventos_novos": 0, "alertas_novos": 0}
    mongo_repo.criar_indices(banco)
    return {
        "banco_disponivel": True,
        "eventos_novos": mongo_repo.salvar_eventos(banco, eventos),
        "alertas_novos": mongo_repo.salvar_alertas(banco, alertas),
    }


def exportar_relatorio(dados, pasta=PASTA_SAIDA):
    """Salva o relatório em saida/relatorio_AAAAMMDD_HHMMSS.json. Retorna o caminho."""
    try:
        os.makedirs(pasta, exist_ok=True)
        caminho = os.path.join(pasta, datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json"))
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, indent=2, ensure_ascii=False)
    except OSError as erro:
        print(f"[ERRO] Não foi possível salvar o relatório: {erro.__class__.__name__}")
        return None
    return caminho


def analisar(pasta_logs=PASTA_LOGS, salvar_no_banco=True, gerar_relatorio=True):
    """
    Executa a análise completa e retorna um resumo (dict, pronto para JSON).
    Nunca trava: sem logs, devolve tudo zerado; sem banco, só não persiste.
    """
    eventos = carregar_todos_os_logs(pasta_logs)
    alertas, ameacas = executar_nucleo(eventos)
    alertas.sort(key=lambda alerta: ORDEM_SEVERIDADE.index(alerta["severidade"]))
    ameacas, ml_disponivel = pontuar_com_ml(ameacas, eventos)

    resultado = {
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_eventos": len(eventos),
        "eventos_por_fonte": contar_por_fonte(eventos),
        "total_alertas": len(alertas),
        "alertas_por_severidade": contar_por_severidade(alertas),
        "ameacas": ameacas,
        "alertas": alertas,
        "ml_disponivel": ml_disponivel,
        "anomalias": detectar_anomalias(eventos),
    }
    if salvar_no_banco:
        resultado["persistencia"] = persistir(eventos, alertas)
    if gerar_relatorio:
        resultado["relatorio"] = exportar_relatorio(resultado)
    return resultado


def exibir_resultado(resultado):
    """Mostra o resumo da análise no terminal."""
    print(f"\nEventos analisados : {resultado['total_eventos']} {resultado['eventos_por_fonte']}")
    print(f"Alertas gerados    : {resultado['total_alertas']}")
    for severidade, quantidade in resultado["alertas_por_severidade"].items():
        if quantidade:
            print(f"   {severidade:<8} {quantidade:>3}")

    print("\nAmeaças por IP (da mais grave para a menor):")
    for item in resultado["ameacas"]:
        score = f"  score ML {item['score_ml']:.2f} ({item['risco_ml']})" if "score_ml" in item else ""
        print(f"   [{item['severidade']:<7}] {item['ip']:<16} "
              f"{item['quantidade_deteccoes']} detecções{score}")

    if resultado.get("anomalias"):
        ips = ", ".join(item["ip"] for item in resultado["anomalias"])
        print(f"\nAnomalias (Isolation Forest): {ips}")

    persistencia = resultado.get("persistencia")
    if persistencia and persistencia["banco_disponivel"]:
        print(f"\nMongoDB: {persistencia['eventos_novos']} eventos e "
              f"{persistencia['alertas_novos']} alertas novos gravados")
    if resultado.get("relatorio"):
        print(f"Relatório salvo em: {os.path.relpath(resultado['relatorio'], PASTA_PROJETO)}")


if __name__ == "__main__":
    pasta = os.path.join(PASTA_PROJETO, sys.argv[1]) if len(sys.argv) > 1 else PASTA_LOGS
    exibir_resultado(analisar(pasta))