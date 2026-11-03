"""
api/servico.py — Análise completa para a API: núcleo + ML + banco (Módulo D).

Segue o mesmo fluxo de analisar.analisar(), mas acrescenta o score de ML e
grava no banco que a API já tem conectado. Não escreve relatório em disco.
Reaproveita as funções do núcleo sem alterá-las.
"""

import logging
from datetime import datetime

from analisar import ORDEM_SEVERIDADE, contar_por_severidade, executar_nucleo
from api.validacao import ValidacaoError
from core.coletor import contar_por_fonte
from db import mongo_repo
from ml.classificar import IntegridadeModeloError

registro = logging.getLogger(__name__)


def _persistir_no_banco(banco, eventos, alertas):
    """Grava eventos e alertas sem duplicar. Sem banco, só informa que não gravou."""
    if banco is None:
        return {"banco_disponivel": False, "eventos_novos": 0, "alertas_novos": 0}
    mongo_repo.criar_indices(banco)
    return {
        "banco_disponivel": True,
        "eventos_novos": mongo_repo.salvar_eventos(banco, eventos),
        "alertas_novos": mongo_repo.salvar_alertas(banco, alertas),
    }


def analisar_com_ml(eventos, deps, persistir=None, eventos_confiaveis=True):
    """
    Roda regras, detector e correlação, pontua as ameaças com o modelo de ML e
    persiste. Se o ML falhar (modelo ausente ou hash que não confere), a análise
    segue sem score e o resultado traz ml_disponivel=False.

    'persistir' é opcional: função (eventos, alertas) -> dict; o padrão grava
    no banco de deps.mongo(). Com eventos_confiaveis=False (lote vindo do
    cliente), um evento que o núcleo não entende vira ValidacaoError (400),
    e não erro interno.
    """
    try:
        alertas, ameacas = executar_nucleo(eventos)
    except (KeyError, ValueError, TypeError):
        if eventos_confiaveis:
            raise
        registro.warning("Lote de eventos rejeitado pelo núcleo", exc_info=True)
        raise ValidacaoError("eventos em formato inesperado") from None
    alertas.sort(key=lambda alerta: ORDEM_SEVERIDADE.index(alerta["severidade"]))

    ml_disponivel = True
    try:
        ameacas = deps.pontuar(ameacas, eventos)
    except IntegridadeModeloError:
        registro.error("ALERTA: o hash do modelo de ML não confere; análise sem score.")
        ml_disponivel = False
    except (FileNotFoundError, ValueError) as erro:
        registro.warning("ML indisponível (%s); análise sem score.", erro.__class__.__name__)
        ml_disponivel = False

    if persistir is None:
        def persistir(eventos_novos, alertas_novos):
            return _persistir_no_banco(deps.mongo(), eventos_novos, alertas_novos)

    return {
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_eventos": len(eventos),
        "eventos_por_fonte": contar_por_fonte(eventos),
        "total_alertas": len(alertas),
        "alertas_por_severidade": contar_por_severidade(alertas),
        "ameacas": ameacas,
        "alertas": alertas,
        "ml_disponivel": ml_disponivel,
        "persistencia": persistir(eventos, alertas),
    }
