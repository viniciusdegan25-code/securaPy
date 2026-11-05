"""Detecção de anomalias com Isolation Forest (bônus do Módulo C).

O classificador de ``ml/treinar.py`` aprende com exemplos rotulados de ataques
conhecidos. O Isolation Forest faz o contrário: aprende **só o tráfego normal**
e marca como anomalia qualquer IP cujo comportamento foge desse padrão, mesmo
que não exista regra nem rótulo para aquele ataque.

Usa as mesmas 6 features por IP de ``ml/features.py``. O modelo é treinado na
primeira chamada com tráfego normal gerado pelo ``ferramentas/gerador_logs.py``
(numa pasta temporária, sem mexer em ``logs/``) e fica guardado em memória.

Uso: ``python -m ml.anomalias``
"""

from __future__ import annotations

import tempfile
from functools import lru_cache
from typing import Iterable, Mapping

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from core.coletor import carregar_todos_os_logs
from ferramentas.gerador_logs import gerar_logs
from ml.features import montar_features

SEMENTES_NORMAIS = range(100, 120)   # diferentes das sementes do classificador
CONTAMINACAO = 0.02                  # fração do tráfego normal aceita como "estranha"


def _amostras_normais(sementes: Iterable[int]) -> np.ndarray:
    """Vetores de features só dos IPs NORMAIS (o gabarito separa os atacantes)."""
    linhas = []
    with tempfile.TemporaryDirectory() as pasta:
        for semente in sementes:
            gabarito = gerar_logs(semente=semente, pasta=pasta)
            atacantes = set(gabarito.values())
            for ip, vetor in montar_features(carregar_todos_os_logs(pasta)).items():
                if ip not in atacantes:
                    linhas.append(vetor)
    if not linhas:
        raise ValueError("O gerador não produziu tráfego normal para o treino.")
    return np.asarray(linhas, dtype=float)


@lru_cache(maxsize=1)
def treinar_detector(sementes: tuple[int, ...] = tuple(SEMENTES_NORMAIS)) -> Pipeline:
    """Treina (uma vez) o Isolation Forest sobre o tráfego normal."""
    detector = Pipeline([
        ("escala", StandardScaler()),
        ("isolation_forest", IsolationForest(
            n_estimators=200, contamination=CONTAMINACAO, random_state=42)),
    ])
    detector.fit(_amostras_normais(sementes))
    return detector


def detectar_anomalias(eventos: Iterable[Mapping]) -> list[dict]:
    """
    Retorna um item por IP: {"ip", "anomalia" (bool), "score_anomalia"}.
    Quanto MAIOR o score_anomalia, mais estranho o comportamento do IP.
    Lista ordenada do mais anômalo para o menos.
    """
    features = montar_features(list(eventos))
    if not features:
        return []
    ips = list(features)
    matriz = np.asarray([features[ip] for ip in ips], dtype=float)

    detector = treinar_detector()
    previsoes = detector.predict(matriz)               # -1 = anomalia, 1 = normal
    scores = -detector.decision_function(matriz)       # positivo = anômalo

    resultado = [{"ip": ip, "anomalia": bool(previsao == -1),
                  "score_anomalia": round(float(score), 4)}
                 for ip, previsao, score in zip(ips, previsoes, scores)]
    return sorted(resultado, key=lambda item: item["score_anomalia"], reverse=True)


def main() -> None:
    from db.configuracao import PASTA_LOGS

    print("Isolation Forest sobre os logs de teste (anomalia = foge do tráfego normal):\n")
    for item in detectar_anomalias(carregar_todos_os_logs(PASTA_LOGS)):
        marca = "ANOMALIA" if item["anomalia"] else "normal"
        print(f"  {item['ip']:<16} {marca:<9} score {item['score_anomalia']:+.4f}")


if __name__ == "__main__":
    main()
