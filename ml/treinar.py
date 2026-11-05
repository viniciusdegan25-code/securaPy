"""Gera dados rotulados pelo gerador do projeto, treina e avalia o modelo ML."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, make_scorer, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from core.coletor import carregar_todos_os_logs
from ferramentas.gerador_logs import PASTA_SAIDA, gerar_logs
from ml.classificar import sha256_arquivo
from ml.features import FEATURES, montar_features

PASTA_ML = Path(__file__).resolve().parent
CAMINHO_MODELO = PASTA_ML / "modelo.pkl"
CAMINHO_HASH = PASTA_ML / "modelo.sha256"
CAMINHO_METRICAS = PASTA_ML / "metricas.json"
SEMENTES_TREINO = range(40)
CLASSE_ATAQUE = "ataque"
CLASSE_NORMAL = "normal"


def construir_dataset(
    sementes: Iterable[int] = SEMENTES_TREINO,
    quantidade_normal: int = 50,
) -> tuple[np.ndarray, np.ndarray]:
    """Monta X e y lendo cada geração logo após o gerador gravar os logs.

    Cada linha representa um IP em uma geração específica. Os IPs que o
    gabarito do gerador identifica como atacantes recebem o rótulo ``ataque``;
    os outros IPs daquela geração recebem ``normal``.
    """
    linhas: list[list[float]] = []
    rotulos: list[str] = []

    for semente in sementes:
        gabarito = gerar_logs(
            quantidade_normal=quantidade_normal,
            semente=semente,
            pasta=PASTA_SAIDA,
        )
        # O gerador sobrescreve os arquivos; por isso, lê-los imediatamente.
        eventos = carregar_todos_os_logs(PASTA_SAIDA)
        features_por_ip = montar_features(eventos)
        ips_atacantes = set(gabarito.values())

        for ip, vetor in features_por_ip.items():
            linhas.append(vetor)
            rotulos.append(CLASSE_ATAQUE if ip in ips_atacantes else CLASSE_NORMAL)

    if not linhas:
        raise ValueError("O gerador não produziu amostras para o treinamento.")

    X = np.asarray(linhas, dtype=float)
    y = np.asarray(rotulos, dtype=str)
    return X, y


def construir_pipeline() -> Pipeline:
    """Cria as etapas de escala e classificação que serão treinadas juntas."""
    return Pipeline([
        ("escala", StandardScaler()),
        ("modelo", RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
        )),
    ])


def treinar(
    sementes: Iterable[int] = SEMENTES_TREINO,
    quantidade_normal: int = 50,
    caminho_modelo: str | Path = CAMINHO_MODELO,
) -> dict:
    """Avalia, ajusta e persiste o modelo, hash SHA-256 e métricas."""
    X, y = construir_dataset(sementes, quantidade_normal)
    contagem_classes = Counter(y)
    if set(contagem_classes) != {CLASSE_ATAQUE, CLASSE_NORMAL}:
        raise ValueError("O dataset precisa conter as classes ataque e normal.")

    menor_classe = min(contagem_classes.values())
    folds = min(5, menor_classe)
    if folds < 2:
        raise ValueError("A validação cruzada exige pelo menos 2 amostras por classe.")

    avaliadores = {
        "precisao": make_scorer(
            precision_score, pos_label=CLASSE_ATAQUE, zero_division=0
        ),
        "recall": make_scorer(
            recall_score, pos_label=CLASSE_ATAQUE, zero_division=0
        ),
        "f1": make_scorer(
            f1_score, pos_label=CLASSE_ATAQUE, zero_division=0
        ),
    }
    validacao = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
    resultados = cross_validate(
        construir_pipeline(),
        X,
        y,
        cv=validacao,
        scoring=avaliadores,
    )

    modelo = construir_pipeline()
    modelo.fit(X, y)

    caminho_modelo = Path(caminho_modelo)
    caminho_modelo.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"modelo": modelo, "features": list(FEATURES)}, caminho_modelo)

    hash_modelo = sha256_arquivo(caminho_modelo)
    caminho_hash = caminho_modelo.with_suffix(".sha256")
    caminho_hash.write_text(hash_modelo + "\n", encoding="ascii")

    relatorio = {
        "amostras": int(len(y)),
        "amostras_por_classe": {
            CLASSE_ATAQUE: int(contagem_classes[CLASSE_ATAQUE]),
            CLASSE_NORMAL: int(contagem_classes[CLASSE_NORMAL]),
        },
        "validacao_cruzada": {
            "folds": int(folds),
            "precisao_media": float(np.mean(resultados["test_precisao"])),
            "recall_medio": float(np.mean(resultados["test_recall"])),
            "f1_medio": float(np.mean(resultados["test_f1"])),
        },
        "features": list(FEATURES),
        "sha256_modelo": hash_modelo,
    }
    caminho_metricas = caminho_modelo.parent / "metricas.json"
    caminho_metricas.write_text(
        json.dumps(relatorio, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return relatorio


def main() -> None:
    """Executa o treinamento padrão e mostra um resumo das métricas."""
    relatorio = treinar()
    metricas = relatorio["validacao_cruzada"]
    print(f"Amostras: {relatorio['amostras']}")
    print(f"Folds: {metricas['folds']}")
    print(f"Precisão média: {metricas['precisao_media']:.4f}")
    print(f"Recall médio: {metricas['recall_medio']:.4f}")
    print(f"F1 médio: {metricas['f1_medio']:.4f}")
    print(f"Modelo salvo em: {CAMINHO_MODELO}")
    print(f"Hash salvo em: {CAMINHO_HASH}")
    print(f"Métricas salvas em: {CAMINHO_METRICAS}")


if __name__ == "__main__":
    main()