"""Treina, avalia e persiste o classificador do SecuraPy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import make_scorer, precision_score, recall_score, f1_score
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:  # funciona como pacote ou como script direto
    from .features import FEATURES, extrair_features
except ImportError:  # pragma: no cover
    from features import FEATURES, extrair_features


def sha256_arquivo(caminho: str | Path) -> str:
    digest = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(65536), b""):
            digest.update(bloco)
    return digest.hexdigest()


def construir_pipeline() -> Pipeline:
    # O StandardScaler fica no Pipeline, para que cada fold ajuste o scaler
    # apenas nos dados de treino. Random Forest segue o exemplo da Aula 4.
    return Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=42
        )),
    ])


def treinar(eventos: list[dict], rotulos_por_ip: dict[str, str], caminho_modelo: str | Path,
            blacklist: set[str] | None = None) -> dict:
    """Treina com rótulos de referência independentes dos dados de entrada.

    rotulos_por_ip usa exclusivamente "ataque" ou "normal". É importante que
    os rótulos venham de revisão/verdade-terreno, não do score previsto pelo ML.
    """
    amostras = extrair_features(eventos, blacklist)
    ips = [ip for ip in amostras if ip in rotulos_por_ip]
    if len(ips) < 4:
        raise ValueError("São necessárias ao menos 4 amostras rotuladas (2 por classe).")
    classes = {rotulos_por_ip[ip] for ip in ips}
    if classes != {"ataque", "normal"}:
        raise ValueError("Os rótulos precisam conter as classes 'ataque' e 'normal'.")
    X = np.asarray([[amostras[ip][nome] for nome in FEATURES] for ip in ips], dtype=float)
    y = np.asarray([rotulos_por_ip[ip] for ip in ips])
    menor_classe = min(np.count_nonzero(y == classe) for classe in classes)
    n_splits = min(5, int(menor_classe))
    if n_splits < 2:
        raise ValueError("Validação cruzada exige pelo menos 2 IPs rotulados em cada classe.")

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    metricas = {
        "precisao": make_scorer(precision_score, pos_label="ataque", zero_division=0),
        "recall": make_scorer(recall_score, pos_label="ataque", zero_division=0),
        "f1": make_scorer(f1_score, pos_label="ataque", zero_division=0),
    }
    pipeline = construir_pipeline()
    resultados_cv = cross_validate(pipeline, X, y, cv=cv, scoring=metricas)
    pipeline.fit(X, y)

    caminho_modelo = Path(caminho_modelo)
    caminho_modelo.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"modelo": pipeline, "features": list(FEATURES)}, caminho_modelo)
    hash_modelo = sha256_arquivo(caminho_modelo)
    Path(f"{caminho_modelo}.sha256").write_text(hash_modelo + "\n", encoding="ascii")
    return {
        nome: float(np.mean(resultados_cv[f"test_{nome}"]))
        for nome in metricas
    } | {"cv_folds": n_splits, "amostras": len(ips), "sha256": hash_modelo}


def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    origem = parser.add_mutually_exclusive_group(required=True)
    origem.add_argument("--eventos-json",
                        help="JSON com lista de eventos normalizados pelo coletor")
    origem.add_argument("--pasta-logs",
                        help="Pasta com auth.log, firewall.log e web_access.log; usa securaPy.coletor")
    parser.add_argument("--rotulos-json", required=True,
                        help="JSON {ip: 'ataque'|'normal'} revisado pelo grupo")
    parser.add_argument("--modelo", default="ml/modelo.pkl")
    parser.add_argument("--blacklist-json", help="Opcional: JSON com lista de IPs")
    args = parser.parse_args()
    if args.eventos_json:
        eventos = json.loads(Path(args.eventos_json).read_text(encoding="utf-8"))
    else:
        try:
            from securaPy.coletor import carregar_todos_os_logs
        except ImportError as erro:
            raise SystemExit(
                "Não foi possível importar securaPy.coletor. Execute na raiz do projeto A/B "
                "ou use --eventos-json."
            ) from erro
        eventos = carregar_todos_os_logs(args.pasta_logs)
    rotulos = json.loads(Path(args.rotulos_json).read_text(encoding="utf-8"))
    blacklist = set(json.loads(Path(args.blacklist_json).read_text(encoding="utf-8"))) if args.blacklist_json else set()
    relatorio = treinar(eventos, rotulos, args.modelo, blacklist)
    print("Validação cruzada (média dos folds):")
    for nome in ("precisao", "recall", "f1"):
        print(f"{nome}: {relatorio[nome]:.3f}")
    print(f"Folds: {relatorio['cv_folds']} | amostras: {relatorio['amostras']}")
    print(f"Modelo: {args.modelo}")
    print(f"SHA-256: {relatorio['sha256']}")


if __name__ == "__main__":
    _main()
