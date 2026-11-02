"""Carrega com verificação SHA-256 e pontua/ordena ameaças por IP."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import joblib
import numpy as np

try:
    from .features import FEATURES, extrair_features, features_de_ameaca
except ImportError:  # pragma: no cover
    from features import FEATURES, extrair_features, features_de_ameaca


class IntegridadeModeloError(RuntimeError):
    """O arquivo do modelo não corresponde ao hash registrado."""


def sha256_arquivo(caminho: str | Path) -> str:
    digest = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(65536), b""):
            digest.update(bloco)
    return digest.hexdigest()


def carregar_modelo(caminho: str | Path):
    caminho = Path(caminho)
    caminho_hash = Path(f"{caminho}.sha256")
    if not caminho.is_file() or not caminho_hash.is_file():
        raise FileNotFoundError("Modelo ou arquivo .sha256 não encontrado; treine o modelo primeiro.")
    esperado = caminho_hash.read_text(encoding="ascii").strip().lower()
    calculado = sha256_arquivo(caminho)
    if not hmac.compare_digest(esperado, calculado):
        raise IntegridadeModeloError("ALERTA: arquivo do modelo foi modificado; carga cancelada.")
    # joblib/pickle só deve ser carregado de origem confiável. Hash adjacente
    # detecta alteração acidental, mas não autentica quem controla ambos arquivos.
    pacote = joblib.load(caminho)
    if not isinstance(pacote, dict) or "modelo" not in pacote or pacote.get("features") != list(FEATURES):
        raise ValueError("Formato do modelo inválido ou incompatível com as features atuais.")
    return pacote["modelo"]


def pontuar(ameacas: list[dict], modelo=None, caminho_modelo: str | Path = "ml/modelo.pkl",
            eventos: list[dict] | None = None, blacklist: set[str] | None = None) -> list[dict]:
    """Enriquece alertas do Módulo B e ordena por score decrescente.

    Quando `eventos` é fornecido, as features são calculadas com os eventos
    normalizados do coletor A (mais informativas que o resumo do alerta B).
    Sem eventos, o formato de alerta B fornece somente as falhas explícitas
    em `descricao`; os outros sinais ficam neutros. Para facilitar integração,
    pontuar(alertas) carrega o modelo padrão.
    """
    if modelo is None:
        modelo = carregar_modelo(caminho_modelo)
    features_por_ip = extrair_features(eventos, blacklist) if eventos is not None else {}
    resultado = []
    for ameaca in ameacas:
        item = dict(ameaca)
        ip = item.get("ip")
        features = features_por_ip.get(ip) if ip else None
        if features is None:
            features = features_de_ameaca(ameaca)
        item.update(classificar_features(features, modelo))
        resultado.append(item)
    return sorted(resultado, key=lambda item: item["score_risco"], reverse=True)


def classificar_features(features: dict[str, float], modelo: object) -> dict:
    """Classifica uma linha de features (inclusive IP sem alerta de regra)."""
    vetor = np.asarray([[features.get(nome, 0.0) for nome in FEATURES]], dtype=float)
    probabilidades = modelo.predict_proba(vetor)[0]
    classes = list(modelo.classes_)
    indice_ataque = classes.index("ataque")
    score = round(float(probabilidades[indice_ataque]) * 100, 2)
    rotulo = "ataque" if modelo.predict(vetor)[0] == "ataque" else "normal"
    faixa = "ALTO" if score >= 70 else "MEDIO" if score >= 40 else "BAIXO"
    return {"score_risco": score, "rotulo_ml": rotulo, "risco_ml": faixa}
