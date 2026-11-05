"""Verifica a integridade do modelo e atribui score aos IPs suspeitos."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Iterable, Mapping

import joblib
import numpy as np

from core.coletor import carregar_todos_os_logs
from db.configuracao import PASTA_LOGS
from ml.features import FEATURES, montar_features

PASTA_ML = Path(__file__).resolve().parent
CAMINHO_MODELO = PASTA_ML / "modelo.pkl"
CAMINHO_HASH = PASTA_ML / "modelo.sha256"


class IntegridadeModeloError(RuntimeError):
    """Indica que o arquivo do modelo difere do hash registrado."""


def sha256_arquivo(caminho: str | Path) -> str:
    """Calcula o SHA-256 de um arquivo em blocos."""
    digest = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(65536), b""):
            digest.update(bloco)
    return digest.hexdigest()


def carregar_modelo(
    caminho_modelo: str | Path = CAMINHO_MODELO,
    caminho_hash: str | Path | None = None,
):
    """Confere o SHA-256 antes de desserializar e validar o modelo."""
    caminho_modelo = Path(caminho_modelo)
    caminho_hash = Path(caminho_hash) if caminho_hash else caminho_modelo.with_suffix(".sha256")

    if not caminho_modelo.is_file() or not caminho_hash.is_file():
        raise FileNotFoundError(
            "Modelo ou arquivo .sha256 não encontrado. Execute python -m ml.treinar primeiro."
        )

    esperado = caminho_hash.read_text(encoding="ascii").strip().lower()
    calculado = sha256_arquivo(caminho_modelo)
    if not hmac.compare_digest(esperado, calculado):
        raise IntegridadeModeloError(
            "O SHA-256 do modelo não confere; o carregamento foi cancelado."
        )

    # joblib usa pickle: só carregue artefatos cuja origem seja confiável.
    pacote = joblib.load(caminho_modelo)
    if (
        not isinstance(pacote, dict)
        or "modelo" not in pacote
        or pacote.get("features") != list(FEATURES)
    ):
        raise ValueError("Formato do modelo inválido ou incompatível com as features atuais.")
    return pacote["modelo"]


def _obter_eventos(eventos: Iterable[Mapping] | None) -> list[Mapping]:
    """Usa os eventos recebidos ou lê os logs configurados pelo projeto."""
    if eventos is not None:
        return list(eventos)
    return carregar_todos_os_logs(PASTA_LOGS)


def _resultado_ip(ip: str, vetor: list[float], modelo) -> dict:
    """Classifica um vetor e monta o retorno público de um IP."""
    matriz = np.asarray([vetor], dtype=float)
    probabilidades = modelo.predict_proba(matriz)[0]
    classes = list(modelo.classes_)
    if "ataque" not in classes:
        raise ValueError("O modelo carregado não possui a classe 'ataque'.")

    score_bruto = float(probabilidades[classes.index("ataque")])
    rotulo = str(modelo.predict(matriz)[0])
    risco = "ALTO" if score_bruto >= 0.7 else "MEDIO" if score_bruto >= 0.4 else "BAIXO"
    return {
        "ip": ip,
        "score_ml": round(score_bruto, 4),
        "rotulo_ml": rotulo,
        "risco_ml": risco,
    }


def pontuar(
    ameacas: list[dict],
    eventos: Iterable[Mapping] | None = None,
    caminho_modelo: str | Path = CAMINHO_MODELO,
) -> list[dict]:
    """Acrescenta score e rótulo ML às ameaças e ordena pelo score decrescente.

    ``ameacas`` segue o formato produzido por
    ``core.detector.gerar_resumo_ameacas``. Se ``eventos`` for omitido,
    carrega os logs da pasta configurada em ``db.configuracao.PASTA_LOGS``.
    """
    modelo = carregar_modelo(caminho_modelo)
    lista_eventos = _obter_eventos(eventos)
    features_por_ip = montar_features(lista_eventos)
    vetor_zerado = [0.0] * len(FEATURES)

    resultado = []
    for ameaca in ameacas:
        item = dict(ameaca)
        ip = str(item["ip"])
        vetor = features_por_ip.get(ip, vetor_zerado)
        item.update(_resultado_ip(ip, vetor, modelo))
        resultado.append(item)

    return sorted(resultado, key=lambda item: item["score_ml"], reverse=True)


def classificar_ip(
    ip: str,
    eventos: Iterable[Mapping] | None = None,
    caminho_modelo: str | Path = CAMINHO_MODELO,
) -> dict:
    """Classifica um único IP; é a interface que a API pode chamar."""
    modelo = carregar_modelo(caminho_modelo)
    lista_eventos = _obter_eventos(eventos)
    features_por_ip = montar_features(lista_eventos)
    vetor = features_por_ip.get(ip, [0.0] * len(FEATURES))
    return _resultado_ip(ip, vetor, modelo)


def main() -> None:
    """Demonstra a classificação dos IPs previstos nos cenários C2 e C3."""
    for ip in ("185.220.101.1", "192.168.1.10"):
        resultado = classificar_ip(ip)
        print(
            f"{ip}: score={resultado['score_ml']:.4f} "
            f"risco={resultado['risco_ml']} rótulo={resultado['rotulo_ml']}"
        )


if __name__ == "__main__":
    main()