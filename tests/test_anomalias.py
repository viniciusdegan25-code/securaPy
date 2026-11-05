"""Testes do bônus de detecção de anomalias (Isolation Forest)."""

from core.coletor import carregar_todos_os_logs
from db.configuracao import PASTA_LOGS
from ml.anomalias import detectar_anomalias


def test_isolation_forest_marca_os_ips_maliciosos_e_nao_os_internos():
    resultado = {item["ip"]: item for item in detectar_anomalias(carregar_todos_os_logs(PASTA_LOGS))}
    anomalos = {ip for ip, item in resultado.items() if item["anomalia"]}
    assert anomalos == {"185.220.101.1", "91.240.118.172", "45.33.32.156"}
    assert resultado["192.168.1.10"]["anomalia"] is False


def test_sem_eventos_devolve_lista_vazia():
    assert detectar_anomalias([]) == []
