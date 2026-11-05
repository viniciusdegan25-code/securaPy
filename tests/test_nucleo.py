"""Testes do núcleo (Módulo A): coletor, regras, detector e correlação temporal."""

import pytest

from analisar import executar_nucleo
from core.coletor import carregar_log, carregar_todos_os_logs, contar_por_fonte
from core.correlacao import detectar_brute_force_temporal
from core.detector import (BLACKLIST, detectar_brute_force, detectar_port_scan,
                           verificar_blacklist)
from core.regras import aplicar_regras, carregar_regras
from db.configuracao import PASTA_LOGS

IP_ATACANTE = "185.220.101.1"
CAMPOS_EVENTO = {"timestamp", "fonte", "tipo", "ip", "detalhes", "linha_original"}


@pytest.fixture(scope="module")
def eventos():
    return carregar_todos_os_logs(PASTA_LOGS)


def test_a1_carrega_os_tres_logs_com_a_fonte_certa(eventos):
    assert len(eventos) == 58
    assert contar_por_fonte(eventos) == {"auth": 23, "firewall": 17, "web": 18}
    assert all(set(evento) == CAMPOS_EVENTO for evento in eventos)
    horarios = [evento["timestamp"] for evento in eventos]
    assert horarios == sorted(horarios)   # lista única em ordem de horário


def test_a2_brute_force_do_atacante_com_severidade_alta(eventos):
    brute_force = detectar_brute_force(eventos)
    # O enunciado fala em 10 FAILs, mas o auth.log fornecido tem 11 (ver README)
    assert brute_force[IP_ATACANTE]["tentativas"] == 11
    assert brute_force[IP_ATACANTE]["severidade"] == "ALTA"


def test_a3_port_scan_com_sete_portas_distintas(eventos):
    port_scan = detectar_port_scan(eventos)
    assert port_scan[IP_ATACANTE]["quantidade"] == 7
    assert isinstance(port_scan[IP_ATACANTE]["portas"], set)


def test_a4_intersecao_com_a_blacklist_retorna_os_3_ips(eventos):
    encontrados, _ = verificar_blacklist(eventos)
    assert encontrados == {"185.220.101.1", "91.240.118.172", "45.33.32.156"}
    assert encontrados < BLACKLIST   # o 23.94.5.100 está na lista mas não nos logs


def test_motor_de_regras_gera_alertas_das_5_regras(eventos):
    alertas = aplicar_regras(eventos, carregar_regras())
    assert {alerta["regra_id"] for alerta in alertas} == {"R001", "R002", "R003", "R004", "R005"}
    assert all(alerta["severidade"] in {"CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"}
               for alerta in alertas)


def test_fluxo_completo_do_nucleo(eventos):
    alertas, ameacas = executar_nucleo(eventos)
    assert len(alertas) == 35
    assert ameacas[0]["ip"] == IP_ATACANTE


def test_bonus_correlacao_temporal_considera_o_tempo(eventos):
    [alerta] = detectar_brute_force_temporal(eventos, janela_segundos=60)
    assert alerta["ip"] == IP_ATACANTE and alerta["regra_id"] == "BFT"
    assert detectar_brute_force_temporal(eventos, janela_segundos=10) == []


# Tratamento de erros (critério 6.2): log inexistente ou malformado não trava

def test_arquivo_inexistente_devolve_lista_vazia(tmp_path, capsys):
    assert carregar_log(str(tmp_path / "nao_existe.log"), "auth") == []
    assert "não encontrado" in capsys.readouterr().out


def test_linha_mal_formatada_e_ignorada(tmp_path, capsys):
    arquivo = tmp_path / "auth.log"
    arquivo.write_text("2025-02-20 08:15:01 FAIL usuario=admin ip=1.2.3.4\n"
                       "linha quebrada sem formato\n"
                       "2025-02-20 08:15:02 OK usuario=ana ip=10.0.0.1\n", encoding="utf-8")
    eventos = carregar_log(str(arquivo), "auth")
    assert [evento["tipo"] for evento in eventos] == ["FAIL", "OK"]
    assert "linha 2 ignorada" in capsys.readouterr().out


def test_pasta_inexistente_nao_trava(tmp_path):
    assert carregar_todos_os_logs(str(tmp_path / "sem_pasta")) == []
