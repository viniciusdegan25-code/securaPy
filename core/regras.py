"""
core/regras.py — Motor de regras de detecção (Módulo A).

Lê as regras de config/regras.json e aplica cada regra ativa a cada
evento. Quando um evento viola uma regra, gera um alerta no formato
padrão do SIEM: timestamp, regra, severidade, ip, descricao.

As regras ficam num JSON externo para o analista ajustar sem mexer
no código (ativar/desativar, trocar portas, usuários, padrões...).
"""

import json
import os

PASTA_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARQUIVO_REGRAS = os.path.join(PASTA_PROJETO, "config", "regras.json")

# (pontuação mínima, severidade) — tupla de tuplas: não muda durante a execução
FAIXAS_SEVERIDADE = ((9, "CRITICA"), (7, "ALTA"), (5, "MEDIA"), (3, "BAIXA"))


# --------------------------------------------------------------------
# Carregamento e classificação
# --------------------------------------------------------------------

def carregar_regras(caminho_config=ARQUIVO_REGRAS):
    """
    Lê o arquivo regras.json e retorna a lista de regras.
    Arquivo inexistente ou JSON inválido: avisa e retorna lista vazia.
    """
    try:
        with open(caminho_config, "r", encoding="utf-8") as arquivo:
            return json.load(arquivo)["regras"]
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras não encontrado: {caminho_config}")
    except json.JSONDecodeError as erro:
        print(f"[ERRO] regras.json com JSON inválido (linha {erro.lineno}). "
              "Nenhuma regra foi carregada: corrija o arquivo.")
    except KeyError:
        print("[ERRO] regras.json não tem a chave 'regras'.")
    return []


def classificar_severidade(pontuacao):
    """>= 9: CRITICA, >= 7: ALTA, >= 5: MEDIA, >= 3: BAIXA, < 3: INFO"""
    for minimo, severidade in FAIXAS_SEVERIDADE:
        if pontuacao >= minimo:
            return severidade
    return "INFO"


def ler_detalhe(evento, chave):
    """
    Pega um valor de dentro de 'detalhes'.
    Ex.: detalhes "proto=TCP dst=10.0.0.1 dport=22", chave "dport" -> "22"
    """
    for pedaco in evento["detalhes"].split():
        if pedaco.startswith(chave + "="):
            return pedaco.split("=", 1)[1]
    return None


# --------------------------------------------------------------------
# Condições: cada uma devolve a descrição do problema, ou None
# --------------------------------------------------------------------

def _usuario_privilegiado(regra, evento):
    usuario = ler_detalhe(evento, "usuario")
    if usuario in regra["usuarios_alvo"]:
        return f"Login {evento['tipo']} com usuário privilegiado '{usuario}'"
    return None


def _porta_critica(regra, evento):
    porta = ler_detalhe(evento, "dport")
    if evento["tipo"] == "BLOCK" and porta and int(porta) in regra["portas_criticas"]:
        return f"Acesso bloqueado à porta crítica {porta}"
    return None


def _padrao_na_url(regra, evento):
    """Usada por path_traversal e xss: procura um dos padrões na URL."""
    url = ler_detalhe(evento, "url") or ""
    if any(padrao in url for padrao in regra["padroes"]):
        return f"URL suspeita: {url}"
    return None


def _reconhecimento(regra, evento):
    url = ler_detalhe(evento, "url") or ""
    caminho = url.split("?")[0]   # ignora o que vem depois do "?"
    if caminho in regra["urls_suspeitas"]:
        return f"Acesso a URL de reconhecimento: {caminho}"
    return None


# Dicionário que liga o nome da condição (no JSON) à função que a verifica
CONDICOES = {
    "usuario_privilegiado": _usuario_privilegiado,
    "porta_critica": _porta_critica,
    "path_traversal": _padrao_na_url,
    "xss": _padrao_na_url,
    "reconhecimento": _reconhecimento,
}


# --------------------------------------------------------------------
# Aplicação das regras
# --------------------------------------------------------------------

def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra específica.
    Retorna o dict do alerta, ou None se não violar.
    """
    if regra["fonte"] != evento["fonte"]:
        return None
    verificar = CONDICOES.get(regra["condicao"])
    if verificar is None:
        return None

    descricao = verificar(regra, evento)
    if descricao is None:
        return None
    return {
        "timestamp": evento["timestamp"],
        "regra": regra["nome"],
        "regra_id": regra["id"],
        "severidade": classificar_severidade(regra["severidade_base"]),
        "pontuacao": regra["severidade_base"],
        "ip": evento["ip"],
        "descricao": descricao,
    }


def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras ATIVAS a todos os eventos.
    Retorna a lista de alertas gerados.
    """
    regras_ativas = [regra for regra in regras if regra.get("ativa", False)]
    alertas = []
    for evento in eventos:
        for regra in regras_ativas:
            alerta = avaliar_regra(regra, evento)
            if alerta is not None:
                alertas.append(alerta)
    return alertas


# --------------------------------------------------------------------
# Teste do módulo: python -m core.regras
# --------------------------------------------------------------------
if __name__ == "__main__":
    from core.coletor import carregar_todos_os_logs

    eventos = carregar_todos_os_logs(os.path.join(PASTA_PROJETO, "logs"))
    regras = carregar_regras()
    alertas = aplicar_regras(eventos, regras)

    ativas = len([r for r in regras if r.get("ativa")])
    print(f"Regras carregadas: {len(regras)} ({ativas} ativas)")
    print(f"Eventos analisados: {len(eventos)} | Alertas gerados: {len(alertas)}\n")

    contagem = {}
    for alerta in alertas:
        contagem[alerta["regra_id"]] = contagem.get(alerta["regra_id"], 0) + 1
    for regra in regras:
        print(f"  {regra['id']} {regra['nome']:<34} {contagem.get(regra['id'], 0):>3} alertas")

    print("\nExemplos:")
    for regra_id in ("R001", "R002", "R003", "R004", "R005"):
        exemplo = next((a for a in alertas if a["regra_id"] == regra_id), None)
        if exemplo:
            print(f"  [{exemplo['severidade']:<7}] {exemplo['ip']:<15} {exemplo['descricao']}")