"""
matcher.py
==========

Cruza os componentes detectados localmente (collectors.py) com CVEs
retornadas pelo NVD, aplica o score EPSS e produz uma lista de
`Finding` ordenada por risco.

Importante: a busca do NVD é por palavra-chave (não por CPE exato), então
o matcher aplica um filtro extra tentando comparar a versão instalada
com trechos numéricos mencionados na descrição da CVE. Isso reduz falsos
positivos, mas NÃO substitui uma checagem CPE completa — o relatório
deixa isso explícito (ver report.py) para evitar excesso de confiança.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .collectors import Component
from .epss_client import get_epss_scores
from .nvd_client import CVEEntry, NVDClient, NVDRequestError


@dataclass
class Finding:
    component: Component
    cve: CVEEntry
    epss_score: float | None
    risk_score: float  # 0-100, combina CVSS + EPSS + exploit público

    @property
    def has_public_exploit(self) -> bool:
        return self.cve.has_public_exploit_hint


def _normalize_version(version: str) -> str:
    """
    Normaliza formatos de versão de distro para o "núcleo" upstream, ex:
        "1:10.0p1-7+deb13u4"  -> "10.0p1"   (remove epoch e revisão Debian)
        "2.41-12+deb13u4"     -> "2.41"
        "3.0.13-0ubuntu3.9"   -> "3.0.13"
    Sem isso, versões de pacotes Debian/Ubuntu (que incluem epoch e
    revisão do empacotador) nunca batem com o texto puro das descrições
    de CVE no NVD.
    """
    version = version.split(":", 1)[-1]  # remove epoch (ex: "1:10.0p1" -> "10.0p1")
    version = version.split("-", 1)[0]  # remove revisão do pacote (ex: "-7+deb13u4")
    version = version.split("+", 1)[0]  # remove sufixo de build (ex: "+deb13u4")
    return version


def _version_mentioned(version: str | None, description: str) -> bool:
    """
    Heurística leve: verifica se algum prefixo numérico da versão instalada
    (major.minor ou major.minor.patch) aparece na descrição da CVE.
    Retorna True também quando não há versão pra comparar (não filtra).
    """
    if not version:
        return True

    normalized = _normalize_version(version)

    # extrai só os componentes numéricos (ex: "10.0p1" -> ["10", "0"]),
    # ignorando sufixos de letras coladas (p1, a, rc1, etc.)
    numeric_parts = re.findall(r"\d+", normalized)

    candidates = {version, normalized}
    if len(numeric_parts) >= 2:
        candidates.add(".".join(numeric_parts[:2]))
    if len(numeric_parts) >= 3:
        candidates.add(".".join(numeric_parts[:3]))

    return any(c and c in description for c in candidates)


def _compute_risk_score(cve: CVEEntry, epss: float | None) -> float:
    """
    Combina CVSS (0-10) e EPSS (0-1) num score único 0-100, dando um bônus
    se há indício de exploit público. É uma heurística de priorização,
    não uma métrica oficial.
    """
    cvss = cve.cvss_score or 0.0
    epss_val = epss or 0.0
    base = (cvss / 10.0) * 60 + epss_val * 30
    bonus = 10.0 if cve.has_public_exploit_hint else 0.0
    return round(min(base + bonus, 100.0), 1)


def find_vulnerabilities(
    components: list[Component],
    nvd_client: NVDClient | None = None,
    strict_version_filter: bool = True,
    on_progress=None,
    on_component_result=None,
) -> tuple[list[Finding], list[str]]:
    """
    Para cada componente, busca CVEs relacionadas no NVD, filtra por versão
    (opcional) e calcula o risk_score combinando CVSS + EPSS.

    on_component_result(component_name, raw_count, filtered_count), se
    fornecido, é chamado após cada consulta — útil para diagnosticar se
    "zero resultados" é porque o NVD não retornou nada (raw_count == 0)
    ou porque o filtro de versão descartou tudo (raw_count > 0 e
    filtered_count == 0).

    Retorna (findings, erros) — erros são mensagens de componentes que
    falharam na consulta (ex: rate limit, timeout), para não derrubar
    o scan inteiro por causa de uma falha pontual.
    """
    client = nvd_client or NVDClient()
    all_findings: list[Finding] = []
    errors: list[str] = []
    all_cves: list[CVEEntry] = []
    pending: list[tuple[Component, CVEEntry]] = []

    for component in components:
        if on_progress:
            on_progress(component.name)
        try:
            # Busca só pelo NOME do componente. Passar a versão crua do
            # pacote (ex: "1.9.16p2-3+deb13u2") para a keyword search do
            # NVD zera os resultados, porque a API exige que todas as
            # palavras da busca apareçam no texto — e essa string de
            # versão nunca aparece literalmente numa descrição de CVE.
            # A filtragem por versão é feita localmente, depois, em
            # _version_mentioned (que já normaliza formatos Debian/Ubuntu).
            cves = client.search_by_keyword(component.name)
        except NVDRequestError as exc:
            errors.append(str(exc))
            continue

        filtered_count = 0
        for cve in cves:
            if strict_version_filter and not _version_mentioned(
                component.version, cve.description
            ):
                continue
            pending.append((component, cve))
            all_cves.append(cve)
            filtered_count += 1

        if on_component_result:
            on_component_result(component.name, len(cves), filtered_count)

    epss_map = {}
    if all_cves:
        try:
            epss_map = get_epss_scores([c.cve_id for c in all_cves])
        except Exception:  # noqa: BLE001 - EPSS é um bônus, não pode quebrar o scan
            errors.append("Não foi possível obter scores EPSS (seguindo sem eles).")

    for component, cve in pending:
        epss = epss_map.get(cve.cve_id)
        risk = _compute_risk_score(cve, epss)
        all_findings.append(Finding(component, cve, epss, risk))

    all_findings.sort(key=lambda f: f.risk_score, reverse=True)
    return all_findings, errors
