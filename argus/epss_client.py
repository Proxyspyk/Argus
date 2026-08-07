"""
epss_client.py
===============

Cliente para a API EPSS (Exploit Prediction Scoring System) do FIRST.org:
https://www.first.org/epss/api

EPSS estima, de 0 a 1, a probabilidade de uma CVE ser explorada nos
próximos 30 dias com base em dados observados na internet. É um ótimo
complemento ao CVSS (que mede severidade, não probabilidade real de uso).
"""

from __future__ import annotations

import requests

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Retorna um dict {cve_id: epss_score} para até 100 CVEs por chamada
    (limite prático da API). CVEs sem score conhecido são omitidas.
    """
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        params = {"cve": ",".join(batch)}
        try:
            resp = requests.get(EPSS_BASE_URL, params=params, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise EPSSRequestError(f"Falha ao consultar EPSS: {exc}") from exc

        data = resp.json()
        for entry in data.get("data", []):
            try:
                scores[entry["cve"]] = float(entry["epss"])
            except (KeyError, ValueError):
                continue

    return scores


class EPSSRequestError(RuntimeError):
    """Erro ao consultar a API EPSS (rede ou resposta inválida)."""
