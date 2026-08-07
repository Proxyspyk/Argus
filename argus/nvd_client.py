"""
nvd_client.py
=============

Cliente simples para a API pública do NVD (National Vulnerability Database)
v2.0: https://nvd.nist.gov/developers/vulnerabilities

Sem API key o rate limit é baixo (~5 requisições / 30s), então o cliente
aplica um throttle conservador e cacheia resultados em memória por execução.
Uma API key gratuita (env var NVD_API_KEY) aumenta o limite para 50/30s.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_severity: str | None
    published: str | None
    references: list[str] = field(default_factory=list)

    @property
    def has_public_exploit_hint(self) -> bool:
        """Heurística simples: referências marcadas como 'Exploit' no NVD."""
        return any("exploit" in ref.lower() for ref in self.references)


class NVDClient:
    def __init__(self, api_key: str | None = None, min_delay: float = 6.0) -> None:
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        # sem key: ~1 req/6s é seguro para não estourar 5/30s
        self.min_delay = 1.2 if self.api_key else min_delay
        self._last_request_ts = 0.0
        self._cache: dict[str, list[CVEEntry]] = {}

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_request_ts
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        self._last_request_ts = time.time()

    def search_by_keyword(
        self, keyword: str, version: str | None = None, results_per_page: int = 50
    ) -> list[CVEEntry]:
        """
        Busca CVEs por palavra-chave. Termos genéricos (ex: "bash", "sudo",
        "openssl") costumam ter centenas ou milhares de CVEs ao longo dos
        anos. Por padrão o NVD ordena por CVE ID ascendente (mais antigas
        primeiro), então pegar só a primeira página retornaria CVEs de
        décadas atrás — inúteis pra auditar um sistema atualizado.

        Por isso: se `totalResults` (informado na própria resposta) for
        maior que `results_per_page`, refaz a consulta pulando direto para
        o final da lista via `startIndex`, trazendo as CVEs mais recentes
        em vez das mais antigas.
        """
        query = keyword
        if query in self._cache:
            return self._cache[query]

        headers = {"apiKey": self.api_key} if self.api_key else {}
        data = self._fetch_page(query, headers, results_per_page, start_index=0)

        total_results = data.get("totalResults", 0)
        if total_results > results_per_page:
            recent_start_index = max(0, total_results - results_per_page)
            data = self._fetch_page(query, headers, results_per_page, recent_start_index)

        entries = [self._parse_vulnerability(v) for v in data.get("vulnerabilities", [])]
        self._cache[query] = entries
        return entries

    def _fetch_page(
        self, query: str, headers: dict, results_per_page: int, start_index: int
    ) -> dict:
        params = {
            "keywordSearch": query,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        self._throttle()
        try:
            resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise NVDRequestError(f"Falha ao consultar NVD para '{query}': {exc}") from exc
        return resp.json()

    @staticmethod
    def _parse_vulnerability(vuln: dict) -> CVEEntry:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        metrics = cve.get("metrics", {})
        cvss_score, cvss_severity = None, None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                cvss_data = metrics[metric_key][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get(
                    "baseSeverity", metrics[metric_key][0].get("baseSeverity")
                )
                break

        references = [r.get("url", "") for r in cve.get("references", [])]

        return CVEEntry(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            published=cve.get("published"),
            references=references,
        )


class NVDRequestError(RuntimeError):
    """Erro ao consultar a API do NVD (rede, rate limit, resposta inválida)."""
