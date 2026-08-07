from unittest.mock import MagicMock, patch

from argus.nvd_client import NVDClient


def _mock_response(total_results: int, vulnerabilities: list[dict]):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {
        "totalResults": total_results,
        "vulnerabilities": vulnerabilities,
    }
    return resp


def _fake_vuln(cve_id: str) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"desc for {cve_id}"}],
            "metrics": {},
            "references": [],
            "published": "2026-01-01T00:00:00",
        }
    }


@patch("argus.nvd_client.requests.get")
def test_search_does_single_request_when_results_fit_in_one_page(mock_get):
    # totalResults (2) <= results_per_page (50): não deve haver segunda chamada
    mock_get.return_value = _mock_response(2, [_fake_vuln("CVE-2026-0001"), _fake_vuln("CVE-2026-0002")])

    client = NVDClient(min_delay=0)
    entries = client.search_by_keyword("openssl", results_per_page=50)

    assert mock_get.call_count == 1
    assert len(entries) == 2


@patch("argus.nvd_client.requests.get")
def test_search_refetches_most_recent_page_when_total_exceeds_page_size(mock_get):
    # totalResults (500) > results_per_page (50): deve refazer a consulta
    # com startIndex apontando para o FINAL da lista (CVEs mais recentes),
    # não para o início (CVEs mais antigas).
    first_page = _mock_response(500, [_fake_vuln("CVE-1999-0001")])  # simulando página antiga
    recent_page = _mock_response(500, [_fake_vuln("CVE-2026-9999")])  # página recente real
    mock_get.side_effect = [first_page, recent_page]

    client = NVDClient(min_delay=0)
    entries = client.search_by_keyword("bash", results_per_page=50)

    assert mock_get.call_count == 2
    second_call_params = mock_get.call_args_list[1].kwargs["params"]
    assert second_call_params["startIndex"] == 450  # 500 - 50
    assert entries[0].cve_id == "CVE-2026-9999"


@patch("argus.nvd_client.requests.get")
def test_search_by_keyword_ignores_raw_version_in_query(mock_get):
    """A query enviada ao NVD deve ser só o keyword, nunca incluir versão."""
    mock_get.return_value = _mock_response(0, [])

    client = NVDClient(min_delay=0)
    client.search_by_keyword("sudo")

    sent_params = mock_get.call_args.kwargs["params"]
    assert sent_params["keywordSearch"] == "sudo"
