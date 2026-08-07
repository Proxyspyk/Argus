from unittest.mock import MagicMock, patch

from argus.collectors import Component
from argus.matcher import (
    _compute_risk_score,
    _version_mentioned,
    find_vulnerabilities,
)
from argus.nvd_client import CVEEntry


def make_cve(cve_id="CVE-2026-0001", cvss=8.8, refs=None, description=""):
    return CVEEntry(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss,
        cvss_severity="HIGH",
        published="2026-01-01T00:00:00",
        references=refs or [],
    )


def test_version_mentioned_true_when_no_version():
    assert _version_mentioned(None, "any description") is True


def test_version_mentioned_matches_prefix():
    assert _version_mentioned("1.9.15p5", "affects sudo versions before 1.9.15") is True


def test_version_mentioned_false_when_absent():
    assert _version_mentioned("9.9.9", "affects versions before 1.2.3") is False


def test_version_mentioned_strips_debian_epoch_and_revision():
    # caso real: openssh no Debian/Parrot vem como "1:10.0p1-7+deb13u4"
    assert _version_mentioned("1:10.0p1-7+deb13u4", "OpenSSH 10.0 client issue") is True


def test_version_mentioned_strips_ubuntu_build_suffix():
    assert _version_mentioned("2.39-0ubuntu8.7", "glibc 2.39 heap overflow") is True


def test_risk_score_bonus_for_public_exploit():
    cve_with_exploit = make_cve(refs=["https://example.com/Exploit"])
    cve_without = make_cve(refs=["https://example.com/Patch"])

    score_with = _compute_risk_score(cve_with_exploit, epss=0.9)
    score_without = _compute_risk_score(cve_without, epss=0.9)

    assert score_with > score_without


def test_risk_score_bounded_at_100():
    cve = make_cve(cvss=10.0, refs=["exploit"])
    score = _compute_risk_score(cve, epss=1.0)
    assert score <= 100.0


@patch("argus.matcher.get_epss_scores")
def test_find_vulnerabilities_filters_and_sorts(mock_epss):
    component = Component(name="sudo", version="1.9.15", source="binary")

    mock_client = MagicMock()
    mock_client.search_by_keyword.return_value = [
        make_cve("CVE-2026-0001", cvss=9.8, description="sudo 1.9.15 heap overflow"),
        make_cve("CVE-2026-0002", cvss=5.0, description="unrelated version 2.2.2"),
    ]
    mock_epss.return_value = {"CVE-2026-0001": 0.95}

    findings, errors = find_vulnerabilities([component], nvd_client=mock_client)

    assert len(findings) == 1
    assert findings[0].cve.cve_id == "CVE-2026-0001"
    assert not errors


@patch("argus.matcher.get_epss_scores")
def test_nvd_search_called_with_name_only_not_raw_version(mock_epss):
    """
    Regressão: passar a versão crua (ex: "1:10.0p1-7+deb13u4") junto na
    keyword search do NVD zera os resultados, porque a API exige que
    todas as palavras da busca apareçam no texto. A busca deve usar
    só o nome do componente; o filtro de versão é feito localmente.
    """
    component = Component(name="openssh", version="1:10.0p1-7+deb13u4", source="dpkg")
    mock_client = MagicMock()
    mock_client.search_by_keyword.return_value = []
    mock_epss.return_value = {}

    find_vulnerabilities([component], nvd_client=mock_client)

    mock_client.search_by_keyword.assert_called_once_with("openssh")


@patch("argus.matcher.get_epss_scores")
def test_on_component_result_reports_raw_vs_filtered_counts(mock_epss):
    component = Component(name="sudo", version="1.9.15", source="binary")

    mock_client = MagicMock()
    mock_client.search_by_keyword.return_value = [
        make_cve("CVE-2026-0001", cvss=9.8, description="sudo 1.9.15 heap overflow"),
        make_cve("CVE-2026-0002", cvss=5.0, description="unrelated version 2.2.2"),
    ]
    mock_epss.return_value = {}

    seen = []
    find_vulnerabilities(
        [component],
        nvd_client=mock_client,
        on_component_result=lambda name, raw, filtered: seen.append((name, raw, filtered)),
    )

    assert seen == [("sudo", 2, 1)]  # 2 CVEs vieram do NVD, só 1 passou no filtro de versão
