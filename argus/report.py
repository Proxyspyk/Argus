"""
report.py
=========

Formata os resultados do scan para o terminal (com cores) e para JSON
(para integrar com outras ferramentas/pipelines de CI).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from .collectors import SystemInfo
from .matcher import Finding

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_DIM = "\033[2m"


def _risk_color(score: float) -> str:
    if score >= 70:
        return _RED
    if score >= 40:
        return _YELLOW
    return _GREEN


def print_terminal_report(
    system_info: SystemInfo, findings: list[Finding], errors: list[str]
) -> None:
    print(f"{_BOLD}{_CYAN}Argus — Linux CVE Auditor{_RESET}")
    print(f"{_DIM}Scan em {datetime.now(timezone.utc).isoformat(timespec='seconds')}Z{_RESET}\n")

    print(f"{_BOLD}[+] Sistema{_RESET}")
    print(f"    Distro : {system_info.distro_name or '?'} {system_info.distro_version or ''}")
    print(f"    Kernel : {system_info.kernel_version}")
    print(f"    Arch   : {system_info.arch}\n")

    print(f"{_BOLD}[+] Componentes detectados{_RESET}")
    for c in system_info.components:
        print(f"    {c.name:<10} {c.version or '?':<20} ({c.source})")
    print()

    if not findings:
        print(f"{_GREEN}Nenhuma CVE correspondente encontrada nas fontes consultadas.{_RESET}")
    else:
        print(f"{_BOLD}[+] Possíveis vulnerabilidades ({len(findings)}){_RESET}\n")
        for f in findings:
            color = _risk_color(f.risk_score)
            print(f"{color}{_BOLD}{f.cve.cve_id}{_RESET}  {color}risco: {f.risk_score}/100{_RESET}")
            print(f"    Componente : {f.component.name} {f.component.version}")
            print(f"    CVSS       : {f.cve.cvss_score} ({f.cve.cvss_severity})")
            epss_str = f"{f.epss_score:.1%}" if f.epss_score is not None else "N/D"
            print(f"    EPSS       : {epss_str}")
            exploit = "✔ indício de exploit público" if f.has_public_exploit else "sem indício de exploit público"
            exploit_color = _RED if f.has_public_exploit else _DIM
            print(f"    Exploit    : {exploit_color}{exploit}{_RESET}")
            desc = f.cve.description[:160] + ("…" if len(f.cve.description) > 160 else "")
            print(f"    Descrição  : {desc}")
            print()

    if errors:
        print(f"{_YELLOW}[!] Avisos durante o scan:{_RESET}")
        for err in errors:
            print(f"    - {err}")
        print()

    print(
        f"{_DIM}Nota: matching é por palavra-chave + heurística de versão, "
        f"não por CPE exato. Trate como priorização, não como confirmação "
        f"definitiva — sempre valide manualmente antes de agir.{_RESET}"
    )


def build_json_report(
    system_info: SystemInfo, findings: list[Finding], errors: list[str]
) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z",
        "system": {
            "distro_name": system_info.distro_name,
            "distro_version": system_info.distro_version,
            "kernel_version": system_info.kernel_version,
            "arch": system_info.arch,
            "components": [asdict(c) for c in system_info.components],
        },
        "findings": [
            {
                "cve_id": f.cve.cve_id,
                "component": f.component.name,
                "installed_version": f.component.version,
                "cvss_score": f.cve.cvss_score,
                "cvss_severity": f.cve.cvss_severity,
                "epss_score": f.epss_score,
                "risk_score": f.risk_score,
                "has_public_exploit_hint": f.has_public_exploit,
                "description": f.cve.description,
                "references": f.cve.references,
            }
            for f in findings
        ],
        "warnings": errors,
    }


def write_json_report(path: str, system_info: SystemInfo, findings: list[Finding], errors: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_json_report(system_info, findings, errors), fh, indent=2, ensure_ascii=False)
