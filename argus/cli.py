"""
cli.py
======

Interface de linha de comando do Argus.

Uso:
    argus scan
    argus scan --json report.json
    argus scan --no-version-filter
"""

from __future__ import annotations

import argparse
import sys

from .collectors import collect_system_info
from .matcher import find_vulnerabilities
from .nvd_client import NVDClient
from .report import print_terminal_report, write_json_report
from .ui import EyeSpinner, print_banner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description=(
            "Argus - detecta versões de componentes críticos do sistema e cruza "
            "com CVEs / EPSS / indícios de exploit público."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Executa o scan e gera o relatório")
    scan.add_argument(
        "--json", metavar="PATH", help="Também salva o relatório em JSON no caminho indicado"
    )
    scan.add_argument(
        "--no-version-filter",
        action="store_true",
        help="Desativa o filtro heurístico de versão (mais resultados, mais ruído)",
    )
    scan.add_argument(
        "--api-key",
        metavar="KEY",
        help="API key do NVD (opcional, aumenta o rate limit). Também pode vir de NVD_API_KEY.",
    )
    scan.add_argument(
        "--no-banner",
        action="store_true",
        help="Não imprime o banner ASCII do Argus (útil em CI/logs)",
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    if not args.no_banner:
        print_banner()

    print("[*] Coletando informações do sistema...", file=sys.stderr)
    system_info = collect_system_info()

    if not system_info.components:
        print(
            "[!] Nenhum componente-alvo foi detectado. "
            "Rode em um sistema Linux com dpkg/rpm ou os binários esperados.",
            file=sys.stderr,
        )

    client = NVDClient(api_key=args.api_key)

    with EyeSpinner() as eye:
        def _progress(name: str) -> None:
            eye.status(f"consultando CVEs para: {name}")

        def _result(name: str, raw_count: int, filtered_count: int) -> None:
            if raw_count == 0:
                eye.log(f"    -> NVD não retornou nenhuma CVE para '{name}'")
            elif filtered_count == 0:
                eye.log(
                    f"    -> NVD retornou {raw_count} CVE(s) para '{name}', mas nenhuma "
                    f"bateu com a versão instalada (filtro de versão descartou tudo)"
                )
            else:
                eye.log(f"    -> {filtered_count}/{raw_count} CVE(s) relevantes para '{name}'")

        eye.status("iniciando consulta ao NVD/EPSS...")
        findings, errors = find_vulnerabilities(
            system_info.components,
            nvd_client=client,
            strict_version_filter=not args.no_version_filter,
            on_progress=_progress,
            on_component_result=_result,
        )

    print()  # separa logs de progresso do relatório
    print_terminal_report(system_info, findings, errors)

    if args.json:
        write_json_report(args.json, system_info, findings, errors)
        print(f"\n[*] Relatório JSON salvo em: {args.json}", file=sys.stderr)

    return 1 if any(f.risk_score >= 70 for f in findings) else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
