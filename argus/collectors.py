"""
collectors.py
=============

Coleta informações do sistema local: kernel, distribuição e versões de
componentes que costumam aparecer em CVEs de escalada de privilégio
(glibc, sudo, systemd, polkit, openssl, docker, podman, snap, etc).

Todo o código aqui é *somente leitura*: nenhuma coleta executa exploits,
altera o sistema ou requer root (embora alguns comandos possam retornar
mais informação se rodados como root).
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class Component:
    """Representa um componente do sistema com uma versão detectada."""

    name: str
    version: str | None
    source: str  # como a versão foi obtida (ex: "dpkg", "rpm", "binary --version")
    raw: str = ""  # saída bruta, útil para debug


@dataclass
class SystemInfo:
    kernel_version: str | None
    distro_name: str | None
    distro_version: str | None
    arch: str
    components: list[Component] = field(default_factory=list)


def _run(cmd: list[str]) -> str | None:
    """
    Executa um comando e retorna stdout apenas se o processo terminou com
    sucesso (returncode 0). Retorna None em caso de falha, timeout, ou
    binário inexistente — isso evita capturar mensagens de erro (ex:
    "package not found") como se fossem uma versão válida.
    """
    if shutil.which(cmd[0]) is None:
        return None
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _extract_version(text: str | None) -> str | None:
    """Extrai o primeiro padrão parecido com versão semântica de um texto."""
    if not text:
        return None
    match = re.search(r"(\d+\.\d+(?:\.\d+){0,3}(?:-[\w.]+)?)", text)
    return match.group(1) if match else None


def get_kernel_version() -> str:
    return platform.release()


def get_distro_info() -> tuple[str | None, str | None]:
    """Lê /etc/os-release para nome e versão da distro."""
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            data = {}
            for line in fh:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    data[key] = value.strip('"')
        return data.get("NAME"), data.get("VERSION_ID")
    except FileNotFoundError:
        return None, None


def _detect_via_package_manager(pkg_name: str) -> Component | None:
    """Tenta obter a versão de um pacote via dpkg ou rpm."""
    dpkg_out = _run(["dpkg-query", "-W", "-f=${Version}", pkg_name])
    if dpkg_out:
        return Component(pkg_name, dpkg_out.strip(), source="dpkg", raw=dpkg_out)

    rpm_out = _run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg_name])
    if rpm_out and "not installed" not in rpm_out:
        return Component(pkg_name, rpm_out.strip(), source="rpm", raw=rpm_out)

    return None


def _detect_via_binary(name: str, binary: str, args: list[str]) -> Component | None:
    """Tenta obter a versão executando `binary args` (ex: `sudo --version`)."""
    out = _run([binary, *args])
    version = _extract_version(out)
    if version:
        return Component(name, version, source=f"{binary} {' '.join(args)}", raw=out or "")
    return None


# (nome lógico, nome(s) de pacote candidatos, binário, args para --version)
_TARGET_COMPONENTS: list[tuple[str, list[str], str | None, list[str]]] = [
    ("glibc", ["libc6", "glibc"], "ldd", ["--version"]),
    ("sudo", ["sudo"], "sudo", ["-V"]),
    ("systemd", ["systemd"], "systemctl", ["--version"]),
    ("polkit", ["policykit-1", "polkit"], "pkexec", ["--version"]),
    ("openssl", ["openssl"], "openssl", ["version"]),
    ("docker", ["docker-ce", "docker.io"], "docker", ["--version"]),
    ("podman", ["podman"], "podman", ["--version"]),
    ("snapd", ["snapd"], "snap", ["--version"]),
    ("bash", ["bash"], "bash", ["--version"]),
    ("openssh", ["openssh-server", "openssh"], "ssh", ["-V"]),
]


def collect_components() -> list[Component]:
    """Coleta a versão de cada componente-alvo, tentando múltiplas fontes."""
    found: list[Component] = []

    for name, pkg_candidates, binary, args in _TARGET_COMPONENTS:
        component: Component | None = None

        for pkg in pkg_candidates:
            component = _detect_via_package_manager(pkg)
            if component:
                component.name = name  # normaliza o nome lógico
                break

        if component is None and binary is not None:
            component = _detect_via_binary(name, binary, args)

        if component:
            found.append(component)

    return found


def collect_system_info() -> SystemInfo:
    """Ponto de entrada principal: coleta tudo que o auditor precisa."""
    distro_name, distro_version = get_distro_info()
    return SystemInfo(
        kernel_version=get_kernel_version(),
        distro_name=distro_name,
        distro_version=distro_version,
        arch=platform.machine(),
        components=collect_components(),
    )
