"""
ui.py
=====

Elementos visuais de terminal do Argus: o banner ASCII exibido no início
e um spinner de "olho piscando" mostrado enquanto o scan consulta as
APIs externas (a parte mais lenta, por causa do rate limit do NVD).
"""

from __future__ import annotations

import shutil
import sys
import threading
import time

_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

# Banner estático mostrado uma vez, no início do scan.
ARGUS_EYE_ART = r"""
              _.-'''''-._
           ,-'             `-.
         ,'                   `.
        /      .-'''''-.       \
       |      /         \       |
       |     |    .-.    |      |
       |     |   ( ● )   |      |
       |     |    '-'    |      |
       |      \         /       |
        \      '-.....-'       /
         `.                  ,'
           `-._           _,-'
               `'-------'`
"""

ARGUS_TITLE = "ARGUS"
ARGUS_SUBTITLE = "cem olhos, nenhum descanso  //  Linux CVE Auditor"

# Estados do olho para o spinner de uma linha só (aberto -> piscando -> aberto).
_EYE_FRAMES = ["◉", "◉", "◉", "◔", "─", "◔", "◉"]


class EyeSpinner:
    """
    Spinner de terminal que anima um olho piscando numa única linha,
    junto com um texto de status atualizável (ex: "consultando: sudo").

    Uso:
        with EyeSpinner() as eye:
            eye.status("consultando: sudo")
            ... trabalho lento ...
            eye.status("consultando: bash")
    """

    def __init__(self, interval: float = 0.15, stream=sys.stderr) -> None:
        self.interval = interval
        self.stream = stream
        self._status = "iniciando..."
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._is_tty = hasattr(stream, "isatty") and stream.isatty()

    def status(self, text: str) -> None:
        with self._lock:
            self._status = text

    def log(self, text: str) -> None:
        """
        Imprime uma linha permanente (ex: diagnóstico de um componente)
        sem atropelar a animação: limpa a linha do spinner, escreve o
        log com quebra de linha, e o spinner continua embaixo dele.
        """
        with self._lock:
            if self._is_tty:
                width = shutil.get_terminal_size(fallback=(80, 20)).columns
                self.stream.write("\r" + " " * (width - 1) + "\r")
            self.stream.write(text + "\n")
            self.stream.flush()

    def _render_loop(self) -> None:
        frame_index = 0
        while not self._stop_event.is_set():
            with self._lock:
                text = self._status
                frame = _EYE_FRAMES[frame_index % len(_EYE_FRAMES)]
                line = f"{_CYAN}{frame}{_RESET}  {_DIM}{text}{_RESET}"
                self._write_line(line)
            frame_index += 1
            time.sleep(self.interval)

    def _write_line(self, line: str) -> None:
        if not self._is_tty:
            return  # evita poluir logs/CI com sequências de carriage return
        width = shutil.get_terminal_size(fallback=(80, 20)).columns
        padded = line[: width - 1].ljust(width - 1)
        self.stream.write(f"\r{padded}")
        self.stream.flush()

    def __enter__(self) -> "EyeSpinner":
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1)
        if self._is_tty:
            width = shutil.get_terminal_size(fallback=(80, 20)).columns
            self.stream.write("\r" + " " * (width - 1) + "\r")
            self.stream.flush()


def print_banner(stream=sys.stderr) -> None:
    print(f"{_CYAN}{ARGUS_EYE_ART}{_RESET}", file=stream)
    width = shutil.get_terminal_size(fallback=(80, 20)).columns
    print(f"{_BOLD}{_CYAN}{ARGUS_TITLE.center(width)}{_RESET}", file=stream)
    print(f"{_DIM}{ARGUS_SUBTITLE.center(width)}{_RESET}\n", file=stream)
