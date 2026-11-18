"""DorkHunter Pro — punto de entrada.

Ejecuta la aplicación de escritorio, inicializa SQLite y muestra el aviso legal
en la primera ejecución. No contiene lógica de búsqueda ni de escaneo.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

# Permite ejecutar `python main.py` desde cualquier directorio.
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# El modo CLI se despacha antes de importar Tkinter/CustomTkinter para que
# funcione en servidores sin entorno gráfico.
if __name__ == "__main__" and "--cli" in sys.argv[1:]:
    from cli import main as cli_main

    sys.argv.remove("--cli")
    raise SystemExit(cli_main())

import customtkinter as ctk

from config import (
    APP_NAME,
    APP_VERSION,
    DB_PATH,
    DISCLAIMER_VERSION,
    HTTP_TIMEOUT,
)
from database.db_manager import DatabaseManager
from gui.dashboard import Dashboard
from gui.disclaimer import DisclaimerDialog
from gui.theme import apply_theme
from utils.helpers import now_iso

# Una consulta WHOIS mal comportada no debe bloquear la aplicación.
socket.setdefaulttimeout(max(HTTP_TIMEOUT, 15))


class DorkHunterApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title(f"{APP_NAME} · v{APP_VERSION}")
        self.geometry("1340x860")
        self.minsize(1140, 740)
        apply_theme(self)

        self.db = DatabaseManager(DB_PATH)
        self.dashboard = Dashboard(self, self.db)
        self.dashboard.pack(fill="both", expand=True)

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(200, self._maybe_show_disclaimer)

    # ------------------------------------------------------------------
    def _maybe_show_disclaimer(self) -> None:
        accepted = self.db.get_setting("disclaimer_accepted_version")
        if accepted == DISCLAIMER_VERSION:
            return

        dialog = DisclaimerDialog(self)
        self.wait_window(dialog)
        if not dialog.accepted:
            self.destroy()
            return

        self.db.set_setting("disclaimer_accepted_version", DISCLAIMER_VERSION)
        self.db.set_setting("disclaimer_accepted_at", now_iso())

    def _on_close(self) -> None:
        stopped = self.dashboard.shutdown()
        if stopped:
            self.db.close()
        # Si un hilo sigue esperando una respuesta HTTP, el proceso terminará
        # igualmente porque los hilos de trabajo son daemon.
        self.destroy()


def main() -> None:
    app = DorkHunterApp()
    app.mainloop()


if __name__ == "__main__":
    main()
