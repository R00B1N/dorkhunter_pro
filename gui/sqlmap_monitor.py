"""Monitoreo en vivo de los procesos SQLMap.

Cada URL verificada tiene un panel con la salida estándar de su proceso
``sqlmap`` en tiempo real. Los eventos llegan por la cola de la GUI
(``sqlmap_started``, ``sqlmap_line``, ``sqlmap``) y ``Dashboard`` los
reenvía a ``handle_event`` desde el hilo principal de Tk, así que este
módulo no necesita sincronización extra.

Los paneles se etiquetan como ``[W1]..[Wn]`` (un worker = un proceso
sqlmap simultáneo). Se muestran como máximo ``MAX_PANELS`` en pantalla;
cuando uno nuevo arranca y no hay espacio, se reutiliza el panel terminado
más antiguo.
"""
from __future__ import annotations

from typing import Any

import customtkinter as ctk

from core.sqlmap_runner import (
    SQLMAP_CLEAN,
    SQLMAP_ERROR,
    SQLMAP_VULNERABLE,
)
from gui.theme import COLORS, font

MAX_PANELS = 8
MAX_LINES_PER_PANEL = 400

# estado interno del panel → (texto, color)
STATUS_STYLES: dict[str, tuple[str, str]] = {
    "running": ("EN CURSO", COLORS["accent"]),
    SQLMAP_VULNERABLE: ("VULNERABLE", COLORS["danger"]),
    SQLMAP_CLEAN: ("LIMPIO", COLORS["success"]),
    SQLMAP_ERROR: ("ERROR", COLORS["warning"]),
}


class SqlmapMonitorWindow(ctk.CTkToplevel):
    def __init__(self, master: ctk.CTk, on_close=None) -> None:
        super().__init__(master)
        self.on_close = on_close

        self.title("SQLMap en vivo · DorkHunter Pro")
        self.geometry("1180x720")
        self.minsize(860, 480)
        self.configure(fg_color=COLORS["bg"])
        self.transient(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.panels: dict[str, dict[str, Any]] = {}
        self.panel_order: list[str] = []
        self.counts: dict[str, int] = {"running": 0, "done": 0, "vuln": 0}

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 4))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Procesos SQLMap en vivo",
            font=font(18, "bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Un panel por URL verificada · [Wn] = proceso simultáneo. "
            "Solo sistemas con autorización escrita.",
            font=font(11),
            text_color=COLORS["muted"],
            wraplength=900,
            justify="left",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.grid(row=1, column=0, sticky="ew", padx=22, pady=(4, 6))
        controls.grid_columnconfigure(0, weight=1)
        self.counts_label = ctk.CTkLabel(
            controls,
            text="0 en curso · 0 completados · 0 vulnerables",
            font=font(11, "bold"),
            text_color=COLORS["muted"],
        )
        self.counts_label.grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            controls,
            text="Limpiar",
            width=90,
            height=28,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=self.reset,
        ).grid(row=0, column=1, padx=(8, 0))
        ctk.CTkButton(
            controls,
            text="Cerrar",
            width=90,
            height=28,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=self.destroy,
        ).grid(row=0, column=2, padx=(8, 0))

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=2, column=0, sticky="nsew", padx=22, pady=(2, 16))
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.grid_frame = ctk.CTkScrollableFrame(
            container,
            fg_color=COLORS["bg"],
        )
        self.grid_frame.grid(row=0, column=0, sticky="nsew")
        self.grid_frame.grid_columnconfigure(0, weight=1, uniform="sqlcol")
        self.grid_frame.grid_columnconfigure(1, weight=1, uniform="sqlcol")

        self._placeholder = ctk.CTkLabel(
            self.grid_frame,
            text="Sin procesos todavía. Lanza una caza con SQLMap activado.",
            font=font(12),
            text_color=COLORS["muted"],
        )
        self._placeholder.grid(row=0, column=0, columnspan=2, pady=40)

        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(60, self._center)

    # ------------------------------------------------------------------
    # API llamada desde Dashboard (hilo de Tk)
    # ------------------------------------------------------------------
    def handle_event(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        url = str(event.get("url") or "")
        if not url:
            return
        if kind == "sqlmap_started":
            self._ensure_panel(url, int(event.get("worker") or 0))
        elif kind == "sqlmap_line":
            self._append_line(url, str(event.get("line") or ""))
        elif kind == "sqlmap":
            self._finish_panel(url, str(event.get("estado") or ""))

    def reset(self) -> None:
        """Limpia todos los paneles (nueva caza)."""
        for panel in list(self.panels.values()):
            try:
                panel["frame"].destroy()
            except Exception:
                pass
        self.panels.clear()
        self.panel_order.clear()
        self.counts = {"running": 0, "done": 0, "vuln": 0}
        self._refresh_counts()
        self._placeholder.grid(row=0, column=0, columnspan=2, pady=40)

    # ------------------------------------------------------------------
    def _ensure_panel(self, url: str, worker: int) -> None:
        if url not in self.panels:
            if len(self.panel_order) >= MAX_PANELS:
                self._recycle_oldest_finished()
            if len(self.panel_order) >= MAX_PANELS:
                # Todos ocupados por procesos en curso: recicla el más viejo.
                self._recycle(self.panel_order[0])
            self._create_panel(url, worker)
        panel = self.panels[url]
        panel["status"] = "running"
        panel["worker"] = worker
        panel["title"].configure(text=f"[W{worker}] {self._short(url)}")
        panel["status_label"].configure(
            text="  EN CURSO  ", text_color=COLORS["accent"]
        )
        self.counts["running"] += 1
        self._refresh_counts()
        try:
            panel["frame"].grid(
                row=(len(self.panel_order) - 1) // 2,
                column=(len(self.panel_order) - 1) % 2,
                padx=6, pady=6, sticky="nsew",
            )
            panel["box"].see("end")
        except Exception:
            pass

    def _create_panel(self, url: str, worker: int) -> None:
        frame = ctk.CTkFrame(
            self.grid_frame,
            fg_color=COLORS["panel"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        title_row = ctk.CTkFrame(frame, fg_color="transparent")
        title_row.pack(fill="x", padx=10, pady=(8, 2))
        title = ctk.CTkLabel(
            title_row,
            text=f"[W{worker}] {self._short(url)}",
            font=font(11, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        )
        title.pack(side="left", fill="x", expand=True)
        status = ctk.CTkLabel(
            title_row,
            text="  EN CURSO  ",
            font=font(10, "bold"),
            text_color=COLORS["accent"],
        )
        status.pack(side="right")

        box = ctk.CTkTextbox(
            frame,
            height=250,
            fg_color=COLORS["bg"],
            border_width=0,
            corner_radius=8,
            text_color=COLORS["muted"],
            font=font(10, mono=True),
            wrap="none",
        )
        box.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        box.configure(state="disabled")

        self.panels[url] = {
            "frame": frame,
            "title": title,
            "status_label": status,
            "box": box,
            "status": "running",
            "worker": worker,
            "lines": 0,
        }
        self.panel_order.append(url)
        self._placeholder.grid_forget()

    def _recycle_oldest_finished(self) -> None:
        for url in list(self.panel_order):
            panel = self.panels.get(url)
            if panel is not None and panel.get("status") != "running":
                self._recycle(url)
                return

    def _recycle(self, url: str) -> None:
        panel = self.panels.pop(url, None)
        if url in self.panel_order:
            self.panel_order.remove(url)
        if panel is None:
            return
        if panel.get("status") == "running":
            self.counts["running"] = max(0, self.counts["running"] - 1)
        else:
            self.counts["done"] = max(0, self.counts["done"] - 1)
        try:
            panel["frame"].destroy()
        except Exception:
            pass
        self._regrid()

    def _regrid(self) -> None:
        for index, url in enumerate(self.panel_order):
            panel = self.panels.get(url)
            if panel is None:
                continue
            try:
                panel["frame"].grid(
                    row=index // 2,
                    column=index % 2,
                    padx=6,
                    pady=6,
                    sticky="nsew",
                )
            except Exception:
                pass

    # ------------------------------------------------------------------
    def _append_line(self, url: str, line: str) -> None:
        panel = self.panels.get(url)
        if panel is None:
            return
        if panel["lines"] >= MAX_LINES_PER_PANEL:
            if panel["lines"] == MAX_LINES_PER_PANEL:
                panel["lines"] += 1
                self._insert(panel, "… (salida truncada; ver reports/sqlmap/)")
            return
        panel["lines"] += 1
        self._insert(panel, line)

    def _insert(self, panel: dict[str, Any], line: str) -> None:
        box = panel["box"]
        try:
            box.configure(state="normal")
            box.insert("end", f"{line}\n")
            # Recorte duro para no crecer sin límite.
            line_count = int(str(box.index("end-1c")).split(".")[0])
            if line_count > MAX_LINES_PER_PANEL + 40:
                box.delete("1.0", f"{line_count - MAX_LINES_PER_PANEL}.0")
            box.see("end")
            box.configure(state="disabled")
        except Exception:
            pass

    def _finish_panel(self, url: str, estado: str) -> None:
        panel = self.panels.get(url)
        if panel is None:
            return
        text, color = STATUS_STYLES.get(estado, ("LISTO", COLORS["muted"]))
        panel["status"] = estado
        panel["status_label"].configure(text=f"  {text}  ", text_color=color)
        self.counts["running"] = max(0, self.counts["running"] - 1)
        self.counts["done"] += 1
        if estado == SQLMAP_VULNERABLE:
            self.counts["vuln"] += 1
        self._refresh_counts()

    def _refresh_counts(self) -> None:
        self.counts_label.configure(
            text=(
                f"{self.counts['running']} en curso · "
                f"{self.counts['done']} completados · "
                f"{self.counts['vuln']} vulnerables"
            )
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _short(url: str, limit: int = 60) -> str:
        return url if len(url) <= limit else url[: limit - 1] + "…"

    def _close(self) -> None:
        callback = self.on_close
        self.destroy()
        if callback:
            try:
                callback()
            except Exception:
                pass

    def _center(self) -> None:
        self.update_idletasks()
        width, height = 1180, 720
        master = self.master
        x = master.winfo_rootx() + (master.winfo_width() - width) // 2
        y = master.winfo_rooty() + (master.winfo_height() - height) // 2
        self.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")
