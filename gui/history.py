"""Historial de cazas guardadas en SQLite.

Permite recuperar una caza anterior en la tabla principal sin volver a
ejecutar búsquedas ni peticiones de red.
"""
from __future__ import annotations

from tkinter import ttk
from typing import Callable

import customtkinter as ctk

from gui.theme import COLORS, font

STATUS_LABELS = {
    "running": "En curso",
    "completado": "Completado",
    "cancelado": "Cancelado",
    "error": "Error",
}


class HistoryWindow(ctk.CTkToplevel):
    def __init__(
        self,
        master: ctk.CTk,
        db,
        on_load: Callable[[int], None],
    ) -> None:
        super().__init__(master)
        self.db = db
        self.on_load = on_load

        self.title("Historial de cazas · DorkHunter Pro")
        self.geometry("960x600")
        self.minsize(780, 480)
        self.configure(fg_color=COLORS["bg"])
        self.transient(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Historial de cazas",
            font=font(20, "bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Doble clic o selecciona una fila para cargarla en el panel.",
            font=font(11),
            text_color=COLORS["muted"],
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        table_card = ctk.CTkFrame(
            self,
            fg_color=COLORS["panel"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        table_card.grid(row=1, column=0, sticky="nsew", padx=24, pady=8)
        table_card.grid_rowconfigure(0, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        columns = (
            "id",
            "fecha",
            "pais",
            "tipo",
            "estado",
            "urls",
            "hallazgos",
            "vulns",
        )
        self.tree = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            style="DH.Treeview",
            selectmode="browse",
        )
        headings = {
            "id": "ID",
            "fecha": "Fecha",
            "pais": "País",
            "tipo": "Tipo",
            "estado": "Estado",
            "urls": "URLs",
            "hallazgos": "Hallazgos",
            "vulns": "Posibles",
        }
        for column, label in headings.items():
            self.tree.heading(column, text=label, anchor="w")
        self.tree.column("id", width=58, minwidth=50, stretch=False, anchor="w")
        self.tree.column("fecha", width=155, minwidth=130, stretch=False, anchor="w")
        self.tree.column("pais", width=130, minwidth=100, stretch=False, anchor="w")
        self.tree.column("tipo", width=150, minwidth=110, stretch=True, anchor="w")
        self.tree.column("estado", width=110, minwidth=90, stretch=False, anchor="w")
        self.tree.column("urls", width=70, minwidth=60, stretch=False, anchor="w")
        self.tree.column("hallazgos", width=88, minwidth=75, stretch=False, anchor="w")
        self.tree.column("vulns", width=78, minwidth=65, stretch=False, anchor="w")
        self.tree.tag_configure("vuln", foreground=COLORS["danger"])
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        self.tree.bind("<Double-1>", lambda _event: self._load_selected())

        scrollbar = ctk.CTkScrollbar(
            table_card,
            command=self.tree.yview,
            fg_color=COLORS["panel"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent"],
        )
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=10)
        self.tree.configure(yscrollcommand=scrollbar.set)

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=24, pady=(8, 20))
        footer.grid_columnconfigure(0, weight=1)

        self.empty_label = ctk.CTkLabel(
            footer,
            text="",
            font=font(10),
            text_color=COLORS["muted"],
        )
        self.empty_label.grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            footer,
            text="Cerrar",
            width=100,
            height=36,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(11),
            command=self.destroy,
        ).grid(row=0, column=1, padx=(8, 0))

        ctk.CTkButton(
            footer,
            text="Cargar caza",
            width=140,
            height=36,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            font=font(11, "bold"),
            command=self._load_selected,
        ).grid(row=0, column=2, padx=(8, 0))

        self._populate()
        self.after(60, self._center)

    # ------------------------------------------------------------------
    def _populate(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        scans = self.db.list_scans_with_counts(200)
        for scan in scans:
            created = str(scan.get("created_at") or "")
            display_date = created[:19].replace("T", " ")
            status = str(scan.get("status") or "")
            vulns = int(scan.get("vulns_count") or 0)
            self.tree.insert(
                "",
                "end",
                iid=str(scan["id"]),
                values=(
                    scan["id"],
                    display_date or "—",
                    scan.get("country") or "—",
                    scan.get("domain_type") or "—",
                    STATUS_LABELS.get(status, status or "—"),
                    scan.get("urls_found") or 0,
                    scan.get("findings_count") or 0,
                    vulns,
                ),
                tags=("vuln",) if vulns else (),
            )
        if not scans:
            self.empty_label.configure(text="No hay cazas registradas todavía.")
        else:
            self.empty_label.configure(text=f"{len(scans)} caza(s) en el historial.")

    def _load_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            self.empty_label.configure(
                text="Selecciona una caza para cargarla.",
                text_color=COLORS["warning"],
            )
            return
        try:
            scan_id = int(selection[0])
        except ValueError:
            return
        self.on_load(scan_id)
        self.destroy()

    def _center(self) -> None:
        self.update_idletasks()
        width, height = 960, 600
        master = self.master
        x = master.winfo_rootx() + (master.winfo_width() - width) // 2
        y = master.winfo_rooty() + (master.winfo_height() - height) // 2
        self.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")
