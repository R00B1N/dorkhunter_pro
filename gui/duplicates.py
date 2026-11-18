"""URLs que aparecieron en más de un dork durante una caza.

La ventana es de solo lectura: muestra la URL, cuántas veces se repitió y
qué dorks la devolvieron. Permite copiar las URLs al portapapeles.
"""
from __future__ import annotations

from tkinter import messagebox, ttk
from typing import Any

import customtkinter as ctk

from gui.theme import COLORS, font


class DuplicateWindow(ctk.CTkToplevel):
    def __init__(self, master: ctk.CTk, duplicates: list[dict[str, Any]]) -> None:
        super().__init__(master)
        self.duplicates = list(duplicates)

        self.title("URLs duplicadas · DorkHunter Pro")
        self.geometry("940x560")
        self.minsize(760, 420)
        self.configure(fg_color=COLORS["bg"])
        self.transient(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="URLs duplicadas",
            font=font(20, "bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text=(
                "Una URL es duplicada cuando la devolvieron dos o más dorks. "
                "Suele indicar un parámetro muy común o un dork demasiado amplio."
            ),
            font=font(11),
            text_color=COLORS["muted"],
            wraplength=860,
            justify="left",
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

        columns = ("url", "veces", "fuentes")
        self.tree = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            style="DH.Treeview",
            selectmode="extended",
        )
        headings = {
            "url": "URL",
            "veces": "Veces",
            "fuentes": "Dorks que la devolvieron",
        }
        for column, label in headings.items():
            self.tree.heading(column, text=label, anchor="w")
        self.tree.column("url", width=430, minwidth=260, stretch=True, anchor="w")
        self.tree.column("veces", width=70, minwidth=60, stretch=False, anchor="w")
        self.tree.column(
            "fuentes", width=360, minwidth=220, stretch=True, anchor="w"
        )
        self.tree.tag_configure("vuln", foreground=COLORS["danger"])
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        self.tree.bind("<Double-1>", lambda _event: self._copy_selected())

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

        self.count_label = ctk.CTkLabel(
            footer,
            text="",
            font=font(10),
            text_color=COLORS["muted"],
        )
        self.count_label.grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            footer,
            text="Copiar seleccionadas",
            width=160,
            height=36,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=font(11),
            command=self._copy_selected,
        ).grid(row=0, column=1, padx=(8, 0))

        ctk.CTkButton(
            footer,
            text="Copiar todas",
            width=130,
            height=36,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            font=font(11, "bold"),
            command=self._copy_all,
        ).grid(row=0, column=2, padx=(8, 0))

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
        ).grid(row=0, column=3, padx=(8, 0))

        self._populate()
        self.after(60, self._center)

    # ------------------------------------------------------------------
    def _populate(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for index, item in enumerate(self.duplicates):
            url = str(item.get("url") or "")
            count = int(item.get("count") or 0)
            sources = item.get("sources") or []
            if isinstance(sources, (list, tuple)):
                source_text = " | ".join(str(source) for source in sources)
            else:
                source_text = str(sources)
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(url, count, source_text),
                tags=("vuln",) if count >= 3 else (),
            )
        total = len(self.duplicates)
        self.count_label.configure(
            text=(
                f"{total} URL(s) repetida(s). "
                "Doble clic en una fila para copiar su URL."
            )
        )

    def _urls_from_selection(self) -> list[str]:
        urls: list[str] = []
        for iid in self.tree.selection():
            values = self.tree.item(iid, "values")
            if values:
                url = str(values[0]).strip()
                if url and url not in urls:
                    urls.append(url)
        return urls

    def _copy_urls(self, urls: list[str]) -> None:
        if not urls:
            messagebox.showinfo(
                "Sin selección",
                "Selecciona al menos una fila o usa «Copiar todas».",
                parent=self,
            )
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(urls))
            self.update_idletasks()
        except Exception as exc:  # pragma: no cover - depende del portapapeles
            messagebox.showerror(
                "No se pudo copiar",
                f"El portapapeles no está disponible: {exc}",
                parent=self,
            )
            return
        self.count_label.configure(
            text=f"{len(urls)} URL(s) copiada(s) al portapapeles."
        )

    def _copy_selected(self) -> None:
        self._copy_urls(self._urls_from_selection())

    def _copy_all(self) -> None:
        urls: list[str] = []
        for iid in self.tree.get_children():
            values = self.tree.item(iid, "values")
            if values:
                url = str(values[0]).strip()
                if url and url not in urls:
                    urls.append(url)
        self._copy_urls(urls)

    def _center(self) -> None:
        self.update_idletasks()
        width, height = 940, 560
        master = self.master
        x = master.winfo_rootx() + (master.winfo_width() - width) // 2
        y = master.winfo_rooty() + (master.winfo_height() - height) // 2
        self.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")
