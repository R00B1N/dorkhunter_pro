"""Ventana de cola manual de SQLMap.

Permite pegar una lista de URLs (una por línea, como en waybackurls/gau o
los exports de otros herramientas) y ejecutar SQLMap sobre ellas sin pasar
por una caza completa. La ejecución real la maneja el dashboard mediante un
worker; esta ventana solo recolecta y valida el texto pegado.
"""
from __future__ import annotations

import customtkinter as ctk

from gui.theme import COLORS, font

_HINT = (
    "Pega una URL por línea (http/https con parámetros).\n"
    "Compatible con waybackurls, gau, Burp o cualquier lista propia.\n"
    "Las líneas vacías y los comentarios (#) se ignoran."
)


class SqlmapQueueWindow(ctk.CTkToplevel):
    def __init__(self, master, on_run) -> None:
        super().__init__(master, fg_color=COLORS["bg"])
        self.on_run = on_run

        self.title("DorkHunter Pro — Cola SQLMap")
        self.geometry("640x520")
        self.minsize(520, 420)
        self.transient(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 6))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Cola manual de SQLMap",
            font=font(17, "bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Verificación ACTIVA: SQLMap envía payloads reales. Solo con "
            "autorización escrita.",
            font=font(10),
            text_color=COLORS["warning"],
            justify="left",
            wraplength=560,
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        body = ctk.CTkFrame(self, fg_color=COLORS["panel"], corner_radius=10)
        body.grid(row=1, column=0, sticky="nsew", padx=16, pady=(6, 6))
        body.grid_rowconfigure(1, weight=1)
        body.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            body,
            text=_HINT,
            font=font(10),
            text_color=COLORS["muted"],
            justify="left",
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 6))

        self.textbox = ctk.CTkTextbox(
            body,
            font=font(12, mono=True),
            fg_color=COLORS["panel_alt"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            wrap="none",
            undo=True,
        )
        self.textbox.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 10))
        self.textbox.insert("1.0", "# https://dominio.com/item.php?id=1\n")

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        footer.grid_columnconfigure(0, weight=1)
        footer.grid_columnconfigure(1, weight=0)
        footer.grid_columnconfigure(2, weight=0)

        self.count_label = ctk.CTkLabel(
            footer,
            text="0 URLs con parámetros detectadas",
            font=font(10),
            text_color=COLORS["muted"],
        )
        self.count_label.grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            footer,
            text="Limpiar",
            width=90,
            height=34,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(11),
            command=self._clear,
        ).grid(row=0, column=1, padx=(0, 8))

        ctk.CTkButton(
            footer,
            text="EJECUTAR COLA",
            width=170,
            height=38,
            corner_radius=8,
            fg_color=COLORS["warning"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            font=font(12, "bold"),
            command=self._run,
        ).grid(row=0, column=2)

        # Recuento en vivo mientras se escribe.
        self.textbox.bind("<KeyRelease>", lambda _e: self._update_count())
        self.after(200, self._update_count)

    # ------------------------------------------------------------------
    def _collect_urls(self) -> list[str]:
        urls: list[str] = []
        try:
            content = self.textbox.get("1.0", "end")
        except Exception:
            return urls
        for line in str(content or "").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            lowered = value.lower()
            if lowered.startswith(("http://", "https://")) and "?" in value:
                urls.append(value)
        return urls

    def _update_count(self) -> None:
        count = len(self._collect_urls())
        self.count_label.configure(
            text=f"{count} URL(s) con parámetros detectadas"
        )

    def _clear(self) -> None:
        self.textbox.delete("1.0", "end")
        self._update_count()

    def _run(self) -> None:
        urls = self._collect_urls()
        if not urls:
            return
        self.on_run(urls)
