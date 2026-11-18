"""Paleta y estilos compartidos de la interfaz."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

COLORS = {
    "bg": "#0d1117",
    "panel": "#151b23",
    "panel_alt": "#1b232e",
    "border": "#26303d",
    "text": "#e6edf3",
    "muted": "#8b98a9",
    "accent": "#22d3ee",
    "accent_hover": "#0ea5b7",
    "accent_text": "#04141a",
    "success": "#34d399",
    "warning": "#fbbf24",
    "danger": "#f87171",
    "info": "#60a5fa",
    "row_alt": "#111820",
    "selection": "#164e63",
}

FONT_FAMILY = "Segoe UI"
FONT_MONO = "DejaVu Sans Mono"


def font(size: int = 12, weight: str = "normal", mono: bool = False) -> ctk.CTkFont:
    return ctk.CTkFont(
        family=FONT_MONO if mono else FONT_FAMILY,
        size=size,
        weight=weight,
    )


def apply_theme(root: tk.Misc) -> None:
    """Aplica el tema oscuro a los widgets ttk (Treeview, scrollbars)."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        "DH.Treeview",
        background=COLORS["panel"],
        fieldbackground=COLORS["panel"],
        foreground=COLORS["text"],
        bordercolor=COLORS["border"],
        borderwidth=0,
        rowheight=30,
        font=(FONT_FAMILY, 10),
    )
    style.configure(
        "DH.Treeview.Heading",
        background=COLORS["panel_alt"],
        foreground=COLORS["muted"],
        relief="flat",
        borderwidth=0,
        padding=(8, 8),
        font=(FONT_FAMILY, 10, "bold"),
    )
    style.map(
        "DH.Treeview",
        background=[("selected", COLORS["selection"])],
        foreground=[("selected", "#ffffff")],
    )
    style.map(
        "DH.Treeview.Heading",
        background=[("active", COLORS["panel_alt"])],
        foreground=[("active", COLORS["text"])],
    )
    # Quita el borde punteado de la primera columna.
    try:
        style.layout(
            "DH.Treeview",
            [("Treeview.treearea", {"sticky": "nswe"})],
        )
    except tk.TclError:
        pass

    style.configure(
        "DH.Vertical.TScrollbar",
        background=COLORS["panel_alt"],
        troughcolor=COLORS["panel"],
        bordercolor=COLORS["panel"],
        arrowcolor=COLORS["muted"],
        width=10,
    )
