"""Ventana de detalle de un hallazgo y generación de reportes."""
from __future__ import annotations

from pathlib import Path
from tkinter import messagebox
from typing import Any, Callable

import customtkinter as ctk

from config import REPORTS_DIR
from core.report_generator import DISCLAIMER_NOTE, ReportGenerator
from core.sqli_scanner import CONFIANZA_LABELS, ESTADO_LABELS
from gui.theme import COLORS, font
from utils.helpers import open_path

REPORT_STATES = {
    "sin_reporte": "Sin reporte",
    "generado": "Generado",
    "enviado": "Enviado",
    "respondido": "Respondido",
    "descartado": "Descartado",
}
_LABEL_TO_KEY = {label: key for key, label in REPORT_STATES.items()}


class FindingDetailWindow(ctk.CTkToplevel):
    def __init__(
        self,
        master: ctk.CTk,
        db,
        finding_id: int,
        on_change: Callable[[int], None] | None = None,
    ) -> None:
        super().__init__(master)
        self.db = db
        self.finding_id = finding_id
        self.on_change = on_change
        finding = db.get_finding(finding_id)
        if finding is None:
            self.destroy()
            return
        self.finding: dict[str, Any] = finding

        self.title("Detalle del hallazgo · DorkHunter Pro")
        self.geometry("960x780")
        self.minsize(860, 640)
        self.configure(fg_color=COLORS["bg"])
        self.transient(master)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_body()
        self._build_footer()

        self.after(60, self._center)

    # ------------------------------------------------------------------
    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=26, pady=(22, 10))
        header.grid_columnconfigure(0, weight=1)

        badge_text = ESTADO_LABELS.get(
            str(self.finding.get("estado")), str(self.finding.get("estado"))
        )
        badge_color = (
            COLORS["danger"]
            if self.finding.get("estado") == "posible_vuln"
            else COLORS["muted"]
        )
        ctk.CTkLabel(
            header,
            text=f"  {badge_text}  ",
            fg_color=COLORS["panel_alt"],
            corner_radius=10,
            text_color=badge_color,
            font=font(10, "bold"),
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="Detalle del hallazgo",
            font=font(22, "bold"),
            text_color=COLORS["text"],
        ).grid(row=1, column=0, sticky="w", pady=(8, 2))

        self.url_label = ctk.CTkLabel(
            header,
            text=str(self.finding.get("url") or ""),
            font=font(11, mono=True),
            text_color=COLORS["accent"],
            wraplength=860,
            justify="left",
            anchor="w",
        )
        self.url_label.grid(row=2, column=0, sticky="w")

    # ------------------------------------------------------------------
    def _build_body(self) -> None:
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=26)
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        info = ctk.CTkFrame(
            body,
            fg_color=COLORS["panel"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        info.grid(row=0, column=0, sticky="ew")
        info.grid_columnconfigure(1, weight=1)
        info.grid_columnconfigure(3, weight=1)

        confidence = str(self.finding.get("confianza") or "")
        rows = [
            ("Parámetro", self.finding.get("parametro") or "No identificado"),
            ("Código HTTP", self.finding.get("http_status") or "N/D"),
            ("Motor de base de datos", self.finding.get("dbms") or "No determinado"),
            ("WAF detectado", self.finding.get("waf") or "No detectado"),
            (
                "Confianza del triaje",
                CONFIANZA_LABELS.get(confidence, confidence or "No determinada"),
            ),
            ("Contacto", self.finding.get("contacto") or "No disponible"),
            ("Organización", self.finding.get("organizacion") or "No disponible"),
            ("Registrador", self.finding.get("registrar") or "No disponible"),
            ("País WHOIS", self.finding.get("whois_country") or "No disponible"),
            ("security.txt", self.finding.get("security_txt") or "No encontrado"),
            (
                "Fuente de enriquecimiento",
                self.finding.get("enrichment_source") or "No disponible",
            ),
            ("Fecha", self.finding.get("created_at") or "N/D"),
            ("Firma detectada", self.finding.get("error_detectado") or "N/D"),
        ]
        for index, (label, value) in enumerate(rows):
            row = index // 2
            column = (index % 2) * 2
            ctk.CTkLabel(
                info,
                text=label.upper(),
                font=font(9, "bold"),
                text_color=COLORS["muted"],
            ).grid(row=row, column=column, sticky="nw", padx=(16, 8), pady=(10, 0))
            ctk.CTkLabel(
                info,
                text=str(value),
                font=font(11),
                text_color=COLORS["text"],
                wraplength=360,
                justify="left",
                anchor="w",
            ).grid(
                row=row,
                column=column + 1,
                sticky="nw",
                padx=(0, 16),
                pady=(10, 0),
            )

        # Estado del reporte
        state_row = (len(rows) + 1) // 2
        ctk.CTkLabel(
            info,
            text="ESTADO DEL REPORTE",
            font=font(9, "bold"),
            text_color=COLORS["muted"],
        ).grid(row=state_row, column=0, sticky="nw", padx=(16, 8), pady=(12, 16))

        self.state_var = ctk.StringVar(
            value=REPORT_STATES.get(
                str(self.finding.get("estado_reporte")), "Sin reporte"
            )
        )
        self.state_menu = ctk.CTkOptionMenu(
            info,
            values=list(REPORT_STATES.values()),
            variable=self.state_var,
            command=self._on_state_change,
            width=180,
            height=30,
            corner_radius=8,
            fg_color=COLORS["panel_alt"],
            button_color=COLORS["panel_alt"],
            button_hover_color=COLORS["border"],
            dropdown_fg_color=COLORS["panel_alt"],
            dropdown_hover_color=COLORS["selection"],
            dropdown_text_color=COLORS["text"],
            text_color=COLORS["text"],
            font=font(10),
            dropdown_font=font(10),
            dynamic_resizing=False,
        )
        self.state_menu.grid(
            row=state_row, column=1, sticky="w", padx=(0, 16), pady=(8, 14)
        )

        ctk.CTkLabel(
            body,
            text="EVIDENCIA (TEXTO DEL ERROR, SIN DATOS SENSIBLES)",
            font=font(9, "bold"),
            text_color=COLORS["muted"],
        ).grid(row=1, column=0, sticky="w", pady=(16, 6))

        self.evidence_box = ctk.CTkTextbox(
            body,
            fg_color=COLORS["panel"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=10,
            text_color=COLORS["danger"],
            font=font(11, mono=True),
            wrap="word",
            height=170,
        )
        self.evidence_box.grid(row=2, column=0, sticky="nsew")
        evidence = str(self.finding.get("evidencia") or "").strip()
        self.evidence_box.insert(
            "1.0",
            evidence or "No se capturó evidencia textual para este hallazgo.",
        )
        self.evidence_box.configure(state="disabled")

        note = ctk.CTkFrame(
            body,
            fg_color=COLORS["panel_alt"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        note.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        ctk.CTkLabel(
            note,
            text=DISCLAIMER_NOTE,
            font=font(10),
            text_color=COLORS["muted"],
            wraplength=860,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=14, pady=10)

    # ------------------------------------------------------------------
    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=26, pady=(14, 20))
        footer.grid_columnconfigure(0, weight=1)

        self.report_path_label = ctk.CTkLabel(
            footer,
            text=self._report_path_text(),
            font=font(9),
            text_color=COLORS["muted"],
            wraplength=880,
            justify="left",
            anchor="w",
        )
        self.report_path_label.grid(row=0, column=0, sticky="w", pady=(0, 8))

        buttons = ctk.CTkFrame(footer, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="e")

        self.copy_status = ctk.CTkLabel(
            buttons, text="", font=font(9), text_color=COLORS["success"]
        )
        self.copy_status.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            buttons,
            text="Copiar contacto",
            width=120,
            height=34,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=self._copy_contact,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            buttons,
            text="Abrir reporte",
            width=115,
            height=34,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=self._open_report,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            buttons,
            text="Generar JSON",
            width=110,
            height=34,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=lambda: self._generate("json"),
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            buttons,
            text="Generar HTML",
            width=115,
            height=34,
            fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"],
            text_color=COLORS["text"],
            font=font(10),
            command=lambda: self._generate("html"),
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            buttons,
            text="Generar reporte MD",
            width=160,
            height=34,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            font=font(10, "bold"),
            command=lambda: self._generate("md"),
        ).pack(side="left")

    # ------------------------------------------------------------------
    def _report_path_text(self) -> str:
        path = self.finding.get("reporte_path")
        return f"Reporte: {path}" if path else "Reporte: aún no generado"

    def _generate(self, fmt: str) -> None:
        try:
            generator = ReportGenerator(REPORTS_DIR)
            path = generator.generate(self.finding, fmt)
        except Exception as exc:
            messagebox.showerror(
                "No se pudo generar el reporte",
                f"Error: {exc}",
                parent=self,
            )
            return

        self.db.update_finding(
            self.finding_id,
            reporte_path=str(path),
            estado_reporte="generado",
        )
        updated = self.db.get_finding(self.finding_id)
        if updated:
            self.finding = updated
        self.state_var.set(REPORT_STATES["generado"])
        self.report_path_label.configure(text=self._report_path_text())
        if self.on_change:
            self.on_change(self.finding_id)

        if messagebox.askyesno(
            "Reporte generado",
            f"Reporte guardado en:\n{path}\n\n¿Abrirlo ahora?",
            parent=self,
        ):
            open_path(path)

    def _open_report(self) -> None:
        raw_path = self.finding.get("reporte_path")
        if not raw_path:
            messagebox.showinfo(
                "Sin reporte",
                "Genera primero un reporte Markdown, HTML o JSON.",
                parent=self,
            )
            return
        path = Path(str(raw_path))
        if not path.exists():
            messagebox.showwarning(
                "Reporte no encontrado",
                f"El archivo ya no existe:\n{path}",
                parent=self,
            )
            return
        if not open_path(path):
            messagebox.showinfo(
                "No se pudo abrir",
                f"Abre el archivo manualmente:\n{path}",
                parent=self,
            )

    def _copy_contact(self) -> None:
        contact = str(self.finding.get("contacto") or "").strip()
        if not contact or contact == "No disponible":
            messagebox.showinfo(
                "Sin contacto",
                "No se encontró un correo de contacto para este dominio.",
                parent=self,
            )
            return
        self.clipboard_clear()
        self.clipboard_append(contact)
        self.copy_status.configure(text="Copiado ✓")
        self.after(2200, lambda: self.copy_status.configure(text=""))

    def _on_state_change(self, label: str) -> None:
        key = _LABEL_TO_KEY.get(label, "sin_reporte")
        self.db.update_finding(self.finding_id, estado_reporte=key)
        updated = self.db.get_finding(self.finding_id)
        if updated:
            self.finding = updated
        if self.on_change:
            self.on_change(self.finding_id)

    def _center(self) -> None:
        self.update_idletasks()
        width, height = 960, 780
        master = self.master
        x = master.winfo_rootx() + (master.winfo_width() - width) // 2
        y = master.winfo_rooty() + (master.winfo_height() - height) // 2
        self.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")
