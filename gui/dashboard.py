"""Vista principal de DorkHunter Pro.

Toda la lógica pesada vive en ``core.orchestrator`` y se ejecuta en un hilo
aparte. La GUI solo consume eventos de una cola y actualiza widgets desde el
hilo principal mediante ``after()``, que es la única forma segura de hacerlo
con Tkinter.
"""
from __future__ import annotations

import queue
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import Menu, filedialog, messagebox, ttk
from typing import Any
from urllib.parse import parse_qsl, urlparse

import customtkinter as ctk

from config import (
    APP_VERSION,
    DEFAULT_DORK_COUNT,
    MAX_RESULTS_PER_DORK,
    MAX_URLS_PER_HUNT,
    REPORTS_DIR,
    SQLMAP_WORKERS,
)
from core.dork_engine import (
    COUNTRY_CATEGORIES,
    DOMAIN_TYPES,
    DorkEngine,
    _fold as _fold_keyword,
    suggest_keywords,
)
from core.orchestrator import (
    HuntOrchestrator,
    HuntParams,
    normalize_target_urls,
    parse_domain_list,
)
from core.passive_sources import collect_domain_urls
from core.report_generator import ReportGenerator
from core.search_engine import SUPPORTED_ENGINES
from core.sqli_scanner import CONFIANZA_LABELS, ESTADO_LABELS
from core.sqlmap_runner import (
    SQLMAP_LABELS,
    TARGET_ALL,
    TARGET_AUTO,
    TARGET_VULNS,
    SqlmapConfig,
    parse_extra_flags,
    preset_extra_flags,
    validate_sqlmap_config,
)
from gui.disclaimer import LegalNoticeWindow
from gui.duplicates import DuplicateWindow
from gui.finding_detail import FindingDetailWindow
from gui.history import HistoryWindow
from gui.sqlmap_monitor import SqlmapMonitorWindow
from gui.sqlmap_queue import SqlmapQueueWindow
from gui.theme import COLORS, font
from utils.helpers import open_path

DEPTH_OPTIONS = {
    "Rápida (6 dorks)": 6,
    "Normal (10 dorks)": DEFAULT_DORK_COUNT,
    "Profunda (16 dorks)": 16,
    "Muy profunda (24 dorks)": 24,
    "Máxima (32 dorks)": 32,
}

# Objetivos de la verificación activa: qué URLs van a SQLMap.
SQLMAP_TARGET_OPTIONS: dict[str, str] = {
    "Vulns + respaldo (todas)": TARGET_AUTO,
    "Solo posibles vulns": TARGET_VULNS,
    "Todas las URLs": TARGET_ALL,
}

# Presets de intensidad de SQLMap (mapean a flags extra del runner).
SQLMAP_PRESET_OPTIONS: dict[str, str] = {
    "Seguro": "seguro",
    "Estándar": "estandar",
    "Profundo": "profundo",
}

# Tope de URLs por ejecución de la cola manual de SQLMap.
QUEUE_MAX_URLS = 50

# Etiqueta → (motores o None, rotar). ``None`` significa el orden de
# ``SEARCH_ENGINES``; ``Rotación`` reparte los motores entre los dorks.
SEARCH_ENGINE_OPTIONS: dict[str, tuple[list[str] | None, bool]] = {
    "Automático": (None, False),
    "Rotación (todos)": (list(SUPPORTED_ENGINES), True),
    "DuckDuckGo": (["duckduckgo"], False),
    "Brave": (["brave"], False),
    "Bing": (["bing"], False),
    "Mojeek": (["mojeek"], False),
    "Yahoo": (["yahoo"], False),
    "Yandex": (["yandex"], False),
}

FILTER_STATES = {
    "Todos": "",
    "Posible Vuln": "posible_vuln",
    "Sin hallazgos": "ok",
    "Bloqueado": "bloqueado",
    "Error": "error",
    "Omitido": "omitido",
    "Pendiente": "pendiente",
}

TAG_BY_ESTADO = {
    "pendiente": "pendiente",
    "posible_vuln": "vuln",
    "ok": "ok",
    "bloqueado": "warn",
    "error": "warn",
    "omitido": "muted",
}


class Dashboard(ctk.CTkFrame):
    def __init__(self, master: ctk.CTk, db) -> None:
        super().__init__(master, fg_color=COLORS["bg"], corner_radius=0)
        self.db = db

        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.orchestrator: HuntOrchestrator | None = None

        self.current_scan_id: int | None = None
        self.row_by_url: dict[str, str] = {}
        self.finding_by_url: dict[str, int] = {}
        self.estado_by_url: dict[str, str] = {}
        self._rows: dict[str, dict[str, Any]] = {}
        self._row_order: list[str] = []
        self._row_counter = 0
        self._scope_confirmed = False
        self._sqlmap_confirmed = False
        self.sqlmap_monitor: SqlmapMonitorWindow | None = None
        self._sqlmap_queue_window: SqlmapQueueWindow | None = None
        self._sort_state: dict[str, bool] = {}
        self._alive = True
        self._duplicates_count = 0
        self._keyword_chips: list[ctk.CTkButton] = []
        self.filter_var = ctk.StringVar(value="")
        self.state_filter_var = ctk.StringVar(value="Todos")

        self._engine = DorkEngine()

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._bind_preview()
        self._update_preview()
        self._poll_events()

    # ==================================================================
    # Construcción de la interfaz
    # ==================================================================
    def _build_sidebar(self) -> None:
        side = ctk.CTkFrame(self, width=322, corner_radius=0, fg_color=COLORS["panel"])
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(0, weight=1)
        side.grid_columnconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(
            side,
            fg_color="transparent",
            width=282,
            scrollbar_button_color=COLORS["border"],
            scrollbar_button_hover_color=COLORS["accent"],
        )
        scroll.grid(row=0, column=0, sticky="nsew", padx=(12, 2), pady=(14, 6))

        # Marca ---------------------------------------------------------
        brand = ctk.CTkFrame(scroll, fg_color="transparent")
        brand.pack(fill="x", pady=(2, 0))
        title_row = ctk.CTkFrame(brand, fg_color="transparent")
        title_row.pack(anchor="w")
        ctk.CTkLabel(
            title_row,
            text="DORKHUNTER",
            font=font(21, "bold"),
            text_color=COLORS["text"],
        ).pack(side="left")
        ctk.CTkLabel(
            title_row,
            text=" PRO",
            font=font(21, "bold"),
            text_color=COLORS["accent"],
        ).pack(side="left")
        ctk.CTkLabel(
            brand,
            text="Auditoría pasiva · OSINT · Divulgación responsable",
            font=font(10),
            text_color=COLORS["muted"],
            wraplength=260,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        ctk.CTkFrame(scroll, height=1, fg_color=COLORS["border"]).pack(
            fill="x", pady=14
        )

        # Filtros -------------------------------------------------------
        self.category_var = ctk.StringVar(value="Latinoamérica")
        self.country_var = ctk.StringVar(value="Colombia")
        self.type_var = ctk.StringVar(value="Educativo (edu)")
        self.keywords_var = ctk.StringVar(value="")
        self.manual_var = ctk.StringVar(value="")
        self.allow_var = ctk.StringVar(value="")
        self.deny_var = ctk.StringVar(value="")
        self.depth_var = ctk.StringVar(value="Normal (10 dorks)")
        self.scan_var = ctk.BooleanVar(value=True)
        self.enrich_var = ctk.BooleanVar(value=True)

        self._field_label(scroll, "Región").pack(anchor="w")
        self.category_menu = self._option_menu(
            scroll,
            list(COUNTRY_CATEGORIES),
            self.category_var,
            command=self._on_category_change,
        )
        self.category_menu.pack(fill="x", pady=(4, 8))

        self._field_label(scroll, "País").pack(anchor="w")
        self.country_menu = self._option_menu(
            scroll,
            list(COUNTRY_CATEGORIES.get(self.category_var.get(), ())),
            self.country_var,
        )
        self.country_menu.pack(fill="x", pady=(4, 12))

        self._field_label(scroll, "Tipo de dominio").pack(anchor="w")
        self.type_menu = self._option_menu(scroll, list(DOMAIN_TYPES), self.type_var)
        self.type_menu.pack(fill="x", pady=(4, 12))

        self._field_label(scroll, "Palabras clave (opcional)").pack(anchor="w")
        self.keywords_entry = self._entry(
            scroll, self.keywords_var, "ej. matrícula, pagos, noticias"
        )
        self.keywords_entry.pack(fill="x", pady=(4, 4))

        # Sugerencias de palabras clave (chips clicables) ---------------
        self.keyword_hint = ctk.CTkFrame(scroll, fg_color="transparent")
        self.keyword_hint.pack(fill="x", pady=(0, 8))
        self.keyword_hint.grid_columnconfigure(0, weight=1)
        self.keyword_hint.grid_columnconfigure(1, weight=1)

        self._field_label(scroll, "Dork manual (opcional)").pack(anchor="w")
        self.manual_entry = self._entry(
            scroll, self.manual_var, "site:edu.co inurl:index.php?id="
        )
        self.manual_entry.pack(fill="x", pady=(4, 12))

        self._field_label(scroll, "Solo dominios (opcional)").pack(anchor="w")
        self.allow_entry = self._entry(
            scroll, self.allow_var, "ej. uni.edu.co, gov.co"
        )
        self.allow_entry.pack(fill="x", pady=(4, 4))
        self._field_label(scroll, "Excluir dominios (opcional)").pack(anchor="w")
        self.deny_entry = self._entry(
            scroll, self.deny_var, "ej. sitio.com, subdominio.edu.co"
        )
        self.deny_entry.pack(fill="x", pady=(4, 12))

        self._field_label(scroll, "Profundidad").pack(anchor="w")
        self.depth_menu = self._option_menu(
            scroll, list(DEPTH_OPTIONS), self.depth_var
        )
        self.depth_menu.pack(fill="x", pady=(4, 12))

        self.engine_var = ctk.StringVar(value="Automático")
        self._field_label(scroll, "Motor de búsqueda").pack(anchor="w")
        self.engine_menu = self._option_menu(
            scroll, list(SEARCH_ENGINE_OPTIONS), self.engine_var
        )
        self.engine_menu.pack(fill="x", pady=(4, 12))

        # Vista previa del dork ----------------------------------------
        preview_card = ctk.CTkFrame(
            scroll,
            fg_color=COLORS["panel_alt"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        preview_card.pack(fill="x", pady=(0, 14))
        ctk.CTkLabel(
            preview_card,
            text="DORK PREVIEW",
            font=font(9, "bold"),
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=10, pady=(8, 0))
        self.preview_label = ctk.CTkLabel(
            preview_card,
            text="",
            font=font(10, mono=True),
            text_color=COLORS["accent"],
            wraplength=248,
            justify="left",
            anchor="w",
        )
        self.preview_label.pack(fill="x", padx=10, pady=(2, 10))

        # Triaje pasivo -------------------------------------------------
        self._section_label(scroll, "Triaje pasivo").pack(anchor="w", pady=(0, 6))
        ctk.CTkCheckBox(
            scroll,
            text="Escanear SQLi (pasivo)",
            variable=self.scan_var,
            font=font(11),
            text_color=COLORS["text"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
            checkmark_color=COLORS["accent_text"],
        ).pack(anchor="w", pady=(0, 6))

        ctk.CTkCheckBox(
            scroll,
            text="Enriquecer con WHOIS + security.txt",
            variable=self.enrich_var,
            font=font(11),
            text_color=COLORS["text"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
            checkmark_color=COLORS["accent_text"],
        ).pack(anchor="w", pady=(0, 14))

        # Verificación activa (OPCIONAL, desactivada) -------------------
        ctk.CTkFrame(scroll, height=1, fg_color=COLORS["border"]).pack(
            fill="x", pady=(0, 10)
        )
        ctk.CTkLabel(
            scroll,
            text="VERIFICACIÓN ACTIVA (OPCIONAL)",
            font=font(10, "bold"),
            text_color=COLORS["warning"],
        ).pack(anchor="w", pady=(0, 6))

        self.sqlmap_var = ctk.BooleanVar(value=False)
        self.sqlmap_proxy_var = ctk.BooleanVar(value=False)
        self.sqlmap_dbs_var = ctk.BooleanVar(value=False)

        ctk.CTkCheckBox(
            scroll,
            text="Confirmar con SQLMap (ACTIVO)",
            variable=self.sqlmap_var,
            font=font(11),
            text_color=COLORS["text"],
            fg_color=COLORS["warning"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
            checkmark_color=COLORS["accent_text"],
        ).pack(anchor="w", pady=(0, 8))

        self._field_label(scroll, "Objetivos").pack(anchor="w")
        self.sqlmap_targets_var = ctk.StringVar(value="Vulns + respaldo (todas)")
        self.sqlmap_targets_menu = self._option_menu(
            scroll, list(SQLMAP_TARGET_OPTIONS), self.sqlmap_targets_var
        )
        self.sqlmap_targets_menu.pack(fill="x", pady=(4, 8))

        self._field_label(scroll, "Intensidad").pack(anchor="w")
        self.sqlmap_preset_var = ctk.StringVar(value="Seguro")
        self.sqlmap_preset_menu = self._option_menu(
            scroll, list(SQLMAP_PRESET_OPTIONS), self.sqlmap_preset_var
        )
        self.sqlmap_preset_menu.pack(fill="x", pady=(4, 8))

        self._field_label(scroll, "Flags extra").pack(anchor="w")
        self.sqlmap_extra_var = ctk.StringVar(value="")
        self.sqlmap_extra_entry = self._entry(
            scroll, self.sqlmap_extra_var, "ej. --forms --titles"
        )
        self.sqlmap_extra_entry.pack(fill="x", pady=(4, 8))

        limits = ctk.CTkFrame(scroll, fg_color="transparent")
        limits.pack(fill="x", pady=(0, 8))
        limits.grid_columnconfigure(0, weight=1)
        limits.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            limits,
            text="PROCESOS",
            font=font(9, "bold"),
            text_color=COLORS["muted"],
        ).grid(row=0, column=0, sticky="w", padx=(0, 4))
        ctk.CTkLabel(
            limits,
            text="HILOS/PROC",
            font=font(9, "bold"),
            text_color=COLORS["muted"],
        ).grid(row=0, column=1, sticky="w")
        self.sqlmap_workers_var = ctk.StringVar(value=str(SQLMAP_WORKERS))
        self.sqlmap_workers_menu = self._option_menu(
            limits,
            ["1", "2", "3", "4", "5", "6", "7", "8"],
            self.sqlmap_workers_var,
        )
        self.sqlmap_workers_menu.grid(
            row=1, column=0, sticky="ew", padx=(0, 4), pady=(2, 0)
        )
        self.sqlmap_threads_var = ctk.StringVar(value="1")
        self.sqlmap_threads_menu = self._option_menu(
            limits, ["1", "2", "3", "5", "10"], self.sqlmap_threads_var
        )
        self.sqlmap_threads_menu.grid(row=1, column=1, sticky="ew", pady=(2, 0))

        ctk.CTkCheckBox(
            scroll,
            text="Usar proxychains4",
            variable=self.sqlmap_proxy_var,
            font=font(11),
            text_color=COLORS["text"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
            checkmark_color=COLORS["accent_text"],
        ).pack(anchor="w", pady=(0, 4))

        ctk.CTkCheckBox(
            scroll,
            text="Enumerar BD (--dbs: extrae datos)",
            variable=self.sqlmap_dbs_var,
            font=font(11),
            text_color=COLORS["text"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
            checkmark_color=COLORS["accent_text"],
        ).pack(anchor="w", pady=(0, 4))

        self.sqlmap_monitor_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            scroll,
            text="Abrir monitoreo en vivo",
            variable=self.sqlmap_monitor_var,
            font=font(11),
            text_color=COLORS["text"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
            checkmark_color=COLORS["accent_text"],
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkButton(
            scroll,
            text="VER SQLMAP EN VIVO",
            height=32,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=font(10, "bold"),
            command=self._open_sqlmap_monitor,
        ).pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(
            scroll,
            text="SQLMap envía payloads reales y puede extraer datos con "
            "--dbs. Solo con autorización escrita.",
            font=font(9),
            text_color=COLORS["warning"],
            wraplength=260,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        # Acciones ------------------------------------------------------
        ctk.CTkFrame(scroll, height=1, fg_color=COLORS["border"]).pack(
            fill="x", pady=(0, 10)
        )
        self.start_btn = ctk.CTkButton(
            scroll,
            text="INICIAR CAZA",
            height=48,
            corner_radius=10,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            font=font(13, "bold"),
            command=self._start_hunt,
        )
        self.start_btn.pack(fill="x", pady=(0, 8))

        self.stop_btn = ctk.CTkButton(
            scroll,
            text="Detener",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            state="disabled",
            command=self._stop_hunt,
        )
        self.stop_btn.pack(fill="x", pady=(0, 12))

        # Herramientas --------------------------------------------------
        self._section_label(scroll, "Herramientas").pack(anchor="w", pady=(0, 6))
        self.manual_url_btn = ctk.CTkButton(
            scroll,
            text="PROBAR URL DIRECTA",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=font(10, "bold"),
            command=self._prompt_manual_url,
        )
        self.manual_url_btn.pack(fill="x", pady=(8, 0))

        self.import_btn = ctk.CTkButton(
            scroll,
            text="IMPORTAR .TXT DE URLS",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=font(10, "bold"),
            command=self._import_url_file,
        )
        self.import_btn.pack(fill="x", pady=(8, 0))

        self.sources_btn = ctk.CTkButton(
            scroll,
            text="FUENTES PASIVAS",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=font(10, "bold"),
            command=self._prompt_passive_sources,
        )
        self.sources_btn.pack(fill="x", pady=(8, 0))

        self.queue_btn = ctk.CTkButton(
            scroll,
            text="COLA SQLMAP",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            font=font(10, "bold"),
            command=self._open_sqlmap_queue,
        )
        self.queue_btn.pack(fill="x", pady=(8, 0))

        self.history_btn = ctk.CTkButton(
            scroll,
            text="HISTORIAL DE CAZAS",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10, "bold"),
            command=self._open_history,
        )
        self.history_btn.pack(fill="x", pady=(8, 0))

        ctk.CTkLabel(
            scroll,
            text="Solo sistemas propios o con autorización escrita.",
            font=font(9),
            text_color=COLORS["warning"],
            wraplength=260,
            justify="left",
        ).pack(anchor="w", pady=(14, 4))

        # Pie -----------------------------------------------------------
        footer = ctk.CTkFrame(side, fg_color="transparent")
        footer.grid(row=1, column=0, sticky="ew", padx=18, pady=(4, 12))
        footer.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            footer,
            text=f"v{APP_VERSION}",
            font=font(9),
            text_color=COLORS["muted"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            footer,
            text="Aviso legal",
            width=90,
            height=26,
            fg_color="transparent",
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=self._show_legal,
        ).grid(row=0, column=1, sticky="e")

    # ------------------------------------------------------------------
    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)

        # Encabezado ----------------------------------------------------
        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 8))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header,
            text="Panel de hallazgos",
            font=font(24, "bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Detección pasiva de errores SQL · sin explotación",
            font=font(12),
            text_color=COLORS["muted"],
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        self.status_pill = ctk.CTkLabel(
            header,
            text="  Listo  ",
            fg_color=COLORS["panel_alt"],
            corner_radius=12,
            text_color=COLORS["muted"],
            font=font(11, "bold"),
        )
        self.status_pill.grid(row=0, column=2, rowspan=2, sticky="e", padx=(10, 0))

        # Barra de herramientas ----------------------------------------
        toolbar = ctk.CTkFrame(main, fg_color="transparent")
        toolbar.grid(row=1, column=0, sticky="ew", padx=22, pady=(6, 8))
        toolbar.grid_columnconfigure(1, weight=1)

        self.count_label = ctk.CTkLabel(
            toolbar,
            text="0 URLs · 0 posibles",
            font=font(11),
            text_color=COLORS["muted"],
        )
        self.count_label.grid(row=0, column=0, sticky="w")

        self.export_btn = ctk.CTkButton(
            toolbar,
            text="Exportar CSV",
            width=118,
            height=32,
            fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"],
            text_color=COLORS["text"],
            font=font(11),
            command=self._export_csv,
        )
        self.export_btn.grid(row=0, column=2, padx=(8, 0))

        self.json_btn = ctk.CTkButton(
            toolbar,
            text="Exportar JSON",
            width=118,
            height=32,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(11),
            command=self._export_json,
        )
        self.json_btn.grid(row=0, column=3, padx=(8, 0))

        self.scan_report_btn = ctk.CTkButton(
            toolbar,
            text="Reporte de caza",
            width=132,
            height=32,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            font=font(11, "bold"),
            command=self._generate_scan_report,
        )
        self.scan_report_btn.grid(row=0, column=4, padx=(8, 0))

        self.reports_btn = ctk.CTkButton(
            toolbar,
            text="Abrir reportes",
            width=120,
            height=32,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(11),
            command=self._open_reports,
        )
        self.reports_btn.grid(row=0, column=5, padx=(8, 0))

        # Filtros de la tabla ------------------------------------------
        filters = ctk.CTkFrame(main, fg_color="transparent")
        filters.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 8))
        filters.grid_columnconfigure(0, weight=1)

        self.filter_entry = ctk.CTkEntry(
            filters,
            textvariable=self.filter_var,
            placeholder_text="Filtrar por URL, dominio, parámetro, motor o contacto…",
            height=32,
            corner_radius=8,
            fg_color=COLORS["panel_alt"],
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            placeholder_text_color=COLORS["muted"],
            font=font(11),
        )
        self.filter_entry.grid(row=0, column=0, sticky="ew")

        self.state_filter_menu = ctk.CTkOptionMenu(
            filters,
            values=list(FILTER_STATES),
            variable=self.state_filter_var,
            command=lambda _value: self._render_rows(),
            width=170,
            height=32,
            corner_radius=8,
            fg_color=COLORS["panel_alt"],
            button_color=COLORS["panel_alt"],
            button_hover_color=COLORS["border"],
            dropdown_fg_color=COLORS["panel_alt"],
            dropdown_hover_color=COLORS["selection"],
            dropdown_text_color=COLORS["text"],
            text_color=COLORS["text"],
            font=font(11),
            dropdown_font=font(11),
            dynamic_resizing=False,
        )
        self.state_filter_menu.grid(row=0, column=1, padx=(8, 0))

        self.clear_filter_btn = ctk.CTkButton(
            filters,
            text="Limpiar",
            width=82,
            height=32,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=self._clear_filters,
        )
        self.clear_filter_btn.grid(row=0, column=2, padx=(8, 0))

        self.copy_urls_btn = ctk.CTkButton(
            filters,
            text="Copiar URLs",
            width=110,
            height=32,
            fg_color=COLORS["panel_alt"],
            hover_color=COLORS["border"],
            text_color=COLORS["text"],
            font=font(10),
            command=self._copy_urls,
        )
        self.copy_urls_btn.grid(row=0, column=3, padx=(8, 0))

        self.duplicates_btn = ctk.CTkButton(
            filters,
            text="Duplicadas",
            width=110,
            height=32,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            font=font(10),
            command=self._open_duplicates,
        )
        self.duplicates_btn.grid(row=0, column=4, padx=(8, 0))

        # Tabla ---------------------------------------------------------
        table_card = ctk.CTkFrame(
            main,
            fg_color=COLORS["panel"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        table_card.grid(row=3, column=0, sticky="nsew", padx=22, pady=(0, 12))
        table_card.grid_rowconfigure(0, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        columns = (
            "url",
            "param",
            "estado",
            "dbms",
            "waf",
            "confianza",
            "contacto",
            "sqlmap",
        )
        self.tree = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            style="DH.Treeview",
            selectmode="browse",
        )
        headings = {
            "url": "URL",
            "param": "Parámetro",
            "estado": "Estado",
            "dbms": "Motor",
            "waf": "WAF",
            "confianza": "Confianza",
            "contacto": "Contacto",
            "sqlmap": "SQLMap",
        }
        for col, text in headings.items():
            self.tree.heading(col, text=text, anchor="w", command=lambda c=col: self._sort_by(c))

        self.tree.column("url", width=400, minwidth=250, stretch=True, anchor="w")
        self.tree.column("param", width=86, minwidth=64, stretch=False, anchor="w")
        self.tree.column("estado", width=105, minwidth=88, stretch=False, anchor="w")
        self.tree.column("dbms", width=88, minwidth=64, stretch=False, anchor="w")
        self.tree.column("waf", width=90, minwidth=60, stretch=False, anchor="w")
        self.tree.column("confianza", width=82, minwidth=70, stretch=False, anchor="w")
        self.tree.column("contacto", width=180, minwidth=120, stretch=False, anchor="w")
        self.tree.column("sqlmap", width=108, minwidth=76, stretch=False, anchor="w")

        self.tree.tag_configure("vuln", foreground=COLORS["danger"])
        self.tree.tag_configure("ok", foreground=COLORS["success"])
        self.tree.tag_configure("warn", foreground=COLORS["warning"])
        self.tree.tag_configure("pendiente", foreground=COLORS["muted"])
        self.tree.tag_configure("muted", foreground=COLORS["muted"])

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._show_row_menu)
        self.tree.bind("<Control-c>", lambda _event: self._copy_urls())

        scrollbar = ctk.CTkScrollbar(
            table_card,
            command=self.tree.yview,
            fg_color=COLORS["panel"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent"],
        )
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=10)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.filter_var.trace_add("write", lambda *_: self._render_rows())

        # Progreso y log ------------------------------------------------
        bottom = ctk.CTkFrame(main, fg_color="transparent")
        bottom.grid(row=4, column=0, sticky="ew", padx=22, pady=(0, 16))
        bottom.grid_columnconfigure(0, weight=1)

        progress_row = ctk.CTkFrame(bottom, fg_color="transparent")
        progress_row.grid(row=0, column=0, sticky="ew")
        progress_row.grid_columnconfigure(1, weight=1)

        self.progress_label = ctk.CTkLabel(
            progress_row,
            text="En espera",
            font=font(10),
            text_color=COLORS["muted"],
        )
        self.progress_label.grid(row=0, column=0, sticky="w")
        self.progress_value = ctk.CTkLabel(
            progress_row,
            text="0%",
            font=font(10, "bold"),
            text_color=COLORS["muted"],
        )
        self.progress_value.grid(row=0, column=2, sticky="e")

        self.progress = ctk.CTkProgressBar(
            bottom,
            height=6,
            corner_radius=3,
            progress_color=COLORS["accent"],
            fg_color=COLORS["panel_alt"],
        )
        self.progress.grid(row=1, column=0, sticky="ew", pady=(6, 10))
        self.progress.set(0)

        self.log_box = ctk.CTkTextbox(
            bottom,
            height=132,
            fg_color=COLORS["panel"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=10,
            text_color=COLORS["muted"],
            font=font(11, mono=True),
            wrap="word",
        )
        self.log_box.grid(row=2, column=0, sticky="ew")
        self.log_box.configure(state="disabled")
        self._configure_log_tags()

        self._log("muted", "Listo. Configura los filtros y pulsa INICIAR CAZA.")

    # ------------------------------------------------------------------
    # Helpers de widgets
    # ------------------------------------------------------------------
    @staticmethod
    def _field_label(parent, text: str) -> ctk.CTkLabel:
        return ctk.CTkLabel(
            parent,
            text=text.upper(),
            font=font(9, "bold"),
            text_color=COLORS["muted"],
        )

    @staticmethod
    def _section_label(parent, text: str, color: str | None = None) -> ctk.CTkLabel:
        return ctk.CTkLabel(
            parent,
            text=text.upper(),
            font=font(10, "bold"),
            text_color=color or COLORS["muted"],
        )

    def _option_menu(
        self,
        parent,
        values: list[str],
        variable,
        command=None,
    ) -> ctk.CTkOptionMenu:
        return ctk.CTkOptionMenu(
            parent,
            values=values,
            variable=variable,
            command=command,
            height=34,
            corner_radius=8,
            fg_color=COLORS["panel_alt"],
            button_color=COLORS["panel_alt"],
            button_hover_color=COLORS["border"],
            dropdown_fg_color=COLORS["panel_alt"],
            dropdown_hover_color=COLORS["selection"],
            dropdown_text_color=COLORS["text"],
            text_color=COLORS["text"],
            font=font(11),
            dropdown_font=font(11),
            dynamic_resizing=False,
        )

    def _entry(self, parent, variable, placeholder: str) -> ctk.CTkEntry:
        return ctk.CTkEntry(
            parent,
            textvariable=variable,
            placeholder_text=placeholder,
            height=34,
            corner_radius=8,
            fg_color=COLORS["panel_alt"],
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            placeholder_text_color=COLORS["muted"],
            font=font(11),
        )

    def _configure_log_tags(self) -> None:
        tags = {
            "info": COLORS["muted"],
            "muted": COLORS["muted"],
            "ok": COLORS["success"],
            "warn": COLORS["warning"],
            "error": COLORS["danger"],
        }
        try:
            for name, color in tags.items():
                self.log_box.tag_config(name, foreground=color)
        except Exception:
            # Si la versión de CustomTkinter no expone tag_config, el texto
            # sigue siendo legible sin color.
            pass

    # ==================================================================
    # Vista previa
    # ==================================================================
    def _bind_preview(self) -> None:
        for variable in (
            self.country_var,
            self.type_var,
            self.keywords_var,
            self.manual_var,
        ):
            variable.trace_add("write", lambda *_: self._update_preview())
        self.keywords_var.trace_add(
            "write",
            lambda *_: self.after_idle(self._refresh_keyword_suggestions),
        )
        self._refresh_keyword_suggestions()

    def _on_category_change(self, category: str) -> None:
        countries = list(COUNTRY_CATEGORIES.get(category, ()))
        self.country_menu.configure(values=countries)
        if countries:
            self.country_var.set(countries[0])

    def _refresh_keyword_suggestions(self) -> None:
        if not self._alive or not hasattr(self, "keyword_hint"):
            return
        for chip in self._keyword_chips:
            chip.destroy()
        self._keyword_chips = []

        parts = [part.strip() for part in self.keywords_var.get().split(",")]
        token = parts[-1] if parts else ""
        for suggestion in suggest_keywords(token, limit=3):
            if _fold_keyword(suggestion) == _fold_keyword(token):
                continue
            chip = ctk.CTkButton(
                self.keyword_hint,
                text=suggestion,
                height=24,
                width=110,
                corner_radius=12,
                fg_color=COLORS["panel_alt"],
                hover_color=COLORS["border"],
                text_color=COLORS["muted"],
                font=font(10),
                command=lambda value=suggestion: self._apply_keyword_suggestion(
                    value
                ),
            )
            index = len(self._keyword_chips)
            chip.grid(
                row=index // 2,
                column=index % 2,
                sticky="ew",
                padx=(0, 4),
                pady=2,
            )
            self._keyword_chips.append(chip)

    def _apply_keyword_suggestion(self, suggestion: str) -> None:
        parts = [
            part.strip() for part in self.keywords_var.get().split(",") if part.strip()
        ]
        token = parts[-1] if parts else ""
        folded_token = _fold_keyword(token)
        folded_suggestion = _fold_keyword(suggestion)
        if token and folded_suggestion.startswith(folded_token) and (
            folded_token != folded_suggestion
        ):
            parts[-1] = suggestion
        elif not token:
            parts = [suggestion]
        else:
            parts.append(suggestion)
        self.keywords_var.set(", ".join(parts))
        self.keywords_entry.focus_set()

    def _update_preview(self) -> None:
        try:
            query = self._engine.preview(
                self.country_var.get(),
                self.type_var.get(),
                self.keywords_var.get(),
                self.manual_var.get(),
            )
        except ValueError as exc:
            self.preview_label.configure(
                text=str(exc), text_color=COLORS["warning"]
            )
            return
        display = query if len(query) <= 120 else query[:117] + "…"
        self.preview_label.configure(text=display, text_color=COLORS["accent"])

    # ==================================================================
    # Acciones
    # ==================================================================
    def _ensure_idle(self) -> bool:
        if self.worker is not None and self.worker.is_alive():
            messagebox.showinfo(
                "Caza en curso",
                "Espera a que termine la caza actual o pulsa Detener.",
                parent=self,
            )
            return False
        return True

    def _confirm_scope(self) -> bool:
        if self._scope_confirmed:
            return True
        confirmed = messagebox.askyesno(
            "Confirmación de alcance",
            "Vas a enviar una petición GET con una comilla simple (') "
            "a URLs de terceros.\n\n"
            "Confirma que:\n"
            "  • eres el propietario de los sistemas, o\n"
            "  • cuentas con autorización escrita para esta prueba.\n\n"
            "¿Deseas continuar?",
            parent=self,
        )
        if confirmed:
            self._scope_confirmed = True
        return confirmed

    def _confirm_sqlmap(self) -> bool:
        """Confirmación específica para la fase ACTIVA con SQLMap."""
        if self._sqlmap_confirmed:
            return True
        extras: list[str] = []
        if self.sqlmap_dbs_var.get():
            extras.append(
                "  • Enumeración --dbs activada: SQLMap EXTRAERÁ bases de datos."
            )
        if self.sqlmap_proxy_var.get():
            extras.append("  • El tráfico pasará por proxychains4.")
        detail = ("\n".join(extras) + "\n\n") if extras else ""
        confirmed = messagebox.askyesno(
            "Verificación activa con SQLMap",
            "SQLMap enviará payloads reales y puede generar cientos de "
            "peticiones por URL. Esto NO forma parte del triaje pasivo.\n\n"
            + detail
            + "Confirma que cuentas con autorización escrita y vigente del "
            "propietario de cada sistema a verificar.\n\n¿Continuar?",
            parent=self,
            icon="warning",
        )
        if confirmed:
            self._sqlmap_confirmed = True
        return confirmed

    def _build_sqlmap_config(
        self, force: bool = False
    ) -> tuple[SqlmapConfig | None, str | None]:
        """Construye la configuración SQLMap si el usuario la activó.

        Con ``force=True`` se construye aunque la casilla esté apagada
        (p. ej. "Enviar a SQLMap" sobre un hallazgo concreto); pide la
        confirmación activa en ese caso.

        Devuelve ``(config, error)``; ``error`` es un mensaje a mostrar,
        ``"cancelado"`` si el usuario rechazó la confirmación.
        """
        if not force and not self.sqlmap_var.get():
            return None, None
        if not self._confirm_sqlmap():
            return None, "cancelado"
        try:
            workers = max(1, int(self.sqlmap_workers_var.get()))
        except ValueError:
            workers = SQLMAP_WORKERS
        try:
            sqlmap_threads = max(1, int(self.sqlmap_threads_var.get()))
        except ValueError:
            sqlmap_threads = 1
        preset = SQLMAP_PRESET_OPTIONS.get(self.sqlmap_preset_var.get(), "seguro")
        extra_flags = preset_extra_flags(preset) + parse_extra_flags(
            self.sqlmap_extra_var.get()
        )
        config = SqlmapConfig(
            enabled=True,
            use_proxychains=bool(self.sqlmap_proxy_var.get()),
            enumerate_dbs=bool(self.sqlmap_dbs_var.get()),
            targets=SQLMAP_TARGET_OPTIONS.get(
                self.sqlmap_targets_var.get(), TARGET_AUTO
            ),
            workers=workers,
            sqlmap_threads=sqlmap_threads,
            extra_flags=extra_flags,
        )
        problems = validate_sqlmap_config(config)
        if problems:
            return None, "\n".join(problems)
        return config, None

    # ------------------------------------------------------------------
    def _monitor_alive(self) -> bool:
        monitor = self.sqlmap_monitor
        if monitor is None:
            return False
        try:
            return bool(monitor.winfo_exists())
        except Exception:
            return False

    def _forward_sqlmap(self, event: dict[str, Any]) -> None:
        """Reenvía eventos SQLMap a la ventana de monitoreo, si está abierta."""
        if self._monitor_alive():
            try:
                self.sqlmap_monitor.handle_event(event)
            except Exception:
                pass

    def _open_sqlmap_monitor(self) -> None:
        if self._monitor_alive():
            try:
                self.sqlmap_monitor.focus()
                return
            except Exception:
                pass
        self.sqlmap_monitor = SqlmapMonitorWindow(
            self.winfo_toplevel(),
            on_close=self._on_monitor_closed,
        )

    def _on_monitor_closed(self) -> None:
        self.sqlmap_monitor = None

    def _launch(
        self, params: HuntParams, header: list[tuple[str, str]]
    ) -> None:
        self._reset_table()
        self._reset_filters()
        if self._monitor_alive():
            try:
                self.sqlmap_monitor.reset()
            except Exception:
                pass
        self.cancel_event.clear()
        self.current_scan_id = None
        self._set_running(True)
        self._log("info", "=" * 64)
        for level, message in header:
            self._log(level, message)
        self.orchestrator = HuntOrchestrator(
            self.db, self.events, self.cancel_event, params
        )
        self.worker = threading.Thread(
            target=self.orchestrator.run, name="hunt", daemon=True
        )
        self.worker.start()

    def _start_hunt(self) -> None:
        if not self._ensure_idle():
            return

        country = self.country_var.get()
        domain_type = self.type_var.get()
        keywords = self.keywords_var.get().strip()
        manual = self.manual_var.get().strip()
        depth = DEPTH_OPTIONS.get(self.depth_var.get(), DEFAULT_DORK_COUNT)

        try:
            dorks = self._engine.build(
                country, domain_type, keywords, manual, limit=depth
            )
        except ValueError as exc:
            messagebox.showwarning("Filtros incompletos", str(exc), parent=self)
            return

        do_scan = bool(self.scan_var.get())
        do_enrich = bool(self.enrich_var.get())
        if do_scan and not self._confirm_scope():
            return

        sqlmap_config, sqlmap_error = self._build_sqlmap_config()
        if sqlmap_error == "cancelado":
            return
        if sqlmap_error:
            messagebox.showerror(
                "SQLMap no disponible",
                "No se pudo activar la verificación activa:\n\n"
                + sqlmap_error
                + "\n\nLa caza no se inició. Corrige la ruta del binario o "
                "desactiva la casilla de SQLMap.",
                parent=self,
            )
            return

        engines, rotate = SEARCH_ENGINE_OPTIONS.get(
            self.engine_var.get(), (None, False)
        )
        params = HuntParams(
            country=country,
            domain_type=domain_type,
            keywords=keywords,
            manual_dork=manual,
            max_results=MAX_RESULTS_PER_DORK,
            do_scan=do_scan,
            do_enrich=do_enrich,
            dorks=dorks,
            max_urls=MAX_URLS_PER_HUNT,
            engines=engines,
            rotate=rotate,
            allow_domains=parse_domain_list(self.allow_var.get()),
            deny_domains=parse_domain_list(self.deny_var.get()),
            sqlmap=sqlmap_config,
        )
        header: list[tuple[str, str]] = [
            ("info", f"Iniciando caza: {country} / {domain_type}")
        ]
        if rotate:
            header.append(
                ("muted", "  · Rotación de motores activada entre dorks")
            )
        header.extend(("muted", f"  · {dork.query}") for dork in dorks)
        if sqlmap_config is not None:
            header.append(
                (
                    "warn",
                    "  · Verificación ACTIVA con SQLMap tras el triaje pasivo"
                    + (" vía proxychains4" if sqlmap_config.use_proxychains else "")
                    + (" · --dbs" if sqlmap_config.enumerate_dbs else ""),
                )
            )
        self._launch(params, header)

    def _launch_targets(self, targets: list[str], header_title: str) -> None:
        """Lanza una caza de URLs directas (manual, .txt o fuentes pasivas)."""
        do_scan = bool(self.scan_var.get())
        do_enrich = bool(self.enrich_var.get())
        if do_scan and not self._confirm_scope():
            return

        sqlmap_config, sqlmap_error = self._build_sqlmap_config()
        if sqlmap_error == "cancelado":
            return
        if sqlmap_error:
            messagebox.showerror(
                "SQLMap no disponible",
                "No se pudo activar la verificación activa:\n\n"
                + sqlmap_error
                + "\n\nLa prueba no se inició. Corrige la ruta del binario o "
                "desactiva la casilla de SQLMap.",
                parent=self,
            )
            return

        params = HuntParams(
            country="Manual",
            domain_type="URL directa",
            keywords="",
            manual_dork="",
            max_results=1,
            do_scan=do_scan,
            do_enrich=do_enrich,
            dorks=[],
            target_urls=targets,
            max_urls=MAX_URLS_PER_HUNT,
            allow_domains=parse_domain_list(self.allow_var.get()),
            deny_domains=parse_domain_list(self.deny_var.get()),
            sqlmap=sqlmap_config,
        )
        header = [("info", f"{header_title}: {len(targets)} URL(s)")]
        header.extend(("muted", f"  · {url}") for url in targets[:5])
        if len(targets) > 5:
            header.append(("muted", f"  · … y {len(targets) - 5} más"))
        if sqlmap_config is not None:
            header.append(
                (
                    "warn",
                    "  · Verificación ACTIVA con SQLMap tras el triaje pasivo"
                    + (" vía proxychains4" if sqlmap_config.use_proxychains else "")
                    + (" · --dbs" if sqlmap_config.enumerate_dbs else ""),
                )
            )
        self._launch(params, header)

    def _prompt_manual_url(self) -> None:
        if not self._ensure_idle():
            return
        dialog = ctk.CTkInputDialog(
            text="Introduce una URL con parámetros (http/https):",
            title="Probar URL directa",
        )
        value = (dialog.get_input() or "").strip()
        if not value:
            return
        targets = normalize_target_urls([value])
        if not targets:
            messagebox.showwarning(
                "URL no válida",
                "La URL debe usar http(s) y contener al menos un parámetro "
                "(por ejemplo: https://dominio.com/item.php?id=1).",
                parent=self,
            )
            return
        self._launch_targets(targets, "Iniciando prueba directa")

    def _import_url_file(self) -> None:
        """Importa URLs desde un .txt (waybackurls, gau, Burp, exports)."""
        if not self._ensure_idle():
            return
        path = filedialog.askopenfilename(
            parent=self,
            title="Importar URLs desde archivo",
            filetypes=[("Texto", "*.txt"), ("Todos los archivos", "*.*")],
        )
        if not path:
            return
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            messagebox.showerror(
                "No se pudo leer el archivo",
                str(exc),
                parent=self,
            )
            return
        raw = [
            line.strip()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        ]
        targets = normalize_target_urls(raw)
        if not targets:
            messagebox.showwarning(
                "Sin URLs válidas",
                "El archivo no contiene URLs aprovechables.\nSe requiere "
                "http(s) y al menos un parámetro (p. ej. item.php?id=1).",
                parent=self,
            )
            return
        skipped = len(raw) - len(targets)
        self._log(
            "muted",
            f"Importación: {len(targets)} URL(s) válidas"
            + (f", {skipped} descartadas (sin parámetros)." if skipped else "."),
        )
        self._launch_targets(targets, "Iniciando caza importada")

    def _prompt_passive_sources(self) -> None:
        """Pide un dominio y consulta Wayback/OTX/crt.sh en un hilo aparte."""
        if not self._ensure_idle():
            return
        dialog = ctk.CTkInputDialog(
            text="Dominio para fuentes pasivas (ej. dominio.edu.co):\n\n"
            "Se consultan Wayback CDX y OTX AlienVault (pasivo); crt.sh "
            "lista subdominios como referencia.",
            title="Fuentes pasivas",
        )
        value = (dialog.get_input() or "").strip()
        if not value:
            return
        domains = parse_domain_list(value)
        if not domains:
            messagebox.showwarning(
                "Dominio no válido",
                "Escribe un dominio como dominio.edu.co.",
                parent=self,
            )
            return
        self._log(
            "info",
            f"Consultando fuentes pasivas (Wayback/OTX/crt.sh) para "
            f"{', '.join(domains)}…",
        )
        self.status_pill.configure(text="  Fuentes…  ", text_color=COLORS["info"])
        thread = threading.Thread(
            target=self._passive_sources_worker,
            args=(domains,),
            name="passive-sources",
            daemon=True,
        )
        thread.start()

    def _passive_sources_worker(self, domains: list[str]) -> None:
        events = self.events

        def sources_log(level: str, message: str) -> None:
            events.put({"type": "log", "level": level, "message": message})

        try:
            targets = collect_domain_urls(
                domains, log=sources_log, cancel_event=self.cancel_event
            )
        except Exception as exc:
            events.put(
                {"type": "error", "message": f"Fuentes pasivas falló: {exc}"}
            )
            return
        events.put({"type": "sources_ready", "targets": targets})

    def _stop_hunt(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            self.cancel_event.set()
            self.stop_btn.configure(state="disabled", text="Deteniendo…")
            self._log("warn", "Detención solicitada; esperando peticiones en curso…")

    def _reset_table(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.row_by_url.clear()
        self.finding_by_url.clear()
        self.estado_by_url.clear()
        self._rows.clear()
        self._row_order.clear()
        self._row_counter = 0
        self._sort_state = {}
        for col, text in (
            ("url", "URL"),
            ("param", "Parámetro"),
            ("estado", "Estado"),
            ("dbms", "Motor"),
            ("waf", "WAF"),
            ("confianza", "Confianza"),
            ("contacto", "Contacto"),
            ("sqlmap", "SQLMap"),
        ):
            self.tree.heading(col, text=text)
        self._duplicates_count = 0
        self._refresh_counts()
        self.progress.set(0)
        self.progress_value.configure(text="0%")
        self.progress_label.configure(text="En espera")

    def _set_running(self, running: bool) -> None:
        self.start_btn.configure(
            state="disabled" if running else "normal",
            text="CAZANDO…" if running else "INICIAR CAZA",
        )
        self.stop_btn.configure(
            state="normal" if running else "disabled",
            text="Detener",
        )
        self.status_pill.configure(
            text="  En curso  " if running else "  Listo  ",
            text_color=COLORS["accent"] if running else COLORS["muted"],
        )

    # ==================================================================
    # Cola de eventos
    # ==================================================================
    def _poll_events(self) -> None:
        if not self._alive:
            return
        try:
            for _ in range(400):
                event = self.events.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        if self._alive:
            self.after(120, self._poll_events)

    def _handle_event(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "log":
            self._log(event.get("level", "info"), event.get("message", ""))
        elif kind == "scan_started":
            self.current_scan_id = event.get("scan_id")
            self._log("info", f"Escaneo #{self.current_scan_id} creado en SQLite.")
        elif kind == "candidate":
            self._add_candidate(str(event.get("url", "")))
        elif kind == "result":
            finding = event.get("finding")
            if finding:
                self._update_finding(finding)
        elif kind == "progress":
            value = float(event.get("value", 0.0))
            self.progress.set(value)
            self.progress_value.configure(text=f"{int(round(value * 100))}%")
            self.progress_label.configure(text=str(event.get("label", "")))
        elif kind == "sqlmap":
            url = str(event.get("url") or "")
            row = self._rows.get(url)
            if row is not None:
                row["sqlmap"] = str(
                    event.get("estado_label")
                    or SQLMAP_LABELS.get(str(event.get("estado")), "—")
                )
                self._render_rows()
            self._forward_sqlmap(event)
        elif kind in ("sqlmap_started", "sqlmap_line"):
            if kind == "sqlmap_started" and not self._monitor_alive():
                if self.sqlmap_monitor_var.get():
                    self._open_sqlmap_monitor()
            self._forward_sqlmap(event)
        elif kind == "done":
            self._on_done(event.get("summary", {}))
        elif kind == "sources_ready":
            self._on_sources_ready(event.get("targets") or [])
        elif kind == "error":
            self._log("error", str(event.get("message", "Error desconocido")))
            if self._alive:
                messagebox.showerror(
                    "Error durante la caza",
                    str(event.get("message", "Error desconocido")),
                    parent=self,
                )

    # ==================================================================
    # Tabla
    # ==================================================================
    def _on_sources_ready(self, targets: list[str]) -> None:
        """Llega del worker de fuentes pasivas (hilo → cola de eventos)."""
        targets = [str(url) for url in targets if url]
        self.status_pill.configure(text="  Listo  ", text_color=COLORS["muted"])
        if not targets:
            messagebox.showinfo(
                "Fuentes pasivas",
                "Wayback/OTX no devolvieron URLs con parámetros para ese "
                "dominio.\nPuedes continuar con la búsqueda de dorks.",
                parent=self,
            )
            return
        if not self._ensure_idle():
            return
        if len(targets) > MAX_URLS_PER_HUNT:
            self._log(
                "muted",
                f"Fuentes pasivas: se recortan a {MAX_URLS_PER_HUNT} URLs "
                "(límite por caza).",
            )
            targets = targets[:MAX_URLS_PER_HUNT]
        self._launch_targets(targets, "Iniciando caza de fuentes pasivas")

    def _sort_by(self, column: str) -> None:
        """Ordena la tabla por la columna clicada (clic de nuevo = inverso)."""
        reverse = not self._sort_state.get(column, False)
        self._sort_state = {column: reverse}

        def sort_key(url: str) -> tuple[str, str]:
            row = self._rows.get(url, {})
            return (str(row.get(column) or "").lower(), url)

        self._row_order.sort(key=sort_key, reverse=reverse)
        for col, base in {
            "url": "URL",
            "param": "Parámetro",
            "estado": "Estado",
            "dbms": "Motor",
            "waf": "WAF",
            "confianza": "Confianza",
            "contacto": "Contacto",
            "sqlmap": "SQLMap",
        }.items():
            arrow = ""
            if col == column:
                arrow = " ▼" if reverse else " ▲"
            self.tree.heading(col, text=base + arrow)
        self._render_rows()
        self._log("muted", f"Tabla ordenada por {column}.")

    def _add_candidate(self, url: str) -> None:
        if not url or url in self._rows:
            return
        iid = f"c{self._row_counter}"
        self._row_counter += 1
        self.row_by_url[url] = iid
        self.estado_by_url[url] = "pendiente"
        self._rows[url] = {
            "url": url,
            "param": "—",
            "estado": "pendiente",
            "dbms": "—",
            "waf": "—",
            "confianza": "—",
            "contacto": "—",
            "sqlmap": "—",
        }
        self._row_order.append(url)
        self._render_rows()
        if iid in self.tree.get_children():
            self.tree.see(iid)

    def _update_finding(self, finding: dict[str, Any]) -> None:
        url = str(finding.get("url") or "")
        if not url:
            return
        if url not in self._rows:
            iid = f"c{self._row_counter}"
            self._row_counter += 1
            self.row_by_url[url] = iid
            self._rows[url] = {
                "url": url,
                "param": "—",
                "estado": "pendiente",
                "dbms": "—",
                "waf": "—",
                "confianza": "—",
                "contacto": "—",
                "sqlmap": "—",
            }
            self._row_order.append(url)

        estado = str(finding.get("estado") or "pendiente")
        confidence = str(finding.get("confianza") or "")
        sqlmap_estado = str(finding.get("sqlmap_estado") or "")
        self.estado_by_url[url] = estado
        if finding.get("id") is not None:
            self.finding_by_url[url] = int(finding["id"])
        self._rows[url].update(
            {
                "param": finding.get("parametro") or "—",
                "estado": estado,
                "dbms": finding.get("dbms") or "—",
                "waf": finding.get("waf") or "—",
                "confianza": CONFIANZA_LABELS.get(confidence, confidence or "—"),
                "contacto": finding.get("contacto") or "—",
                "sqlmap": SQLMAP_LABELS.get(sqlmap_estado, "—"),
            }
        )
        self._render_rows()

    def _render_rows(self) -> None:
        """Redibuja la tabla aplicando los filtros actuales."""
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        for url in self._row_order:
            row = self._rows.get(url)
            if row is None or not self._matches_filter(row):
                continue
            iid = self.row_by_url.get(url)
            if iid is None:
                iid = f"c{self._row_counter}"
                self._row_counter += 1
                self.row_by_url[url] = iid
            estado = str(row.get("estado") or "pendiente")
            values = (
                row.get("url") or "",
                row.get("param") or "—",
                ESTADO_LABELS.get(estado, estado),
                row.get("dbms") or "—",
                row.get("waf") or "—",
                row.get("confianza") or "—",
                row.get("contacto") or "—",
                row.get("sqlmap") or "—",
            )
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=values,
                tags=(TAG_BY_ESTADO.get(estado, "muted"),),
            )
        self._refresh_counts()

    def _matches_filter(self, row: dict[str, Any]) -> bool:
        needle = self.filter_var.get().strip().lower()
        if needle:
            haystack = " ".join(
                str(row.get(key) or "")
                for key in (
                    "url",
                    "param",
                    "estado",
                    "dbms",
                    "waf",
                    "confianza",
                    "contacto",
                    "sqlmap",
                )
            ).lower()
            if needle not in haystack:
                return False
        wanted = FILTER_STATES.get(self.state_filter_var.get(), "")
        return not wanted or row.get("estado") == wanted

    def _reset_filters(self) -> None:
        self.filter_var.set("")
        self.state_filter_var.set("Todos")

    def _clear_filters(self) -> None:
        self._reset_filters()
        self._render_rows()

    def _refresh_counts(self) -> None:
        total = len(self._rows)
        vulns = sum(
            1 for row in self._rows.values() if row.get("estado") == "posible_vuln"
        )
        suffix = (
            f" · {self._duplicates_count} duplicadas"
            if self._duplicates_count
            else ""
        )
        self.count_label.configure(
            text=f"{total} URLs · {vulns} posibles{suffix}"
        )

    def _copy_urls(self) -> None:
        """Copia al portapapeles las URLs seleccionadas o todas las visibles."""
        selected = self.tree.selection()
        iids = selected or self.tree.get_children()
        urls: list[str] = []
        for iid in iids:
            values = self.tree.item(iid, "values")
            if values:
                url = str(values[0]).strip()
                if url and url not in urls:
                    urls.append(url)
        if not urls:
            messagebox.showinfo(
                "Sin URLs",
                "No hay URLs visibles para copiar.",
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
        scope = "seleccionada(s)" if selected else "visible(s)"
        self._log("ok", f"{len(urls)} URL(s) {scope} copiada(s) al portapapeles.")

    def _open_duplicates(self) -> None:
        """Abre la ventana de URLs encontradas por más de un dork."""
        duplicates: list[dict[str, Any]] = []
        if self.current_scan_id is not None:
            duplicates = self.db.get_scan_duplicates(self.current_scan_id)
        if not duplicates and self.orchestrator is not None:
            duplicates = self.orchestrator.duplicates()
        if not duplicates:
            messagebox.showinfo(
                "Sin duplicadas",
                "Esta caza no tiene URLs repetidas en varios dorks.\n"
                "Las duplicadas aparecen cuando dos dorks distintos "
                "devuelven la misma URL.",
                parent=self,
            )
            return
        DuplicateWindow(self.winfo_toplevel(), duplicates)

    def _reload_row(self, finding_id: int) -> None:
        finding = self.db.get_finding(finding_id)
        if finding:
            self._update_finding(finding)

    def _open_history(self) -> None:
        if not self._ensure_idle():
            return
        HistoryWindow(self.winfo_toplevel(), self.db, self._load_scan)

    def _load_scan(self, scan_id: int) -> None:
        """Carga una caza histórica en la tabla sin ejecutar red."""
        if not self._ensure_idle():
            return
        scan = self.db.get_scan(scan_id)
        if scan is None:
            messagebox.showwarning(
                "Caza no encontrada",
                f"No existe la caza #{scan_id}.",
                parent=self,
            )
            return
        findings = self.db.list_findings(scan_id)
        self._reset_table()
        self._reset_filters()
        self.current_scan_id = scan_id
        self._duplicates_count = int(scan.get("duplicadas") or 0)
        for finding in findings:
            self._update_finding(finding)
        self._refresh_counts()
        self._set_running(False)
        self.status_pill.configure(
            text="  Histórico  ", text_color=COLORS["info"]
        )
        self.progress.set(1.0)
        self.progress_value.configure(text="100%")
        self.progress_label.configure(
            text=f"Caza #{scan_id} · {scan.get('status') or 'histórico'}"
        )
        self._log(
            "info",
            f"Caza histórica #{scan_id} cargada: {len(findings)} hallazgo(s)"
            + (
                f", {self._duplicates_count} URL(s) duplicada(s)."
                if self._duplicates_count
                else "."
            ),
        )

    def _on_double_click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        values = self.tree.item(iid, "values")
        if not values:
            return
        self._open_finding_detail(str(values[0]))

    def _open_finding_detail(self, url: str) -> None:
        finding_id = self.finding_by_url.get(url)
        if finding_id is None:
            messagebox.showinfo(
                "Hallazgo pendiente",
                "Esta URL todavía no ha sido escaneada. Espera al resultado.",
                parent=self,
            )
            return
        FindingDetailWindow(
            self.winfo_toplevel(),
            self.db,
            finding_id,
            on_change=self._reload_row,
        )

    # ------------------------------------------------------------------
    # Menú contextual de la tabla
    # ------------------------------------------------------------------
    def _show_row_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        values = self.tree.item(iid, "values")
        if not values:
            return
        url = str(values[0])
        menu = Menu(self, tearoff=0)
        menu.add_command(label="Copiar URL", command=lambda: self._copy_one_url(url))
        menu.add_command(
            label="Ver detalle", command=lambda: self._open_finding_detail(url)
        )
        menu.add_command(
            label="Enviar a SQLMap",
            command=lambda: self._send_finding_to_sqlmap(url),
        )
        menu.add_separator()
        menu.add_command(
            label="Abrir en navegador", command=lambda: self._open_in_browser(url)
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_one_url(self, url: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
            self.update_idletasks()
        except Exception as exc:  # pragma: no cover - depende del portapapeles
            messagebox.showerror(
                "No se pudo copiar",
                f"El portapapeles no está disponible: {exc}",
                parent=self,
            )
            return
        self._log("ok", "URL copiada al portapapeles.")

    def _open_in_browser(self, url: str) -> None:
        try:
            webbrowser.open(url)
            self._log("info", f"Abriendo en navegador: {url}")
        except Exception as exc:  # pragma: no cover - depende del entorno
            messagebox.showerror(
                "No se pudo abrir",
                f"El navegador no está disponible: {exc}",
                parent=self,
            )

    # ------------------------------------------------------------------
    # Verificación activa manual: cola y envío por hallazgo
    # ------------------------------------------------------------------
    def _send_finding_to_sqlmap(self, url: str) -> None:
        """Verifica con SQLMap un hallazgo concreto de la tabla."""
        if not self._ensure_idle():
            return
        finding_id = self.finding_by_url.get(url)
        if finding_id is None:
            messagebox.showinfo(
                "Hallazgo pendiente",
                "Esta URL todavía no ha sido escaneada; no hay hallazgo al "
                "que asociar el resultado de SQLMap.",
                parent=self,
            )
            return
        sqlmap_config, error = self._build_sqlmap_config(force=True)
        if error == "cancelado":
            return
        if error:
            messagebox.showerror("SQLMap no disponible", error, parent=self)
            return
        assert sqlmap_config is not None
        if sqlmap_config.output_dir is None:
            sqlmap_config.output_dir = (
                REPORTS_DIR / "sqlmap" / f"finding_{finding_id}"
            )
        self._start_sqlmap_worker(
            [{"finding_id": finding_id, "url": url}],
            scan_id=None,
            sqlmap_config=sqlmap_config,
            header=[("info", f"SQLMap directo sobre: {url}")],
            reset=False,
        )

    def _open_sqlmap_queue(self) -> None:
        window = self._sqlmap_queue_window
        if window is not None:
            try:
                if window.winfo_exists():
                    window.focus()
                    return
            except Exception:
                pass
        self._sqlmap_queue_window = SqlmapQueueWindow(
            self.winfo_toplevel(), on_run=self._run_sqlmap_queue
        )

    def _run_sqlmap_queue(self, urls: list[str]) -> None:
        """Ejecuta SQLMap directamente sobre una cola de URLs pegadas."""
        if not self._ensure_idle():
            return
        targets = normalize_target_urls(list(urls or []))
        if not targets:
            messagebox.showwarning(
                "Sin URLs válidas",
                "Ninguna línea contiene una URL http(s) con parámetros.",
                parent=self,
            )
            return
        if len(targets) > QUEUE_MAX_URLS:
            confirmed = messagebox.askyesno(
                "Cola muy larga",
                f"Hay {len(targets)} URLs válidas; se procesarán solo las "
                f"primeras {QUEUE_MAX_URLS}.\n\n¿Continuar?",
                parent=self,
            )
            if not confirmed:
                return
            targets = targets[:QUEUE_MAX_URLS]
        sqlmap_config, error = self._build_sqlmap_config(force=True)
        if error == "cancelado":
            return
        if error:
            messagebox.showerror("SQLMap no disponible", error, parent=self)
            return
        assert sqlmap_config is not None
        try:
            scan_id = self.db.create_scan(
                dork_used="Cola manual SQLMap: " + " | ".join(targets),
                country="Manual",
                domain_type="Cola SQLMap",
                keywords="",
            )
        except Exception as exc:
            messagebox.showerror(
                "Base de datos", f"No se pudo crear la caza: {exc}", parent=self
            )
            return
        self._reset_table()
        self._reset_filters()
        if self._monitor_alive():
            try:
                self.sqlmap_monitor.reset()
            except Exception:
                pass
        self.current_scan_id = scan_id
        self.cancel_event.clear()
        self._set_running(True)
        self._log("info", "=" * 64)
        self._log(
            "info",
            f"Cola manual de SQLMap: {len(targets)} URL(s) · caza #{scan_id}",
        )
        self._log(
            "warn",
            "SQLMap envía payloads reales. Continúa SOLO con autorización "
            "escrita del propietario de cada sistema.",
        )
        self._start_sqlmap_worker(
            [{"finding_id": None, "url": url} for url in targets],
            scan_id=scan_id,
            sqlmap_config=sqlmap_config,
            header=[],
            reset=False,
        )

    def _start_sqlmap_worker(
        self,
        items: list[dict[str, Any]],
        scan_id: int | None,
        sqlmap_config: SqlmapConfig,
        header: list[tuple[str, str]],
        reset: bool = True,
    ) -> None:
        if not self._ensure_idle():
            return
        if reset:
            self._reset_table()
            self._reset_filters()
            if self._monitor_alive():
                try:
                    self.sqlmap_monitor.reset()
                except Exception:
                    pass
            self.current_scan_id = scan_id
            self.cancel_event.clear()
            self._set_running(True)
            self._log("info", "=" * 64)
        for level, message in header:
            self._log(level, message)
        self.orchestrator = None
        self.worker = threading.Thread(
            target=self._sqlmap_worker_main,
            args=(items, scan_id, sqlmap_config),
            name="sqlmap-queue",
            daemon=True,
        )
        self.worker.start()

    def _sqlmap_worker_main(
        self,
        items: list[dict[str, Any]],
        scan_id: int | None,
        sqlmap_config: SqlmapConfig,
    ) -> None:
        """Worker de la verificación activa manual (fuera del orquestador).

        Para la cola crea los hallazgos; para el envío de un hallazgo
        concreto reutiliza el ``finding_id`` existente.
        """
        started = time.monotonic()
        events = self.events
        cancel = self.cancel_event
        from core.sqlmap_runner import SqlmapRunner  # import local: evita ciclo

        try:
            if scan_id is not None:
                events.put({"type": "scan_started", "scan_id": scan_id})
            for item in items:
                if cancel.is_set():
                    break
                if item.get("finding_id") is not None:
                    continue
                url = str(item.get("url") or "")
                try:
                    parsed = urlparse(url)
                    host = (parsed.hostname or "").lower()
                    query = parse_qsl(parsed.query, keep_blank_values=True)
                except ValueError:
                    host, query = "", []
                first_param = query[0][0] if query else ""
                finding_id = self.db.add_finding(
                    scan_id,
                    url,
                    domain=host,
                    parametro=first_param,
                    estado="pendiente",
                )
                item["finding_id"] = finding_id
                events.put({"type": "candidate", "url": url})
                finding = self.db.get_finding(finding_id)
                if finding:
                    events.put({"type": "result", "finding": finding})

            def on_progress(done: int, total: int) -> None:
                events.put(
                    {
                        "type": "progress",
                        "value": 0.2 + 0.8 * (done / total) if total else 1.0,
                        "label": f"SQLMap ({done}/{total})",
                    }
                )

            if cancel.is_set():
                counts: dict[str, int] | None = None
            else:
                if scan_id is not None and sqlmap_config.output_dir is None:
                    sqlmap_config.output_dir = (
                        REPORTS_DIR / "sqlmap" / f"scan_{scan_id}"
                    )
                runner = SqlmapRunner(sqlmap_config, self.db, events.put, cancel)
                counts = runner.run(items, on_progress=on_progress)

            status = "cancelado" if cancel.is_set() else "completado"
            if scan_id is not None:
                self.db.finish_scan(scan_id, status, len(items))
            events.put(
                {
                    "type": "done",
                    "summary": {
                        "scan_id": scan_id,
                        "urls": len(items),
                        "vulns": 0,
                        "duplicates": 0,
                        "cancelled": cancel.is_set(),
                        "elapsed": round(time.monotonic() - started, 1),
                        "status": status,
                        "sqlmap": counts,
                    },
                }
            )
        except Exception as exc:
            events.put({"type": "error", "message": f"Cola SQLMap: {exc}"})
            if scan_id is not None:
                try:
                    self.db.finish_scan(scan_id, "error", len(items))
                except Exception:
                    pass

    # ==================================================================
    # Log
    # ==================================================================
    def _log(self, level: str, message: str) -> None:
        if not message:
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": "·",
            "muted": "·",
            "ok": "✓",
            "warn": "!",
            "error": "✗",
        }.get(level, "·")
        try:
            self.log_box.configure(state="normal")
            self.log_box.insert("end", f"{stamp}  {prefix}  {message}\n", level)
            self.log_box.see("end")
            line_count = int(str(self.log_box.index("end-1c")).split(".")[0])
            if line_count > 800:
                self.log_box.delete("1.0", "120.0")
            self.log_box.configure(state="disabled")
        except Exception:
            pass

    # ==================================================================
    # Finalización
    # ==================================================================
    def _on_done(self, summary: dict[str, Any]) -> None:
        self._set_running(False)
        self.progress.set(1.0)
        self.progress_value.configure(text="100%")
        self.progress_label.configure(text="Completado")

        cancelled = bool(summary.get("cancelled"))
        status = str(summary.get("status", "completado"))
        urls = int(summary.get("urls", 0))
        vulns = int(summary.get("vulns", 0))
        duplicates = int(summary.get("duplicates", 0))
        elapsed = float(summary.get("elapsed", 0.0))
        sqlmap_counts = summary.get("sqlmap") or {}
        self._duplicates_count = duplicates
        self._refresh_counts()

        if cancelled:
            self.status_pill.configure(text="  Cancelado  ", text_color=COLORS["warning"])
            self._log("warn", f"Caza cancelada tras {elapsed:.1f}s.")
            return
        if status == "error":
            self.status_pill.configure(text="  Error  ", text_color=COLORS["danger"])
            return

        self._log(
            "ok",
            f"Caza completada en {elapsed:.1f}s · {urls} URLs · {vulns} posibles"
            + (f" · {duplicates} duplicadas." if duplicates else "."),
        )
        if sqlmap_counts:
            self._log(
                "info",
                "Verificación activa: "
                f"{sqlmap_counts.get('sqlmap_vulnerable', 0)} vulnerable(s), "
                f"{sqlmap_counts.get('sqlmap_limpio', 0)} sin inyección, "
                f"{sqlmap_counts.get('sqlmap_error', 0)} con error.",
            )
        if vulns:
            messagebox.showinfo(
                "Caza completada",
                f"Se encontraron {vulns} posibles vulnerabilidades.\n\n"
                "Haz doble clic en una fila para revisar la evidencia y "
                "generar el reporte de divulgación responsable.",
                parent=self,
            )

    # ==================================================================
    # Exportación y carpetas
    # ==================================================================
    def _export_csv(self) -> None:
        rows = self.db.list_findings(self.current_scan_id)
        if not rows:
            messagebox.showinfo(
                "Sin datos",
                "Todavía no hay hallazgos para exportar.",
                parent=self,
            )
            return

        path = filedialog.asksaveasfilename(
            parent=self,
            title="Exportar hallazgos a CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"dorkhunter_{datetime.now():%Y%m%d_%H%M}.csv",
        )
        if not path:
            return

        try:
            import pandas as pd
        except ImportError:
            messagebox.showerror(
                "Falta pandas",
                "Instala la dependencia con:\n\npip install pandas",
                parent=self,
            )
            return

        frame = pd.DataFrame(
            [
                {
                    "ID": row["id"],
                    "URL": row["url"],
                    "Dominio": row["domain"],
                    "Parámetro": row["parametro"],
                    "Estado": ESTADO_LABELS.get(row["estado"], row["estado"]),
                    "Motor": row.get("dbms") or "",
                    "WAF": row.get("waf") or "",
                    "Confianza": CONFIANZA_LABELS.get(
                        str(row.get("confianza") or ""),
                        row.get("confianza") or "",
                    ),
                    "Error detectado": row["error_detectado"],
                    "HTTP": row["http_status"],
                    "Contacto": row["contacto"],
                    "Organización": row["organizacion"],
                    "Registrador": row.get("registrar") or "",
                    "País WHOIS": row.get("whois_country") or "",
                    "security.txt": row["security_txt"],
                    "Fuente enriquecimiento": row.get("enrichment_source") or "",
                    "Estado reporte": row["estado_reporte"],
                    "Fecha": row["created_at"],
                }
                for row in rows
            ]
        )
        try:
            frame.to_csv(path, index=False, encoding="utf-8-sig")
        except OSError as exc:
            messagebox.showerror(
                "No se pudo exportar", f"Error al escribir el archivo:\n{exc}", parent=self
            )
            return

        if messagebox.askyesno(
            "Exportación completada",
            f"Guardado en:\n{path}\n\n¿Abrir la carpeta?",
            parent=self,
        ):
            open_path(Path(path).parent)

    def _export_json(self) -> None:
        if self.current_scan_id is None:
            messagebox.showinfo(
                "Sin caza seleccionada",
                "Ejecuta o carga una caza antes de exportar JSON.",
                parent=self,
            )
            return
        scan = self.db.get_scan(self.current_scan_id)
        rows = self.db.list_findings(self.current_scan_id)
        if not rows:
            messagebox.showinfo(
                "Sin datos",
                "Todavía no hay hallazgos para exportar.",
                parent=self,
            )
            return

        path = filedialog.asksaveasfilename(
            parent=self,
            title="Exportar caza a JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"dorkhunter_{datetime.now():%Y%m%d_%H%M}.json",
        )
        if not path:
            return
        try:
            content = ReportGenerator(REPORTS_DIR).build_scan_json(
                scan or {"id": self.current_scan_id}, rows
            )
            Path(path).write_text(content, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(
                "No se pudo exportar",
                f"Error al escribir el archivo:\n{exc}",
                parent=self,
            )
            return

        if messagebox.askyesno(
            "Exportación completada",
            f"Guardado en:\n{path}\n\n¿Abrir la carpeta?",
            parent=self,
        ):
            open_path(Path(path).parent)

    def _generate_scan_report(self) -> None:
        if self.current_scan_id is None:
            messagebox.showinfo(
                "Sin caza seleccionada",
                "Ejecuta o carga una caza antes de generar el reporte.",
                parent=self,
            )
            return
        scan = self.db.get_scan(self.current_scan_id)
        if scan is None:
            messagebox.showwarning(
                "Caza no encontrada",
                f"No existe la caza #{self.current_scan_id}.",
                parent=self,
            )
            return
        findings = self.db.list_findings(self.current_scan_id)
        dialog = ctk.CTkInputDialog(
            text="Formato del reporte de caza (md, html o json):",
            title="Reporte de caza",
        )
        fmt = (dialog.get_input() or "").strip().lower().lstrip(".")
        if not fmt:
            return
        if fmt not in {"md", "html", "json"}:
            messagebox.showwarning(
                "Formato no válido",
                "Usa md, html o json.",
                parent=self,
            )
            return
        try:
            path = ReportGenerator(REPORTS_DIR).generate_scan(scan, findings, fmt)
        except Exception as exc:
            messagebox.showerror(
                "No se pudo generar el reporte",
                f"Error: {exc}",
                parent=self,
            )
            return
        if messagebox.askyesno(
            "Reporte de caza generado",
            f"Guardado en:\n{path}\n\n¿Abrirlo ahora?",
            parent=self,
        ):
            open_path(path)

    def _open_reports(self) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if not open_path(REPORTS_DIR):
            messagebox.showinfo(
                "Carpeta de reportes",
                f"No se pudo abrir el gestor de archivos.\n\n{REPORTS_DIR}",
                parent=self,
            )

    def _show_legal(self) -> None:
        LegalNoticeWindow(self.winfo_toplevel())

    # ==================================================================
    def shutdown(self) -> bool:
        """Detiene la caza. Devuelve True si el hilo terminó a tiempo."""
        self._alive = False
        self.cancel_event.set()
        if self.worker is not None and self.worker.is_alive():
            self.worker.join(timeout=1.5)
            return not self.worker.is_alive()
        return True
