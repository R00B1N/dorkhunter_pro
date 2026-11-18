#!/usr/bin/env python3
"""DorkHunter Pro — edición mono-script (un solo archivo, sin GUI).

Copia autocontenida de la lógica completa del proyecto (generada a partir de
los módulos originales; el proyecto de referencia sigue intacto en la carpeta
madre). Conserva el mismo alcance y límites:

* Dorks por país/tipo de dominio + búsqueda en motores públicos (sin Google).
* Detección PASIVA de errores SQL con una sola comilla por URL, con motor,
  confianza y etiquetado de WAF.
* Enriquecimiento WHOIS/security.txt, fuentes pasivas (Wayback CDX, OTX,
  crt.sh), importación de .txt, allowlist/denylist de dominios.
* Verificación ACTIVA opcional con SQLMap (apagada por defecto; requiere
  confirmación propia; --dbs extrae datos), presets y flags, hasta 8 procesos.
* Historial en SQLite, exportación CSV/JSON y reportes MD/HTML/JSON.

Uso idéntico al CLI del proyecto:

    python dorkhunter_pro_mono.py --country Colombia --type "Educativo (edu)" --yes
    python dorkhunter_pro_mono.py --url "https://dominio.com/item.php?id=1" --yes
    python dorkhunter_pro_mono.py --help

Este script NO incluye la interfaz gráfica. Las rutas data/ y reports/ se
crean junto al propio archivo, así que conviene aislarlo en su carpeta.
"""
from __future__ import annotations


# ==========================================================================
# Configuración y límites  (de config.py)
# ==========================================================================
"""Configuración central de DorkHunter Pro.

Todos los valores ajustables viven aquí para evitar constantes dispersas.
Los límites de red son deliberadamente conservadores: la herramienta hace
triaje pasivo, no explotación.
"""

from pathlib import Path

APP_NAME = "DorkHunter Pro"
APP_VERSION = "1.4.0"
DISCLAIMER_VERSION = "1.1"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
DB_PATH = DATA_DIR / "dorkhunter.db"

# ---------------------------------------------------------------------------
# Identificación del cliente HTTP.
# Un User-Agent honesto con un correo de contacto real es parte de la
# divulgación responsable. CAMBIA este correo antes de usar la herramienta.
# ---------------------------------------------------------------------------
CONTACT_EMAIL = "security@example.org"
USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} "
    f"(passive SQLi triage; responsible disclosure; contact: {CONTACT_EMAIL})"
)

# ---------------------------------------------------------------------------
# Límites de red
# ---------------------------------------------------------------------------
HTTP_TIMEOUT = 10                 # segundos por petición
MAX_BODY_BYTES = 512 * 1024       # no descargar más de 512 KB por respuesta
MAX_REDIRECTS = 3

SCAN_DELAY_PER_HOST = 1.5         # segundos entre peticiones al mismo host
SCAN_WORKERS = 3                  # peticiones simultáneas (global)
MAX_PARAMS_PER_URL = 1            # un parámetro por URL (el de mayor prioridad)

SEARCH_DELAY = 2.0                # segundos entre consultas a un motor
SEARCH_TIMEOUT = 20
SEARCH_RETRIES = 3
SEARCH_ENGINES: tuple[str, ...] = ("duckduckgo", "brave", "bing", "mojeek")

WHOIS_TIMEOUT = 12
WHOIS_DELAY = 2.0

MAX_RESULTS_PER_DORK = 25
MAX_URLS_PER_HUNT = 40
DEFAULT_DORK_COUNT = 10

# ---------------------------------------------------------------------------
# Verificación activa con SQLMap (OPCIONAL, desactivada por defecto).
# SQLMap envía payloads reales y, con --dbs, extrae datos. Úsala SOLO sobre
# sistemas con autorización escrita. El binario debe estar en el PATH o
# apuntar a una ruta absoluta.
# ---------------------------------------------------------------------------
SQLMAP_BIN = "sqlmap"
PROXYCHAINS_BIN = "proxychains4"
SQLMAP_TIMEOUT = 600              # segundos por URL
SQLMAP_WORKERS = 2                # procesos sqlmap simultáneos

MAX_EVIDENCE_CHARS = 600


# ==========================================================================
# Utilidades compartidas  (de utils/helpers.py)
# ==========================================================================
"""Utilidades pequeñas y sin dependencias pesadas."""

import html
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")


def now_iso() -> str:
    """Fecha local en ISO-8601 con zona horaria."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def strip_html(text: str) -> str:
    """Convierte HTML en texto plano legible (sin dependencias)."""
    if not text:
        return ""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def redact_sensitive(text: str) -> str:
    """Elimina correos, hashes y tokens largos de la evidencia almacenada."""
    if not text:
        return ""
    text = _EMAIL_RE.sub("[correo redactado]", text)
    text = _HEX_RE.sub("[hash redactado]", text)
    text = _B64_RE.sub("[token redactado]", text)
    return text


def sanitize_filename(value: str, max_len: int = 60) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return (value[:max_len] or "sin_nombre")


def open_path(path: str | Path) -> bool:
    """Abre un archivo o carpeta con la aplicación predeterminada del sistema."""
    target = str(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(target)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
        return True
    except Exception:
        return False


# ==========================================================================
# Generación de dorks  (de core/dork_engine.py)
# ==========================================================================
"""Generación de Google Dorks acotados por país y tipo de dominio.

El motor construye consultas con los operadores ``site:``, ``inurl:`` e
``intext:``. ``core.search_engine`` adapta la consulta a cada buscador: los
que no soportan ``inurl:`` reciben el parámetro como frase entre comillas.
"""

import re
import unicodedata
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Catálogo de países agrupado por región. El campo ``gov`` solo se declara
# cuando el prefijo real difiere del estándar (México usa gob.mx, Uruguay
# gub.uy, Costa Rica go.cr, Francia gouv.fr, Canadá gc.ca, Suiza admin.ch...).
# ---------------------------------------------------------------------------
COUNTRY_CATEGORIES: dict[str, tuple[str, ...]] = {
    "Todos / Internacional": ("Todos / Internacional",),
    "Latinoamérica": (
        "Argentina",
        "Bolivia",
        "Brasil",
        "Chile",
        "Colombia",
        "Costa Rica",
        "Cuba",
        "Ecuador",
        "El Salvador",
        "Guatemala",
        "Honduras",
        "México",
        "Nicaragua",
        "Panamá",
        "Paraguay",
        "Perú",
        "Puerto Rico",
        "República Dominicana",
        "Uruguay",
        "Venezuela",
    ),
    "Norteamérica y Caribe": (
        "Canadá",
        "Estados Unidos",
        "Bahamas",
        "Barbados",
        "Jamaica",
        "Trinidad y Tobago",
    ),
    "Europa": (
        "Alemania",
        "Austria",
        "Bélgica",
        "Chequia",
        "Dinamarca",
        "España",
        "Finlandia",
        "Francia",
        "Grecia",
        "Hungría",
        "Irlanda",
        "Italia",
        "Noruega",
        "Países Bajos",
        "Polonia",
        "Portugal",
        "Reino Unido",
        "Rumanía",
        "Rusia",
        "Suecia",
        "Suiza",
        "Turquía",
        "Ucrania",
    ),
    "Asia y Oceanía": (
        "Australia",
        "Bangladés",
        "China",
        "Corea del Sur",
        "Filipinas",
        "India",
        "Indonesia",
        "Japón",
        "Malasia",
        "Nueva Zelanda",
        "Pakistán",
        "Singapur",
        "Tailandia",
        "Vietnam",
    ),
    "África y Oriente Medio": (
        "Arabia Saudita",
        "Argelia",
        "Catar",
        "Egipto",
        "Emiratos Árabes Unidos",
        "Ghana",
        "Israel",
        "Kenia",
        "Marruecos",
        "Nigeria",
        "Sudáfrica",
        "Túnez",
    ),
}

COUNTRIES: dict[str, dict[str, str]] = {
    "Todos / Internacional": {"tld": ""},
    # Latinoamérica ------------------------------------------------------
    "Argentina": {"tld": "ar", "gov": "gob"},
    "Bolivia": {"tld": "bo", "gov": "gob"},
    "Brasil": {"tld": "br"},
    "Chile": {"tld": "cl", "gov": "gob"},
    "Colombia": {"tld": "co"},
    "Costa Rica": {"tld": "cr", "gov": "go"},
    "Cuba": {"tld": "cu", "gov": "gob"},
    "Ecuador": {"tld": "ec", "gov": "gob"},
    "El Salvador": {"tld": "sv", "gov": "gob"},
    "Guatemala": {"tld": "gt", "gov": "gob"},
    "Honduras": {"tld": "hn", "gov": "gob"},
    "México": {"tld": "mx", "gov": "gob"},
    "Nicaragua": {"tld": "ni", "gov": "gob"},
    "Panamá": {"tld": "pa", "gov": "gob"},
    "Paraguay": {"tld": "py"},
    "Perú": {"tld": "pe", "gov": "gob"},
    "Puerto Rico": {"tld": "pr"},
    "República Dominicana": {"tld": "do", "gov": "gob"},
    "Uruguay": {"tld": "uy", "gov": "gub"},
    "Venezuela": {"tld": "ve", "gov": "gob"},
    # Norteamérica y Caribe ---------------------------------------------
    "Canadá": {"tld": "ca", "gov": "gc"},
    "Estados Unidos": {"tld": "us"},
    "Bahamas": {"tld": "bs"},
    "Barbados": {"tld": "bb"},
    "Jamaica": {"tld": "jm"},
    "Trinidad y Tobago": {"tld": "tt"},
    # Europa -------------------------------------------------------------
    "Alemania": {"tld": "de", "gov": "bund"},
    "Austria": {"tld": "at", "gov": "gv"},
    "Bélgica": {"tld": "be"},
    "Chequia": {"tld": "cz"},
    "Dinamarca": {"tld": "dk"},
    "España": {"tld": "es", "gov": "gob"},
    "Finlandia": {"tld": "fi"},
    "Francia": {"tld": "fr", "gov": "gouv"},
    "Grecia": {"tld": "gr"},
    "Hungría": {"tld": "hu"},
    "Irlanda": {"tld": "ie"},
    "Italia": {"tld": "it"},
    "Noruega": {"tld": "no"},
    "Países Bajos": {"tld": "nl", "gov": "overheid"},
    "Polonia": {"tld": "pl"},
    "Portugal": {"tld": "pt"},
    "Reino Unido": {"tld": "uk"},
    "Rumanía": {"tld": "ro"},
    "Rusia": {"tld": "ru"},
    "Suecia": {"tld": "se"},
    "Suiza": {"tld": "ch", "gov": "admin"},
    "Turquía": {"tld": "tr"},
    "Ucrania": {"tld": "ua"},
    # Asia y Oceanía -----------------------------------------------------
    "Australia": {"tld": "au"},
    "Bangladés": {"tld": "bd"},
    "China": {"tld": "cn"},
    "Corea del Sur": {"tld": "kr", "gov": "go"},
    "Filipinas": {"tld": "ph"},
    "India": {"tld": "in"},
    "Indonesia": {"tld": "id", "gov": "go"},
    "Japón": {"tld": "jp", "gov": "go"},
    "Malasia": {"tld": "my"},
    "Nueva Zelanda": {"tld": "nz", "gov": "govt"},
    "Pakistán": {"tld": "pk"},
    "Singapur": {"tld": "sg"},
    "Tailandia": {"tld": "th", "gov": "go"},
    "Vietnam": {"tld": "vn"},
    # África y Oriente Medio --------------------------------------------
    "Arabia Saudita": {"tld": "sa"},
    "Argelia": {"tld": "dz"},
    "Catar": {"tld": "qa"},
    "Egipto": {"tld": "eg"},
    "Emiratos Árabes Unidos": {"tld": "ae"},
    "Ghana": {"tld": "gh"},
    "Israel": {"tld": "il"},
    "Kenia": {"tld": "ke", "gov": "go"},
    "Marruecos": {"tld": "ma"},
    "Nigeria": {"tld": "ng"},
    "Sudáfrica": {"tld": "za"},
    "Túnez": {"tld": "tn"},
}

DOMAIN_TYPES: dict[str, str] = {
    "Educativo (edu)": "edu",
    "Gubernamental (gov)": "gov",
    "Gubernamental (gob)": "gob",
    "Militar (mil)": "mil",
    "Organizaciones (org)": "org",
    "Comercial (com)": "com",
    "Redes (net)": "net",
    "Salud (salud)": "salud",
    "Todos": "",
}

# Patrones de parámetros clásicamente vulnerables. El orden importa: los
# primeros son los que se prueban en una caza "Rápida".
VULNERABLE_PARAMS: tuple[str, ...] = (
    "id",
    "cat",
    "page",
    "user",
    "search",
    "item",
    "product",
    "news",
    "article",
    "file",
    "view",
    "lang",
    "q",
    "s",
    "pid",
    "nid",
    "tid",
    "cid",
    "doc",
    "menu",
    "mod",
    "option",
    "cmd",
    "url",
    "path",
    "report",
    "download",
    "album",
    "gallery",
    "year",
    "month",
    "date",
    "keyword",
    "query",
    "idx",
    "cod",
    "codigo",
    "num",
    "folio",
    "ref",
    # Ampliación para cazas profundas (más variedad de parámetros).
    "tipo",
    "categoria",
    "seccion",
    "pagina",
    "noticia",
    "evento",
    "curso",
    "programa",
    "materia",
    "estudiante",
    "docente",
    "profesor",
    "empleado",
    "cliente",
    "proveedor",
    "servicio",
    "solicitud",
    "tramite",
    "formulario",
    "encuesta",
    "foro",
    "tema",
    "blog",
    "video",
    "imagen",
    "archivo",
    "adjunto",
    "plantilla",
    "modulo",
    "accion",
    "tabla",
    "registro",
    "consulta",
    "buscar",
    "clave",
    "area",
    "sede",
    "carrera",
    "convocatoria",
    "normativa",
    "resolucion",
    "acuerdo",
    "circular",
    "informe",
    "acta",
    "planilla",
    "nomina",
    "presupuesto",
    "contrato",
)

# ---------------------------------------------------------------------------
# Sugerencias para el campo de palabras clave (autocompletado de la GUI).
# ---------------------------------------------------------------------------
KEYWORD_SUGGESTIONS: tuple[str, ...] = (
    "admin",
    "login",
    "intranet",
    "portal",
    "sistema",
    "usuarios",
    "matrícula",
    "pagos",
    "facturación",
    "documentos",
    "noticias",
    "eventos",
    "biblioteca",
    "campus",
    "becas",
    "convocatorias",
    "empleo",
    "contratación",
    "licitaciones",
    "reportes",
    "estadísticas",
    "transparencia",
    "datos abiertos",
    "investigación",
    "posgrado",
    "egresados",
    "certificados",
    "boletines",
    "descargas",
    "soporte",
    "ayuda",
    "contacto",
    "formulario",
    "registro",
    "consulta",
)


def _fold(text: str) -> str:
    """Minúsculas sin acentos, para comparar sugerencias."""
    normalized = unicodedata.normalize("NFKD", (text or "").lower())
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def suggest_keywords(prefix: str, limit: int = 6) -> list[str]:
    """Sugerencias para el campo de palabras clave.

    Coincide sin distinguir mayúsculas ni acentos: ``matri`` sugiere
    ``matrícula``. Con un prefijo vacío devuelve las primeras sugerencias.
    """
    folded = _fold((prefix or "").strip())
    if not folded:
        return list(KEYWORD_SUGGESTIONS[: max(1, limit)])
    starts = [word for word in KEYWORD_SUGGESTIONS if _fold(word).startswith(folded)]
    contains = [
        word
        for word in KEYWORD_SUGGESTIONS
        if folded in _fold(word) and word not in starts
    ]
    return (starts + contains)[: max(1, limit)]


_SITE_RE = re.compile(r"\bsite:\s*([^\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Dork:
    query: str
    pattern: str = ""
    label: str = ""
    scope_suffix: str = ""


class DorkEngine:
    def __init__(self, patterns: tuple[str, ...] | None = None) -> None:
        self.patterns = patterns or VULNERABLE_PARAMS

    # ------------------------------------------------------------------
    def suffix_for(self, country: str, domain_type: str) -> str:
        """Devuelve el sufijo de ``site:`` (p. ej. ``edu.co``), o ``''``."""
        info = COUNTRIES.get(country)
        if not info:
            raise ValueError(f"País no soportado: {country}")
        tld = info.get("tld", "")
        if not tld:
            return ""
        prefix = DOMAIN_TYPES.get(domain_type)
        if prefix is None:
            raise ValueError(f"Tipo de dominio no soportado: {domain_type}")
        if not prefix:
            return tld
        if prefix == "gov":
            prefix = info.get("gov", "gov")
        return f"{prefix}.{tld}"

    # ------------------------------------------------------------------
    def build(
        self,
        country: str,
        domain_type: str,
        keywords: str = "",
        manual_dork: str = "",
        limit: int = DEFAULT_DORK_COUNT,
    ) -> list[Dork]:
        """Genera la lista de dorks que se enviarán al buscador."""
        manual = (manual_dork or "").strip()
        if manual:
            scope = ""
            match = _SITE_RE.search(manual)
            if match:
                scope = match.group(1).strip().lower()
            return [
                Dork(
                    query=manual,
                    pattern="manual",
                    label="Dork manual",
                    scope_suffix=scope,
                )
            ]

        suffix = self.suffix_for(country, domain_type)
        if not suffix:
            raise ValueError(
                "Selecciona un país concreto o escribe un dork manual que "
                "incluya site:dominio para acotar el alcance."
            )

        base = f"site:{suffix}"
        keyword_clause = self._normalize_keywords(keywords)
        if keyword_clause:
            # Se usa intext: (estilo Google). search_engine lo traduce para DDG.
            base += f" {keyword_clause}"

        patterns = list(self.patterns[: max(1, limit)])
        return [
            Dork(
                query=f"{base} inurl:{pattern}=",
                pattern=pattern,
                label=f"Parámetro {pattern}",
                scope_suffix=suffix,
            )
            for pattern in patterns
        ]

    # ------------------------------------------------------------------
    def preview(
        self,
        country: str,
        domain_type: str,
        keywords: str = "",
        manual_dork: str = "",
    ) -> str:
        dorks = self.build(
            country, domain_type, keywords, manual_dork, limit=1
        )
        return dorks[0].query

    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_keywords(keywords: str) -> str:
        """Convierte palabras clave en una o varias cláusulas ``intext:``.

        Acepta una frase (``pagos en línea``) o una lista separada por comas
        (``matrícula, pagos``). En el segundo caso se genera un ``intext:`` por
        término para no buscar la coma como parte de la frase.
        """
        value = (keywords or "").strip()
        if not value:
            return ""
        value = value.strip('"').strip()
        if not value:
            return ""
        parts = [
            part.strip().strip('"')
            for part in value.split(",")
            if part.strip().strip('"')
        ]
        if not parts:
            return ""
        unique: list[str] = []
        seen: set[str] = set()
        for part in parts:
            key = part.casefold()
            if key not in seen:
                seen.add(key)
                unique.append(part)
        terms = [
            f'"{part}"' if re.search(r"\s", part) else part
            for part in unique
        ]
        return " ".join(f"intext:{term}" for term in terms)


# ==========================================================================
# Búsqueda en motores públicos  (de core/search_engine.py)
# ==========================================================================
"""Recolección de URLs en varios buscadores públicos (sin Google).

Para cada dork se combina:

1. la librería ``ddgs`` con un backend concreto (DuckDuckGo, Brave, Mojeek).
2. el HTML público de Bing, Brave y Mojeek si la librería falla o no trae nada.

Google se descarta a propósito porque es el motor que más bloquea el triaje
automatizado. Todos los motores se consultan con el mismo ``User-Agent``
honesto y respetan un espaciado mínimo entre peticiones.
"""

import base64
import logging
import re
import threading
import time
from collections.abc import Iterable
from typing import Callable
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)

SUPPORTED_ENGINES: tuple[str, ...] = (
    "duckduckgo",
    "brave",
    "bing",
    "mojeek",
    "yahoo",
    "yandex",
)

ENGINE_LABELS = {
    "duckduckgo": "DuckDuckGo",
    "brave": "Brave",
    "bing": "Bing",
    "mojeek": "Mojeek",
    "yahoo": "Yahoo",
    "yandex": "Yandex",
}

# Motores cuyo HTML público se puede leer sin API ni Google.
_HTML_PROVIDERS: dict[str, dict[str, str]] = {
    "bing": {"endpoint": "https://www.bing.com/search"},
    "brave": {"endpoint": "https://search.brave.com/search"},
    "mojeek": {"endpoint": "https://www.mojeek.com/search"},
}
_CSS_SELECTORS = {
    "bing": "li.b_algo h2 a[href]",
    "brave": "div[data-type='web'] a[href]",
    "mojeek": "ul.results li h2 a[href]",
}
_SEARCH_HOSTS: tuple[str, ...] = (
    "duckduckgo.com",
    "brave.com",
    "bing.com",
    "mojeek.com",
    "yahoo.com",
    "yandex.com",
)

_BINARY_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".jpg", ".jpeg", ".png",
    ".gif", ".webp", ".svg", ".mp3", ".mp4", ".avi", ".mov", ".exe",
    ".dmg", ".iso", ".apk",
}


def normalize_engines(
    engines: str | Iterable[str] | None,
) -> list[str]:
    """Convierte ``"brave,bing,mojeek"`` en una lista limpia y válida.

    ``None``, lista vacía y ``""`` significa *usar ``SEARCH_ENGINES``*.
    Si se pide ``auto``, se devuelve el orden por defecto.
    """
    if not engines:
        return list(SEARCH_ENGINES)
    if isinstance(engines, str):
        tokens = re.split(r"[,\s]+", engines.strip())
    else:
        tokens = [str(value) for value in engines]
    valid: list[str] = []
    for token in (token.strip().lower() for token in tokens if token.strip()):
        if token in {"auto", "all", "todos"}:
            for engine in SEARCH_ENGINES:
                if engine not in valid:
                    valid.append(engine)
            continue
        if token not in SUPPORTED_ENGINES:
            raise ValueError(
                "Motores disponibles: " + ", ".join(SUPPORTED_ENGINES)
                + " (o 'auto')."
            )
        if token not in valid:
            valid.append(token)
    return valid


def _load_ddgs():
    """Devuelve la clase DDGS si alguna de las dos variantes está instalada."""
    try:
        from ddgs import DDGS  # type: ignore

        return DDGS
    except Exception:
        pass
    try:
        from duckduckgo_search import DDGS  # type: ignore

        return DDGS
    except Exception:
        return None


def translate_query(query: str) -> str:
    """Adapta operadores estilo Google a lo que los demás motores entienden.

    - ``intext:"frase"``  ->  ``"frase"``
    - ``ext:php``         ->  ``filetype:php``
    """
    query = re.sub(r'\bintext:\s*"([^"]*)"', r'"\1"', query, flags=re.IGNORECASE)
    query = re.sub(r"\bintext:\s*(\S+)", r"\1", query, flags=re.IGNORECASE)
    query = re.sub(r"\bext:(\w+)", r"filetype:\1", query, flags=re.IGNORECASE)
    return query.strip()


# Motores que no interpretan ``inurl:``. Para ellos la cadena del dork se
# convierte en una frase entre comillas: es la aproximación más cercana sin
# recurrir a Google y evita resultados totalmente fuera de contexto.
_NO_INURL_ENGINES = frozenset({"bing", "brave", "yahoo", "yandex"})


def translate_query_for_engine(query: str, engine: str) -> str:
    """Traduce la consulta para un motor concreto.

    ``translate_query`` se aplica siempre. Además, los motores sin soporte de
    ``inurl:`` reciben la cadena como frase entre comillas; DuckDuckGo y
    Mojeek conservan el operador original.
    """
    query = translate_query(query)
    if engine in _NO_INURL_ENGINES:
        query = re.sub(
            r"\binurl:\s*(\S+)",
            lambda match: f'"{match.group(1)}"',
            query,
            flags=re.IGNORECASE,
        )
        query = re.sub(r"\s+", " ", query).strip()
    return query


def decode_ddg_link(href: str) -> str:
    """Extrae la URL real de los enlaces de redirección de DuckDuckGo."""
    href = (href or "").strip()
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        values = parse_qs(parsed.query).get("uddg")
        if values:
            return unquote(values[0])
    return href


def _extract_site_host(query: str) -> str:
    """Extrae el dominio de un operador ``site:`` para filtrar resultados.

    Devuelve ``""`` si el dork no acota el dominio; en ese caso no se filtra
    por host. Se acepta ``site:edu.co``, ``site: www.ejemplo.com`` y
    ``site:"ejemplo.com"``.
    """
    match = re.search(r'\bsite:\s*"?([^\s"\']+)"?', query, flags=re.IGNORECASE)
    if not match:
        return ""
    host = match.group(1).strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _unwrap_bing_url(href: str) -> str:
    """Descodifica el ``u=...`` en base64url de los enlaces de Bing."""
    raw = (href or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    values = parse_qs(parsed.query).get("u")
    if not values:
        return raw
    encoded = values[0]
    if len(encoded) <= 2:
        return raw
    try:
        payload = encoded[2:]
        stripped = payload.rstrip("=")
        decoded = base64.urlsafe_b64decode(
            stripped + "=" * (-len(stripped) % 4)
        )
        return decoded.decode("utf-8", "ignore") or raw
    except Exception:
        return raw


class SearchEngine:
    def __init__(
        self,
        delay: float = SEARCH_DELAY,
        timeout: int = SEARCH_TIMEOUT,
        max_results: int = 25,
    ) -> None:
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self.max_results = max_results
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept-Language": "es-CO,es;q=0.9,en;q=0.8",
                "Accept": "text/html,application/xhtml+xml",
            }
        )
        self._lock = threading.Lock()
        self._next_allowed = 0.0
        self._ddgs = _load_ddgs()

    # ------------------------------------------------------------------
    def search(
        self,
        query: str,
        max_results: int | None = None,
        cancel_event: threading.Event | None = None,
        log: Callable[[str, str], None] | None = None,
        engines: str | Iterable[str] | None = None,
    ) -> list[str]:
        limit = int(max_results or self.max_results)
        labels = normalize_engines(engines)
        site_host = _extract_site_host(query)

        results: list[str] = []
        for engine in labels:
            if cancel_event is not None and cancel_event.is_set():
                break
            try:
                results.extend(
                    self._search_engine(
                        engine, query, limit, cancel_event, log
                    )
                )
            except Exception as exc:
                logger.warning("%s falló: %s", ENGINE_LABELS.get(engine, engine), exc)
                if log:
                    log("warn", f"{engine} falló ({exc}).")
            results = self._clean(results, limit, site_host=site_host)
            if len(results) >= limit:
                break

        cleaned = results
        if not cleaned and log:
            log(
                "warn",
                "Ningún motor de búsqueda devolvió URLs utilizables.",
            )
        return cleaned

    # ------------------------------------------------------------------
    def _search_engine(
        self,
        engine: str,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        query = translate_query_for_engine(query, engine)
        if engine == "duckduckgo":
            return self._search_duckduckgo(query, limit, cancel_event, log)
        if engine == "brave":
            return self._search_brave(query, limit, cancel_event, log)
        if engine == "bing":
            return self._search_bing(query, limit, cancel_event, log)
        if engine == "mojeek":
            return self._search_mojeek(query, limit, cancel_event, log)
        if engine == "yahoo":
            return self._search_yahoo(query, limit, cancel_event, log)
        if engine == "yandex":
            return self._search_yandex(query, limit, cancel_event, log)
        raise ValueError(f"Motor no implementado: {engine}.")

    def _search_duckduckgo(
        self,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        if self._ddgs:
            try:
                return self._search_ddgs(query, limit, cancel_event)
            except Exception as exc:
                logger.warning("ddgs/DuckDuckGo falló: %s", exc)
        return self._search_html("duckduckgo", query, limit, cancel_event, log)

    def _search_brave(
        self,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        if self._ddgs:
            try:
                return self._search_ddgs(query, limit, cancel_event, backend="brave")
            except Exception as exc:
                logger.warning("ddgs/Brave falló: %s", exc)
        return self._search_html("brave", query, limit, cancel_event, log)

    def _search_bing(
        self,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        return self._search_html("bing", query, limit, cancel_event, log)

    def _search_mojeek(
        self,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        if self._ddgs:
            try:
                return self._search_ddgs(query, limit, cancel_event, backend="mojeek")
            except Exception as exc:
                logger.warning("ddgs/Mojeek falló: %s", exc)
        return self._search_html("mojeek", query, limit, cancel_event, log)

    def _search_yahoo(
        self,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        if self._ddgs:
            try:
                return self._search_ddgs(query, limit, cancel_event, backend="yahoo")
            except Exception as exc:
                logger.warning("ddgs/Yahoo falló: %s", exc)
        return []

    def _search_yandex(
        self,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        if self._ddgs:
            try:
                return self._search_ddgs(query, limit, cancel_event, backend="yandex")
            except Exception as exc:
                logger.warning("ddgs/Yandex falló: %s", exc)
        return []

    # ------------------------------------------------------------------
    def _search_ddgs(
        self,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        backend: str = "duckduckgo",
    ) -> list[str]:
        assert self._ddgs is not None
        found: list[str] = []
        self._throttle(cancel_event)
        with self._ddgs() as ddgs:  # type: ignore[union-attr]
            try:
                iterator = ddgs.text(
                    query, max_results=limit, backend=backend, safesearch="off"
                )
            except TypeError:
                iterator = ddgs.text(query, max_results=limit)
            for item in iterator:
                if cancel_event is not None and cancel_event.is_set():
                    break
                href = item.get("href") or item.get("link") or item.get("url")
                if href:
                    found.append(str(href))
                if len(found) >= limit:
                    break
        return found

    # ------------------------------------------------------------------
    def _search_html(
        self,
        engine: str,
        query: str,
        limit: int,
        cancel_event: threading.Event | None,
        log: Callable[[str, str], None] | None,
    ) -> list[str]:
        label = ENGINE_LABELS.get(engine, engine.title())
        payload = {"q": query, "kl": "wt-wt", "kp": "-1"} if engine == "duckduckgo" else {"q": query}
        if engine in _HTML_PROVIDERS:
            if engine == "bing":
                payload["mkt"] = "es-CO"
            if engine == "brave":
                payload["source"] = "web"
            if engine == "mojeek":
                payload["tlen"] = "0"
            target = _HTML_PROVIDERS[engine]["endpoint"].rstrip("/")
            method = "GET"
        else:
            # Mantenemos la ruta histórica del endpoint HTML de DuckDuckGo.
            target = "https://html.duckduckgo.com/html/"
            method = "POST"

        selector = _CSS_SELECTORS.get(engine, "a.result__a")
        for attempt in range(1, SEARCH_RETRIES + 1):
            if cancel_event is not None and cancel_event.is_set():
                return []
            self._throttle(cancel_event)
            try:
                response = self._session.request(
                    method=method,
                    url=target,
                    params=payload if method == "GET" else None,
                    data=payload if method == "POST" else None,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                logger.warning("Intento %s con %s falló: %s", attempt, label, exc)
                self._sleep(2.0 * attempt, cancel_event)
                continue

            if response.status_code in {403, 406, 409, 429, 503}:
                if log:
                    log("warn", f"{label} limitó la petición (HTTP {response.status_code}).")
                self._sleep(3.0 * attempt, cancel_event)
                continue
            if response.status_code != 200:
                if log:
                    log("warn", f"{label} respondió HTTP {response.status_code}.")
                self._sleep(2.0 * attempt, cancel_event)
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            hrefs: list[str] = []
            for anchor in soup.select(selector):
                href = anchor.get("href") or ""
                if engine == "bing":
                    href = _unwrap_bing_url(str(href))
                elif engine == "duckduckgo":
                    href = decode_ddg_link(str(href))
                if href:
                    hrefs.append(str(href))
                if len(hrefs) >= limit:
                    break
            return hrefs

        if log:
            log("warn", f"No se pudieron leer resultados HTML de {label}.")
        return []

    # ------------------------------------------------------------------
    def _clean(
        self,
        urls: list[str],
        limit: int,
        site_host: str = "",
    ) -> list[str]:
        cleaned: list[str] = []
        seen: set[tuple[str, str, str]] = set()
        for raw in urls:
            url = (raw or "").strip()
            if not url:
                continue
            if url.startswith("//"):
                url = "https:" + url
            if not url.lower().startswith(("http://", "https://")):
                continue
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            host = (parsed.hostname or "").lower()
            if not host or any(host == h or host.endswith("." + h) for h in _SEARCH_HOSTS):
                continue
            # Precisión: si el dork acota con ``site:``, solo se aceptan hosts
            # de ese dominio (o subdominios). Esto descarta el ruido que algunos
            # motores devuelven cuando ignoran el operador.
            if site_host and not (host == site_host or host.endswith("." + site_host)):
                continue
            path = parsed.path
            if path.startswith("/ck/") or path.startswith("/y/"):
                continue
            path_lower = path.lower()
            if not parsed.query and any(path_lower.endswith(ext) for ext in _BINARY_EXT):
                continue
            key = (host, path, parsed.query)
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(url)
            if len(cleaned) >= limit:
                break
        return cleaned

    # ------------------------------------------------------------------
    def _throttle(self, cancel_event: threading.Event | None = None) -> None:
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self.delay
        if wait > 0:
            self._sleep(wait, cancel_event)

    @staticmethod
    def _sleep(seconds: float, cancel_event: threading.Event | None) -> None:
        end = time.monotonic() + max(0.0, seconds)
        while time.monotonic() < end:
            if cancel_event is not None and cancel_event.is_set():
                return
            time.sleep(min(0.2, max(0.0, end - time.monotonic())))


# ==========================================================================
# Triaje pasivo de SQLi + detección de WAF  (de core/sqli_scanner.py)
# ==========================================================================
"""Detección pasiva de errores SQL.

Alcance deliberadamente limitado:

* Una petición GET de línea base y **una** petición GET con una comilla simple
  añadida al primer parámetro auditable.
* Solo se busca la aparición de firmas de error del motor de base de datos.
* No hay payloads de unión, booleanos, temporales ni extracción de datos.

Este módulo no debe ampliarse para explotar la vulnerabilidad. Su función es
generar un indicio que un equipo autorizado pueda confirmar.
"""

import re
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ESTADO_PENDIENTE = "pendiente"
ESTADO_VULN = "posible_vuln"
ESTADO_OK = "ok"
ESTADO_BLOQUEADO = "bloqueado"
ESTADO_ERROR = "error"
ESTADO_OMITIDO = "omitido"

ESTADO_LABELS = {
    ESTADO_PENDIENTE: "Pendiente",
    ESTADO_VULN: "Posible Vuln",
    ESTADO_OK: "Sin hallazgos",
    ESTADO_BLOQUEADO: "Bloqueado",
    ESTADO_ERROR: "Error",
    ESTADO_OMITIDO: "Omitido",
}

# Nivel de confianza del triaje. No es una confirmación de explotabilidad:
# sirve para ordenar la revisión manual de los hallazgos.
CONFIANZA_ALTA = "alta"
CONFIANZA_MEDIA = "media"
CONFIANZA_BAJA = "baja"

CONFIANZA_LABELS = {
    CONFIANZA_ALTA: "Alta",
    CONFIANZA_MEDIA: "Media",
    CONFIANZA_BAJA: "Baja",
}

# Parámetros que podrían provocar efectos secundarios (cerrar sesión, borrar,
# pagar, cambiar contraseñas...). No se tocan.
SKIP_PARAMS = {
    "logout", "signout", "salir", "delete", "remove", "destroy", "reset",
    "unsubscribe", "checkout", "pay", "payment", "purchase", "upload",
    "admin", "login", "signin", "signup", "register", "password", "passwd",
    "pwd", "token", "csrf", "csrf_token", "_token", "authenticity_token",
    "session", "sessionid", "sess", "action", "do", "cmd", "confirm",
}

# Parámetros de analítica/campañas: no suelen llegar a una consulta SQL y
# añaden ruido. Se omiten por completo para no gastar peticiones en ellos.
SKIP_PARAM_PREFIXES = (
    "utm_", "fbclid", "gclid", "dclid", "msclkid", "mc_", "mtm_",
    "pk_", "hsa_", "_ga", "ref_", "vero_", "oly_",
)

# Los nombres clásicamente usados por aplicaciones web se prueban primero.
# El orden es una heurística, no una garantía.
PRIORITY_PARAMS = (
    "id", "cat", "page", "user", "search", "item", "product", "news",
    "article", "file", "view", "lang", "q", "s", "pid", "nid", "tid",
    "cid", "doc", "menu", "mod", "option", "url", "path", "report",
    "download", "album", "gallery", "year", "month", "date", "keyword",
    "query", "idx", "cod", "codigo", "num", "folio", "ref",
)

# Firmas de error. Se comparan en minúsculas para evitar falsos negativos por
# variaciones de mayúsculas.
ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("MySQL", re.compile(r"you have an error in your sql syntax", re.I)),
    ("MySQL", re.compile(r"warning\s*:\s*mysql_", re.I)),
    ("MySQL", re.compile(r"mysql_fetch_(?:array|assoc|row|object|field)\s*\(\s*\)", re.I)),
    ("MySQL", re.compile(r"mysql_num_rows\s*\(\s*\)", re.I)),
    ("MySQL", re.compile(r"supplied argument is not a valid mysql", re.I)),
    ("MySQL", re.compile(r"(?:pdo|mysqli?|mysqlnd)[^\n]{0,80}(?:error|exception)", re.I)),
    ("MariaDB", re.compile(r"mariadb.{0,40}error", re.I | re.S)),
    ("PostgreSQL", re.compile(r"pg_(?:query|exec|prepare)\s*\(\s*\)", re.I)),
    ("PostgreSQL", re.compile(r"postgresql.{0,40}error", re.I | re.S)),
    ("PostgreSQL", re.compile(r"syntax error at or near", re.I)),
    ("PostgreSQL", re.compile(r"unterminated quoted string", re.I)),
    ("PostgreSQL", re.compile(r"psqlexception", re.I)),
    ("MSSQL", re.compile(r"unclosed quotation mark after the character string", re.I)),
    ("MSSQL", re.compile(r"microsoft ole db provider for sql server", re.I)),
    ("MSSQL", re.compile(r"odbc sql server driver", re.I)),
    ("MSSQL", re.compile(r"incorrect syntax near", re.I)),
    ("MSSQL", re.compile(r"system\.data\.sqlclient\.sqlexception", re.I)),
    ("MSSQL", re.compile(r"microsoft sql native client", re.I)),
    ("MSSQL", re.compile(r"sqlserver jdbc driver", re.I)),
    ("Oracle", re.compile(r"ora-0(?:0933|1756|0921|1742|0904|06512|0911|0936)", re.I)),
    ("Oracle", re.compile(r"ora-\d{5}", re.I)),
    ("Oracle", re.compile(r"oracle.{0,30}error", re.I | re.S)),
    ("SQLite", re.compile(r"sqlite3?\.(?:operational|database)error", re.I)),
    ("SQLite", re.compile(r"sqlite.{0,20}error", re.I | re.S)),
    ("SQLite", re.compile(r"sqliteexception", re.I)),
    ("SQLite", re.compile(r"unrecognized token:", re.I)),
    ("DB2", re.compile(r"db2 sql error", re.I)),
    ("DB2", re.compile(r"db2exception", re.I)),
    ("DB2", re.compile(r"cli driver", re.I)),
    ("Informix", re.compile(r"informix", re.I)),
    ("Firebird", re.compile(r"dynamic sql error", re.I)),
    ("Firebird", re.compile(r"firebird", re.I)),
    ("Firebird", re.compile(r"\bisc_\w+", re.I)),
    ("Sybase", re.compile(r"sybase", re.I)),
    ("Sybase", re.compile(r"adaptive server", re.I)),
    ("Sybase", re.compile(r"sql anywhere", re.I)),
    ("Access", re.compile(r"microsoft jet database engine", re.I)),
    ("Access", re.compile(r"odbc microsoft access driver", re.I)),
    ("Access", re.compile(r"syntax error in string in query expression", re.I)),
    ("SQL", re.compile(r"sqlstate\[\w+\]", re.I)),
    ("SQL", re.compile(r"quoted string not properly terminated", re.I)),
    ("SQL", re.compile(r"sql syntax.{0,40}error", re.I | re.S)),
)


class ScanCancelled(Exception):
    """Se lanza cuando el usuario detiene la caza."""


@dataclass
class ScanResult:
    url: str
    domain: str
    parametro: str = ""
    estado: str = ESTADO_PENDIENTE
    evidencia: str = ""
    error_detectado: str = ""
    http_status: int | None = None
    dbms: str = ""
    confianza: str = ""
    mensaje: str = ""
    waf: str = ""


class HostThrottle:
    """Espacia las peticiones por host de forma atómica y segura entre hilos."""

    def __init__(self, delay: float) -> None:
        self.delay = max(0.0, delay)
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str, cancel_event: threading.Event | None = None) -> None:
        with self._lock:
            now = time.monotonic()
            scheduled = self._next.get(host, 0.0)
            wait = max(0.0, scheduled - now)
            self._next[host] = max(now, scheduled) + self.delay
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if cancel_event is not None and cancel_event.is_set():
                raise ScanCancelled()
            time.sleep(min(0.2, max(0.0, end - time.monotonic())))
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled()


class PassiveScanner:
    def __init__(
        self,
        delay: float = SCAN_DELAY_PER_HOST,
        max_params: int = 1,
        timeout: int = HTTP_TIMEOUT,
    ) -> None:
        self.timeout = timeout
        self.max_params = max(1, max_params)
        self.throttle = HostThrottle(delay)
        self._local = threading.local()

    # ------------------------------------------------------------------
    def scan_urls(
        self,
        urls: list[str],
        cancel_event: threading.Event | None = None,
    ) -> list[ScanResult]:
        """API secuencial para escanear una lista.

        El orquestador usa un ``ThreadPoolExecutor`` para paralelizar, pero
        esta función es útil para scripts y pruebas.
        """
        results: list[ScanResult] = []
        for url in urls:
            if cancel_event is not None and cancel_event.is_set():
                break
            results.append(self.scan_url(url, cancel_event))
        return results

    # ------------------------------------------------------------------
    def scan_url(
        self, url: str, cancel_event: threading.Event | None = None
    ) -> ScanResult:
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            return ScanResult(url=url, domain="", estado=ESTADO_ERROR, mensaje=str(exc))

        domain = (parsed.hostname or "").lower()
        if not parsed.query:
            return ScanResult(
                url=url,
                domain=domain,
                estado=ESTADO_OMITIDO,
                mensaje="La URL no tiene parámetros.",
            )

        candidates = _candidate_params(parsed.query)
        if not candidates:
            return ScanResult(
                url=url,
                domain=domain,
                estado=ESTADO_OMITIDO,
                mensaje="No hay parámetros auditables (se omiten login, logout, etc.).",
            )

        param, value = candidates[0]
        injected_url = _replace_param(url, param, f"{value}'")

        baseline_text = ""
        baseline_status: int | None = None
        baseline_engine = ""
        baseline_headers: Any = None
        baseline_failed = False
        try:
            baseline_text, baseline_status, _, baseline_headers = self._fetch(
                url, cancel_event
            )
            baseline_engine, _ = detect_error(baseline_text)
        except ScanCancelled:
            return ScanResult(url=url, domain=domain, estado=ESTADO_OMITIDO, mensaje="Cancelado.")
        except Exception:
            baseline_failed = True

        try:
            body, status, _, injected_headers = self._fetch(injected_url, cancel_event)
        except ScanCancelled:
            return ScanResult(url=url, domain=domain, estado=ESTADO_OMITIDO, mensaje="Cancelado.")
        except Exception as exc:
            return ScanResult(
                url=url,
                domain=domain,
                parametro=param,
                estado=ESTADO_ERROR,
                http_status=baseline_status,
                mensaje=f"Error de conexión: {exc}",
            )

        waf = detect_waf(
            baseline_headers if baseline_headers is not None else injected_headers,
            body,
        )

        engine, match = detect_error(body)
        if engine and engine != baseline_engine:
            evidence = extract_evidence(body, match)
            return ScanResult(
                url=url,
                domain=domain,
                parametro=param,
                estado=ESTADO_VULN,
                evidencia=evidence,
                error_detectado=f"{engine}: {truncate(match.group(0), 140)}" if match else engine,
                http_status=status,
                dbms=engine,
                confianza=_confidence_for(
                    engine, baseline_failed, baseline_status, status
                ),
                mensaje="Firma de error SQL introducida por la comilla.",
                waf=waf,
            )

        if status in (401, 403, 429) or baseline_status in (401, 403, 429):
            blocked_message = (
                f"HTTP {status} (WAF: {waf})"
                if waf
                else f"HTTP {status} (posible WAF o control de acceso)."
            )
            return ScanResult(
                url=url,
                domain=domain,
                parametro=param,
                estado=ESTADO_BLOQUEADO,
                http_status=status,
                mensaje=blocked_message,
                waf=waf,
            )

        if status >= 500:
            return ScanResult(
                url=url,
                domain=domain,
                parametro=param,
                estado=ESTADO_ERROR,
                http_status=status,
                mensaje=f"HTTP {status} sin firma SQL reconocible.",
                waf=waf,
            )

        message = "Sin errores SQL en la respuesta."
        if engine and engine == baseline_engine:
            message = "La firma ya aparecía en la línea base; no se atribuye a la comilla."
        if baseline_failed:
            message = "Línea base no disponible; se comparó solo la respuesta inyectada."
        if waf:
            message += f" WAF detectado: {waf}."
        return ScanResult(
            url=url,
            domain=domain,
            parametro=param,
            estado=ESTADO_OK,
            http_status=status,
            mensaje=message,
            waf=waf,
        )

    # ------------------------------------------------------------------
    def _fetch(
        self, url: str, cancel_event: threading.Event | None = None
    ) -> tuple[str, int, str, Any]:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        self.throttle.wait(host, cancel_event)
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled()

        session = self._session()
        kwargs = {
            "timeout": self.timeout,
            "allow_redirects": True,
            "stream": True,
        }
        try:
            response = session.get(url, verify=True, **kwargs)
        except requests.exceptions.SSLError:
            # Muchos sitios institucionales tienen cadenas incompletas.
            response = session.get(url, verify=False, **kwargs)

        try:
            status = int(response.status_code)
            final_url = response.url
            headers = dict(response.headers)
            encoding = response.encoding or "utf-8"
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=8192):
                if cancel_event is not None and cancel_event.is_set():
                    raise ScanCancelled()
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BODY_BYTES:
                    break
            raw = b"".join(chunks)
        finally:
            response.close()

        try:
            text = raw.decode(encoding, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        return text, status, final_url, headers

    # ------------------------------------------------------------------
    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.max_redirects = MAX_REDIRECTS
            session.headers.update(
                {
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "es-CO,es;q=0.9,en;q=0.8",
                    "Connection": "close",
                }
            )
            retry = Retry(
                total=1,
                connect=1,
                read=1,
                backoff_factor=0.4,
                status_forcelist=(502, 503, 504),
                allowed_methods=frozenset({"GET"}),
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._local.session = session
        return session


# ----------------------------------------------------------------------
# Funciones auxiliares expuestas para pruebas
# ----------------------------------------------------------------------
def detect_error(text: str) -> tuple[str, re.Match[str] | None]:
    if not text:
        return "", None
    sample = text[:MAX_BODY_BYTES]
    for engine, pattern in ERROR_SIGNATURES:
        match = pattern.search(sample)
        if match:
            return engine, match
    return "", None


def detect_waf(headers: Any = None, body: str = "") -> str:
    """Detecta la presencia de un WAF por cabeceras, cookies o cuerpo.

    Es una heurística informativa (triaje), no una certeza: devuelve el
    nombre del WAF probable o cadena vacía.
    """
    lowered: dict[str, str] = {}
    try:
        lowered = {
            str(key).lower(): str(value).lower()
            for key, value in dict(headers or {}).items()
        }
    except Exception:
        lowered = {}
    server = lowered.get("server", "")
    joined = " ".join(lowered.values())
    if "cf-ray" in lowered or "cloudflare" in server:
        return "Cloudflare"
    if "x-amzn-waf-action" in lowered or "awswaf" in joined:
        return "AWS WAF"
    if "x-sucuri-id" in lowered:
        return "Sucuri"
    if "x-iinfo" in lowered or "incapsula" in joined:
        return "Imperva"
    if "akamai" in server or "x-akamai" in lowered:
        return "Akamai"
    if "bigipserver" in joined or "x-f5" in lowered:
        return "F5 BIG-IP"
    if "dotdefender" in joined:
        return "dotDefender"
    if "x-waf-status" in lowered or "x-waf-event" in lowered:
        return "WAF genérico"
    body_l = (body or "")[:MAX_BODY_BYTES].lower()
    if "mod_security" in body_l or "modsecurity" in body_l:
        return "ModSecurity"
    if "wordfence" in body_l and ("blocked" in body_l or "firewall" in body_l):
        return "Wordfence"
    protected = lowered.get("x-protected-by", "").strip()
    if protected:
        return protected.title()
    return ""


def extract_evidence(text: str, match: re.Match[str] | None) -> str:
    if not text or match is None:
        return ""
    start = max(0, match.start() - 220)
    end = min(len(text), match.end() + 320)
    snippet = strip_html(text[start:end])
    snippet = re.sub(r"\s+", " ", snippet).strip()
    snippet = redact_sensitive(snippet)
    return truncate(snippet, MAX_EVIDENCE_CHARS)


def _confidence_for(
    engine: str,
    baseline_failed: bool,
    baseline_status: int | None,
    status: int,
) -> str:
    """Heurística de triaje, no una confirmación de explotabilidad."""
    if engine == "SQL":
        return CONFIANZA_BAJA if baseline_failed else CONFIANZA_MEDIA
    if baseline_failed:
        return CONFIANZA_MEDIA
    if status >= 500:
        return CONFIANZA_MEDIA
    if baseline_status is not None and status != baseline_status:
        return CONFIANZA_MEDIA
    return CONFIANZA_ALTA


def _candidate_params(query: str) -> list[tuple[str, str]]:
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return []
    candidates: list[tuple[str, str]] = []
    for name, value in pairs:
        lowered = name.lower()
        if not name or lowered in SKIP_PARAMS:
            continue
        if lowered.startswith(SKIP_PARAM_PREFIXES):
            continue
        if len(value) > 300:
            continue
        candidates.append((name, value))

    priority = {name: index for index, name in enumerate(PRIORITY_PARAMS)}
    # ``sort`` es estable: los parámetros desconocidos conservan el orden de
    # aparición en la URL.
    candidates.sort(key=lambda item: priority.get(item[0].lower(), len(priority)))
    return candidates


def _replace_param(url: str, name: str, new_value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    output: list[tuple[str, str]] = []
    for key, value in pairs:
        if not replaced and key == name:
            output.append((key, new_value))
            replaced = True
        else:
            output.append((key, value))
    query = urlencode(output, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


# ==========================================================================
# WHOIS + security.txt  (de core/whois_lookup.py)
# ==========================================================================
"""Enriquecimiento de hallazgos: WHOIS + security.txt.

``python-whois`` se usa cuando está instalado, pero la consulta se ejecuta en
un hilo con tiempo límite para que una conexión colgada no bloquee la caza.
Si falla, se usa un cliente WHOIS por socket (RFC 3912) con timeouts explícitos.
"""

import logging
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PRIVACY_MARKERS = (
    "redacted",
    "privacy",
    "withheld",
    "not disclosed",
    "gdpr",
    "data protected",
    "statutory masking",
)

# Prefijos de segundo nivel habituales (edu.co, gob.mx, ac.uk, com.br...).
_SECOND_LEVEL = {
    "com", "edu", "gov", "gob", "mil", "org", "net", "ac", "co", "ne",
    "or", "go", "gub", "salud", "ss", "gob", "nom", "art", "info",
}

_TLDEXTRACT = None
_TLD_LOCK = threading.Lock()


@dataclass
class WhoisInfo:
    domain: str
    organization: str = ""
    emails: list[str] = field(default_factory=list)
    security_contacts: list[str] = field(default_factory=list)
    registrar: str = ""
    country: str = ""
    security_txt_url: str = ""
    source: str = ""

    @property
    def best_contact(self) -> str:
        for contact in self.security_contacts:
            if "@" in contact:
                return contact
        if self.security_contacts:
            return self.security_contacts[0]
        for email in self.emails:
            if "@" in email:
                return email
        return "No disponible"

    @property
    def organization_display(self) -> str:
        return self.organization or "No disponible"


# ----------------------------------------------------------------------
# Dominio raíz
# ----------------------------------------------------------------------
def root_domain(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "//" + raw
    try:
        host = (urlparse(raw).hostname or "").lower().strip(".")
    except ValueError:
        return ""
    if not host:
        return ""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or ":" in host:
        return host
    if host.startswith("www."):
        host = host[4:]

    extracted = _extract_with_tldextract(host)
    if extracted:
        return extracted

    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _extract_with_tldextract(host: str) -> str | None:
    global _TLDEXTRACT
    try:
        import tldextract  # type: ignore
    except Exception:
        return None
    with _TLD_LOCK:
        if _TLDEXTRACT is None:
            try:
                _TLDEXTRACT = tldextract.TLDExtract(suffix_list_urls=())
            except TypeError:  # versiones antiguas
                _TLDEXTRACT = tldextract.TLDExtract()
        try:
            ext = _TLDEXTRACT(host)
        except Exception:
            return None
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


# ----------------------------------------------------------------------
class WhoisLookup:
    def __init__(self, delay: float = WHOIS_DELAY, timeout: int = WHOIS_TIMEOUT) -> None:
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self._cache: dict[str, WhoisInfo] = {}
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    # ------------------------------------------------------------------
    def lookup(
        self, url_or_domain: str, cancel_event: threading.Event | None = None
    ) -> WhoisInfo:
        domain = root_domain(url_or_domain)
        if not domain:
            raise ValueError("No se pudo extraer el dominio raíz.")

        with self._lock:
            cached = self._cache.get(domain)
        if cached is not None:
            return cached

        self._throttle(cancel_event)
        organization, emails, registrar, country, source = self._whois(domain)
        security_url, security_contacts = self._security_txt(domain, cancel_event)

        info = WhoisInfo(
            domain=domain,
            organization=organization,
            emails=emails,
            security_contacts=security_contacts,
            registrar=registrar,
            country=country,
            security_txt_url=security_url,
            source=source,
        )
        with self._lock:
            self._cache[domain] = info
        return info

    # ------------------------------------------------------------------
    def _whois(self, domain: str) -> tuple[str, list[str], str, str, str]:
        try:
            import whois as whois_lib  # type: ignore
        except Exception:
            whois_lib = None

        if whois_lib is not None:
            try:
                data = _run_with_timeout(
                    lambda: whois_lib.whois(domain), self.timeout
                )
                parsed = _parse_python_whois(data)
                if any(parsed):
                    return (*parsed, "python-whois")
            except Exception as exc:
                logger.info("python-whois falló para %s: %s", domain, exc)

        raw = self._raw_whois(domain)
        if raw:
            return (*_parse_raw_whois(raw), "whois-socket")
        return "", [], "", "", ""

    # ------------------------------------------------------------------
    def _raw_whois(self, domain: str) -> str:
        tld = domain.rsplit(".", 1)[-1]
        iana = ""
        try:
            iana = _socket_query("whois.iana.org", tld, self.timeout)
        except OSError:
            pass

        server = ""
        for line in iana.splitlines():
            lowered = line.lower()
            if lowered.startswith(("refer:", "whois:")):
                server = line.split(":", 1)[1].strip()
                break
        if not server:
            server = {
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "co": "whois.nic.co",
                "mx": "whois.mx",
                "ar": "whois.nic.ar",
                "br": "whois.registro.br",
                "cl": "whois.nic.cl",
                "pe": "whois.nic.pe",
                "es": "whois.nic.es",
            }.get(tld, "")

        if not server:
            return ""
        try:
            return _socket_query(server, domain, self.timeout)
        except OSError as exc:
            logger.info("WHOIS socket falló para %s: %s", domain, exc)
            return ""

    # ------------------------------------------------------------------
    def _security_txt(
        self, domain: str, cancel_event: threading.Event | None = None
    ) -> tuple[str, list[str]]:
        candidates = (
            f"https://{domain}/.well-known/security.txt",
            f"https://{domain}/security.txt",
            f"http://{domain}/.well-known/security.txt",
        )
        headers = {"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"}
        for url in candidates:
            if cancel_event is not None and cancel_event.is_set():
                return "", []
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=min(8, self.timeout),
                    allow_redirects=True,
                    verify=False,
                )
            except requests.RequestException:
                continue
            if response.status_code != 200:
                continue
            text = response.text[:20000]
            contacts = _parse_security_txt(text)
            if contacts:
                return url, contacts
        return "", []

    # ------------------------------------------------------------------
    def _throttle(self, cancel_event: threading.Event | None = None) -> None:
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self.delay
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if cancel_event is not None and cancel_event.is_set():
                return
            time.sleep(min(0.2, max(0.0, end - time.monotonic())))


# ----------------------------------------------------------------------
# Parsers
# ----------------------------------------------------------------------
def _parse_security_txt(text: str) -> list[str]:
    contacts: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() != "contact":
            continue
        value = value.strip()
        if value.lower().startswith("mailto:"):
            value = value[7:]
        value = value.split("?")[0].strip(" ,;<>")
        if value and value not in contacts:
            contacts.append(value)
    return contacts


def _parse_python_whois(data) -> tuple[str, list[str], str, str]:
    def get(*keys: str) -> str:
        for key in keys:
            value = None
            try:
                value = data.get(key)  # type: ignore[union-attr]
            except Exception:
                value = getattr(data, key, None)
            if value:
                if isinstance(value, (list, tuple)):
                    value = value[0] if value else ""
                return str(value).strip()
        return ""

    organization = get("org", "organization", "registrant_organization", "name")
    if _is_privacy(organization):
        organization = ""
    emails_raw = []
    try:
        emails_raw = data.get("emails") or []  # type: ignore[union-attr]
    except Exception:
        emails_raw = getattr(data, "emails", []) or []
    if isinstance(emails_raw, str):
        emails_raw = [emails_raw]
    emails = _clean_emails(emails_raw)
    registrar = get("registrar")
    country = get("country", "registrant_country")
    return organization, emails, registrar, country


def _parse_raw_whois(raw: str) -> tuple[str, list[str], str, str]:
    organization = ""
    for key in (
        "Registrant Organization",
        "Registrant Organisation",
        "Organization",
        "Organisation",
        "org",
        "owner",
    ):
        match = re.search(rf"(?im)^\s*{re.escape(key)}\s*:\s*(.+)$", raw)
        if match:
            value = match.group(1).strip()
            if value and not _is_privacy(value):
                organization = value
                break

    emails = _clean_emails(_EMAIL_RE.findall(raw))

    registrar = ""
    match = re.search(r"(?im)^\s*Registrar\s*:\s*(.+)$", raw)
    if match:
        registrar = match.group(1).strip()

    country = ""
    match = re.search(r"(?im)^\s*(?:Registrant )?Country\s*:\s*(.+)$", raw)
    if match:
        country = match.group(1).strip()

    return organization, emails, registrar, country


def _clean_emails(values) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        if not value:
            continue
        email = str(value).strip().lower()
        email = email.replace("mailto:", "").split("?")[0].strip(" ,;<>")
        if "@" not in email or _is_privacy(email):
            continue
        if any(bad in email for bad in ("example.com", "yourdomain", "sentry.io")):
            continue
        if email not in cleaned:
            cleaned.append(email)
    return cleaned


def _is_privacy(value: str) -> bool:
    lowered = (value or "").lower()
    return any(marker in lowered for marker in _PRIVACY_MARKERS)


def _socket_query(server: str, query: str, timeout: int) -> str:
    try:
        encoded = (query + "\r\n").encode("idna")
    except UnicodeError:
        encoded = (query + "\r\n").encode("utf-8", "replace")
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(encoded)
        chunks: list[bytes] = []
        total = 0
        while total < 256 * 1024:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _run_with_timeout(func, timeout: int):
    """Ejecuta ``func`` en un hilo daemon con tiempo límite."""
    result: dict[str, object] = {}

    def target() -> None:
        try:
            result["value"] = func()
        except Exception as exc:  # pragma: no cover - depende de la red
            result["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError("La consulta WHOIS excedió el tiempo límite.")
    if "error" in result:
        raise result["error"]  # type: ignore[misc]
    return result.get("value")


# ==========================================================================
# Fuentes pasivas (Wayback/OTX/crt.sh)  (de core/passive_sources.py)
# ==========================================================================
"""Fuentes pasivas de URLs y subdominios (Wayback, OTX, crt.sh).

Todo lo que hace este módulo son lecturas públicas contra terceros de OSINT
(web.archive.org, otx.alienvault.com, crt.sh). **Nunca** contacta al objetivo:
las URLs que devuelve se incorporan a la caza y solo se prueban si el usuario
lo autoriza en la fase de triaje/verificación.

Cada fuente es tolerante a fallos: si la petición falla, se devuelve una lista
vacía y la caza continúa con el resto de fuentes.
"""

import threading
import time
from typing import Any, Callable

import requests


WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
OTX_URL_LIST = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
)
CRTSH_URL = "https://crt.sh/"

DEFAULT_LIMIT = 150
SOURCE_PAUSE_SECONDS = 1.0  # pausa educada entre fuentes/dominios


# ----------------------------------------------------------------------
# Parsers puros (testeables sin red)
# ----------------------------------------------------------------------
def parse_wayback_cdx(rows: Any) -> list[str]:
    """Extrae URLs de una tabla CDX JSON de Wayback.

    La primera fila es la cabecera (``original``); el resto son valores.
    """
    urls: list[str] = []
    if not isinstance(rows, list) or len(rows) < 2:
        return urls
    header = [str(cell).strip().lower() for cell in rows[0]]
    try:
        index = header.index("original")
    except ValueError:
        return urls
    for row in rows[1:]:
        if isinstance(row, (list, tuple)) and len(row) > index:
            url = str(row[index]).strip()
            if url:
                urls.append(url)
    return urls


def parse_otx(payload: Any) -> list[str]:
    """Extrae URLs de la respuesta ``url_list`` de OTX AlienVault."""
    entries: Any = []
    if isinstance(payload, dict):
        entries = payload.get("url_list") or payload.get("results") or []
    elif isinstance(payload, list):
        entries = payload
    urls: list[str] = []
    for entry in entries or []:
        if isinstance(entry, dict):
            url = str(entry.get("url") or "").strip()
        elif isinstance(entry, str):
            url = entry.strip()
        else:
            continue
        if url:
            urls.append(url)
    return urls


def parse_crtsh(rows: Any) -> list[str]:
    """Extrae subdominios de la salida JSON de crt.sh (name_value)."""
    names: set[str] = set()
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw = row.get("name_value") or ""
        for line in str(raw).splitlines():
            name = line.strip().lower()
            while name.startswith("*."):
                name = name[2:]
            name = name.strip(".").strip()
            if name and "." in name and " " not in name:
                names.add(name)
    return sorted(names)


def filter_param_urls(urls: list[str]) -> list[str]:
    """Deja solo URLs HTTP(S) con cadena de consulta, sin duplicados."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in urls or []:
        url = str(raw or "").strip()
        if not url or url in seen:
            continue
        if not url.lower().startswith(("http://", "https://")):
            continue
        if "?" not in url:
            continue
        seen.add(url)
        result.append(url)
    return result


# ----------------------------------------------------------------------
# Peticiones a las fuentes (tolerantes a fallos)
# ----------------------------------------------------------------------
def _get_json(url: str, params: dict[str, Any], timeout: float) -> Any:
    response = requests.get(
        url,
        params=params,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    response.raise_for_status()
    return response.json()


def fetch_wayback_urls(
    domain: str,
    limit: int = DEFAULT_LIMIT,
    timeout: float = 20.0,
    cancel_event: threading.Event | None = None,
) -> list[str]:
    """URLs archivadas del dominio (incluye subdominios vía comodín)."""
    if not domain:
        return []
    try:
        rows = _get_json(
            WAYBACK_CDX_URL,
            {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "filter": "statuscode:200",
                "limit": str(max(1, int(limit))),
            },
            timeout,
        )
    except Exception:
        return []
    return parse_wayback_cdx(rows)


def fetch_otx_urls(
    domain: str,
    limit: int = DEFAULT_LIMIT,
    timeout: float = 20.0,
    cancel_event: threading.Event | None = None,
) -> list[str]:
    """URLs conocidas por OTX para el dominio (pasivo)."""
    if not domain:
        return []
    try:
        payload = _get_json(
            OTX_URL_LIST.format(domain=domain),
            {"limit": min(100, max(1, int(limit)))},
            timeout,
        )
    except Exception:
        return []
    return parse_otx(payload)


def fetch_crtsh_subdomains(
    domain: str,
    timeout: float = 30.0,
    cancel_event: threading.Event | None = None,
) -> list[str]:
    """Subdominios del dominio vía Certificate Transparency (crt.sh)."""
    if not domain:
        return []
    try:
        rows = _get_json(
            CRTSH_URL,
            {"q": f"%.{domain}", "output": "json"},
            timeout,
        )
    except Exception:
        return []
    return parse_crtsh(rows)


def collect_domain_urls(
    domains: list[str],
    per_domain: int = DEFAULT_LIMIT,
    log: Callable[[str, str], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[str]:
    """Recolecta URLs con parámetros de Wayback + OTX para cada dominio.

    ``log`` recibe ``(nivel, mensaje)`` como el resto del orquestador.
    Devuelve URLs ya filtradas (HTTP(S) con ``?``) y sin duplicados.
    """
    collected: list[str] = []
    for domain in [str(d or "").strip().lower() for d in domains or []]:
        if not domain:
            continue
        if cancel_event is not None and cancel_event.is_set():
            break
        if log is not None:
            log("info", f"Fuentes pasivas para {domain}...")
        wayback = fetch_wayback_urls(domain, per_domain, cancel_event=cancel_event)
        if log is not None:
            log("muted", f"  Wayback CDX: {len(wayback)} URLs")
        if cancel_event is not None and cancel_event.is_set():
            break
        otx = fetch_otx_urls(domain, per_domain, cancel_event=cancel_event)
        if log is not None:
            log("muted", f"  OTX AlienVault: {len(otx)} URLs")
        subs = fetch_crtsh_subdomains(domain, cancel_event=cancel_event)
        if log is not None and subs:
            log("muted", f"  crt.sh: {len(subs)} subdominios (informativo)")
        collected.extend(wayback)
        collected.extend(otx)
        if cancel_event is not None and cancel_event.is_set():
            break
        time.sleep(SOURCE_PAUSE_SECONDS)
    urls = filter_param_urls(collected)
    if log is not None:
        log("ok", f"Fuentes pasivas: {len(urls)} URLs con parámetros listas.")
    return urls


# ==========================================================================
# Fase ACTIVA opcional con SQLMap  (de core/sqlmap_runner.py)
# ==========================================================================
"""Verificación activa con SQLMap (opcional, separada del triaje pasivo).

DorkHunter Pro es pasivo por diseño: una comilla y observación de errores.
Esta fase es un EXTRA explícito que el usuario debe activar. Ejecuta el
binario ``sqlmap`` como subproceso (en un pool de hilos) sobre un conjunto
reducido de URLs, transmite su salida estándar en vivo (eventos
``sqlmap_started``/``sqlmap_line`` por worker) y guarda el veredicto por
hallazgo.

REGLAS:
  • Solo sobre sistemas con autorización escrita y vigente.
  • ``--dbs`` extrae bases de datos: solo si el alcance lo permite.
  • El comando se construye como lista de argumentos (sin shell), de modo
    que la URL no puede inyectar comandos.
  • Si pides proxychains4 y el binario no existe, la fase se aborta: nunca
    se ejecuta "sin proxy" por accidente.
"""

import queue
import re
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


SQLMAP_VULNERABLE = "sqlmap_vulnerable"
SQLMAP_CLEAN = "sqlmap_limpio"
SQLMAP_ERROR = "sqlmap_error"

SQLMAP_LABELS: dict[str, str] = {
    SQLMAP_VULNERABLE: "Vulnerable",
    SQLMAP_CLEAN: "No vulnerable",
    SQLMAP_ERROR: "Error",
}

# Frases con las que SQLMap confirma una inyección en su salida estándar.
_VULN_MARKERS = re.compile(
    r"is vulnerable|is prone to|injection\(s\) found|"
    r"identified the following injection",
    re.IGNORECASE,
)

# Máximo de líneas que se transmiten en vivo por proceso; la salida completa
# siempre se escribe en el archivo de reporte.
MAX_STREAM_LINES = 4000

TARGET_VULNS = "vulns"
TARGET_ALL = "all"
TARGET_AUTO = "auto"  # vulns primero; si no hay, todas las URLs con parámetros

# Presets de intensidad: flags extra que acompañan al comando base.
SQLMAP_PRESET_FLAGS: dict[str, tuple[str, ...]] = {
    "seguro": (),  # Por defecto: batch, sin subir nivel ni riesgo.
    "estandar": ("--level", "2", "--risk", "1"),
    "profundo": ("--level", "3", "--risk", "2"),
}


def preset_extra_flags(name: str) -> tuple[str, ...]:
    """Flags del preset indicado (seguro/estandar/profundo)."""
    key = str(name or "seguro").strip().lower()
    if key == "estándar":
        key = "estandar"
    return SQLMAP_PRESET_FLAGS.get(key, ())


def parse_extra_flags(text: str) -> tuple[str, ...]:
    """Tokeniza flags libres escritos por el usuario con ``shlex.split``.

    Solo se separan tokens; no se ejecuta ningún shell. Los tokens vacíos
    se descartan.
    """
    try:
        tokens = shlex.split(str(text or ""))
    except ValueError:
        tokens = str(text or "").split()
    return tuple(token for token in tokens if token)


@dataclass
class SqlmapConfig:
    """Configuración de la fase de verificación activa."""

    enabled: bool = False
    sqlmap_bin: str = SQLMAP_BIN
    proxychains_bin: str = PROXYCHAINS_BIN
    use_proxychains: bool = False
    random_agent: bool = True
    enumerate_dbs: bool = False
    targets: str = TARGET_AUTO          # "auto" | "vulns" | "all"
    extra_flags: tuple[str, ...] = field(default_factory=tuple)
    timeout: int = SQLMAP_TIMEOUT
    workers: int = SQLMAP_WORKERS        # procesos sqlmap simultáneos
    sqlmap_threads: int = 1              # --threads de sqlmap (por proceso)
    output_dir: Path | None = None

    def __post_init__(self) -> None:
        if int(self.workers) < 1:
            self.workers = 1
        if int(self.workers) > 8:
            self.workers = 8
        if int(self.sqlmap_threads) < 1:
            self.sqlmap_threads = 1
        if int(self.sqlmap_threads) > 16:
            self.sqlmap_threads = 16
        if int(self.timeout) < 30:
            self.timeout = 30
        if self.targets not in {TARGET_VULNS, TARGET_ALL, TARGET_AUTO}:
            self.targets = TARGET_AUTO


def build_sqlmap_command(url: str, config: SqlmapConfig) -> list[str]:
    """Construye el comando como lista de argumentos (sin shell).

    Equivale a ``[proxychains4] sqlmap -u URL --batch --random-agent [--dbs]
    [--threads=N] --output-dir DIR`` más las banderas extra configuradas.
    """
    command: list[str] = []
    if config.use_proxychains and config.proxychains_bin:
        command.append(config.proxychains_bin)
    command.append(config.sqlmap_bin)
    command.extend(["-u", url])
    command.append("--batch")
    if config.random_agent:
        command.append("--random-agent")
    if config.enumerate_dbs:
        command.append("--dbs")
    if int(config.sqlmap_threads) > 1:
        command.append(f"--threads={int(config.sqlmap_threads)}")
    if config.output_dir is not None:
        command.extend(["--output-dir", str(config.output_dir)])
    command.extend(str(flag) for flag in config.extra_flags if str(flag))
    return command


def validate_sqlmap_config(config: SqlmapConfig) -> list[str]:
    """Devuelve los problemas que deben impedir ejecutar SQLMap."""
    problems: list[str] = []
    if not shutil.which(config.sqlmap_bin) and not Path(config.sqlmap_bin).is_file():
        problems.append(
            f"El binario de SQLMap no se encontró: {config.sqlmap_bin}"
        )
    if config.use_proxychains:
        if not config.proxychains_bin:
            problems.append("proxychains está activado pero sin binario configurado.")
        elif not shutil.which(config.proxychains_bin) and not Path(
            config.proxychains_bin
        ).is_file():
            problems.append(
                f"El binario de proxychains no se encontró: {config.proxychains_bin}"
            )
    return problems


class SqlmapRunner:
    """Ejecuta SQLMap en paralelo, transmite su salida y guarda el veredicto."""

    def __init__(
        self,
        config: SqlmapConfig,
        db,
        emit: Callable[[dict[str, Any]], None],
        cancel_event: threading.Event,
    ) -> None:
        self.config = config
        self.db = db
        self.emit = emit
        self.cancel = cancel_event
        self.output_dir = (
            Path(config.output_dir)
            if config.output_dir is not None
            else None
        )

    # ------------------------------------------------------------------
    def run(
        self,
        items: list[dict[str, Any]],
        on_progress: Callable[[int, int], None] | None = None,
    ) -> dict[str, int]:
        """Ejecuta SQLMap sobre ``items`` (dicts con ``finding_id`` y ``url``).

        Devuelve un resumen ``{"sqlmap_vulnerable": n, ...}``. Cada proceso
        recibe un ID de worker (1..N) para que la GUI pueda mostrar N
        consolas en vivo.
        """
        counts = {SQLMAP_VULNERABLE: 0, SQLMAP_CLEAN: 0, SQLMAP_ERROR: 0}
        if not items:
            return counts
        if self.output_dir is not None:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        workers = max(1, int(self.config.workers))
        free_worker_ids: "queue.Queue[int]" = queue.Queue()
        for worker_id in range(1, workers + 1):
            free_worker_ids.put(worker_id)

        def job(item: dict[str, Any]) -> tuple[str, str] | None:
            if self.cancel.is_set():
                return None  # omitido: la caza fue cancelada antes de lanzar
            worker_id = free_worker_ids.get()
            try:
                return self.run_one(item, worker_id)
            finally:
                free_worker_ids.put(worker_id)

        total = len(items)
        done = 0
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="sqlmap"
        ) as pool:
            futures = {pool.submit(job, item): item for item in items}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    outcome = future.result()
                except CancelledError:
                    continue
                except Exception as exc:  # pragma: no cover - salvaguarda
                    outcome = (SQLMAP_ERROR, "")
                    self._log(
                        "error",
                        f"SQLMap falló para {item.get('url')}: {exc}",
                    )
                if outcome is None:
                    continue
                estado, output_path = outcome
                counts[estado] = counts.get(estado, 0) + 1
                self._store(item, estado, output_path)
                done += 1
                if on_progress is not None:
                    on_progress(done, total)
                if self.cancel.is_set():
                    # Los pendientes se cancelan; los en curso llegan a este
                    # mismo bucle cuando run_one corta y los registra.
                    for pending in futures:
                        pending.cancel()
        return counts

    # ------------------------------------------------------------------
    def run_one(self, item: dict[str, Any], worker_id: int = 0) -> tuple[str, str]:
        """Lanza un proceso sqlmap y transmite su salida línea a línea.

        La lectura usa un hilo lector + una cola con timeout, de modo que la
        cancelación funciona incluso cuando el proceso no imprime nada.
        """
        url = str(item.get("url") or "")
        command = build_sqlmap_command(url, self.config)
        self.emit(
            {
                "type": "sqlmap_started",
                "url": url,
                "worker": int(worker_id),
            }
        )
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            self._log("error", f"No se pudo ejecutar {command[0]}: {exc}")
            return SQLMAP_ERROR, ""

        incoming: "queue.Queue[str | None]" = queue.Queue()

        def pump() -> None:
            try:
                assert proc.stdout is not None
                for raw in proc.stdout:
                    incoming.put(raw.rstrip("\r\n"))
            except Exception:  # pragma: no cover - pipe cerrado
                pass
            finally:
                incoming.put(None)  # marcador de fin de flujo

        reader = threading.Thread(
            target=pump, daemon=True, name=f"sqlmap-read-{worker_id}"
        )
        reader.start()

        # Watchdog: si sqlmap se cuelga, el kill libera el hilo de lectura.
        watchdog = threading.Timer(int(self.config.timeout), proc.kill)
        watchdog.daemon = True
        watchdog.start()

        lines: list[str] = []
        try:
            while True:
                try:
                    line = incoming.get(timeout=0.2)
                except queue.Empty:
                    if self.cancel.is_set():
                        proc.terminate()
                        break
                    if not watchdog.is_alive():
                        # El watchdog ejecutó kill: proceso colgado, timeout.
                        break
                    continue
                if line is None:
                    break
                lines.append(line)
                if len(lines) <= MAX_STREAM_LINES:
                    self.emit(
                        {
                            "type": "sqlmap_line",
                            "url": url,
                            "worker": int(worker_id),
                            "line": line,
                        }
                    )
        finally:
            watchdog.cancel()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover - salvaguarda
                proc.kill()
                proc.wait(timeout=15)
            reader.join(timeout=5)

        output = "\n".join(lines)
        output_path = self._dump_output(item, url, output)
        if proc.returncode != 0:
            reason = (
                "agotó el tiempo"
                if proc.returncode is not None and proc.returncode < 0
                else f"terminó con código {proc.returncode}"
            )
            self._log("warn", f"SQLMap {reason} para {url}.")
            return SQLMAP_ERROR, output_path
        if _VULN_MARKERS.search(output):
            return SQLMAP_VULNERABLE, output_path
        return SQLMAP_CLEAN, output_path

    # ------------------------------------------------------------------
    def _dump_output(self, item: dict[str, Any], url: str, text: Any) -> str:
        """Guarda la salida cruda de SQLMap junto al resto de reportes."""
        if self.output_dir is None:
            return ""
        try:
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", url)[:120].strip("_") or "url"
            suffix = str(item.get("finding_id") or "x")
            path = self.output_dir / f"finding_{suffix}_{safe}.txt"
            body = text if isinstance(text, str) else str(text)
            path.write_text(body or "", encoding="utf-8", errors="replace")
            return str(path)
        except OSError:
            return ""

    # ------------------------------------------------------------------
    def _store(self, item: dict[str, Any], estado: str, output_path: str) -> None:
        finding_id = item.get("finding_id")
        url = str(item.get("url") or "")
        if finding_id is not None:
            try:
                self.db.set_finding_sqlmap(int(finding_id), estado, output_path)
            except Exception:  # pragma: no cover - salvaguarda de la GUI
                pass
        self.emit(
            {
                "type": "sqlmap",
                "finding_id": finding_id,
                "url": url,
                "estado": estado,
                "estado_label": SQLMAP_LABELS.get(estado, estado),
                "output": output_path,
            }
        )
        level = "ok" if estado == SQLMAP_VULNERABLE else "muted"
        message = f"SQLMap · {url}: {SQLMAP_LABELS.get(estado, estado)}"
        if estado == SQLMAP_ERROR and output_path:
            message += f" (salida: {output_path})"
        self._log(level, message)

    def _log(self, level: str, message: str) -> None:
        self.emit({"type": "log", "level": level, "message": message})


# ==========================================================================
# Reportes Markdown/HTML/JSON  (de core/report_generator.py)
# ==========================================================================
"""Generación de reportes de divulgación responsable (Markdown, HTML y JSON)."""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any


DISCLAIMER_NOTE = (
    "Este hallazgo fue detectado mediante análisis pasivo de OSINT. "
    "Se recomienda al equipo de TI realizar una prueba de penetración "
    "autorizada para confirmar la vulnerabilidad."
)

RECOMMENDATION = """- Validar y sanear todas las entradas en el servidor (lista blanca de tipos,
  longitudes y formatos). No confiar en validaciones del lado del cliente.
- Usar consultas parametrizadas (prepared statements) o un ORM que las genere.
  Nunca concatenar entrada del usuario en la sentencia SQL.
- Aplicar el principio de mínimo privilegio al usuario de base de datos de la
  aplicación (sin permisos de DDL, sin acceso a otras bases).
- Devolver mensajes de error genéricos al usuario y registrar el detalle en los
  logs internos, sin exponer rutas, versiones ni estructura de tablas.
- Revisar los logs del servidor web y de la base de datos para descartar
  intentos previos sobre el mismo parámetro.
- Considerar un WAF como control compensatorio, nunca como sustituto del
  saneamiento de código."""

IMPACT = """Si la vulnerabilidad se confirma, un atacante podría alterar la lógica de las
consultas SQL y, dependiendo de los privilegios del usuario de base de datos,
leer información sensible, modificar registros o afectar la disponibilidad del
servicio. El impacto real no se evaluó: esta herramienta no extrae datos ni
ejecuta técnicas de explotación."""


class ReportGenerator:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def generate(self, finding: dict[str, Any], fmt: str = "md") -> Path:
        fmt = fmt.lower().lstrip(".")
        if fmt not in {"md", "html", "json"}:
            raise ValueError("Formato no soportado. Usa 'md', 'html' o 'json'.")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        domain = sanitize_filename(finding.get("domain") or "dominio")
        param = sanitize_filename(finding.get("parametro") or "parametro")
        finding_id = sanitize_filename(str(finding.get("id") or "nuevo"))
        path = self.output_dir / (
            f"reporte_{timestamp}_{domain}_{param}_{finding_id}.{fmt}"
        )

        builders = {
            "md": self.build_markdown,
            "html": self.build_html,
            "json": self.build_json,
        }
        path.write_text(builders[fmt](finding), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    def generate_scan(
        self,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
        fmt: str = "md",
    ) -> Path:
        """Genera un reporte agregado de toda una caza."""
        fmt = fmt.lower().lstrip(".")
        if fmt not in {"md", "html", "json"}:
            raise ValueError("Formato no soportado. Usa 'md', 'html' o 'json'.")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        scan_id = sanitize_filename(str(scan.get("id") or "caza"))
        path = self.output_dir / f"reporte_caza_{timestamp}_{scan_id}.{fmt}"
        builders = {
            "md": self.build_scan_markdown,
            "html": self.build_scan_html,
            "json": self.build_scan_json,
        }
        path.write_text(builders[fmt](scan, findings), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    def build_markdown(self, finding: dict[str, Any]) -> str:
        url = str(finding.get("url") or "")
        param = str(finding.get("parametro") or "No identificado")
        evidence = str(finding.get("evidencia") or "").strip()
        if not evidence:
            evidence = "No se capturó evidencia textual. Repetir la prueba de forma autorizada."
        evidence = truncate(evidence, MAX_EVIDENCE_CHARS)
        # Evita que la evidencia cierre el bloque de código del reporte.
        evidence = evidence.replace("```", "'''")

        contact = str(finding.get("contacto") or "No disponible")
        organization = str(finding.get("organizacion") or "No disponible")
        security_txt = str(finding.get("security_txt") or "No encontrado")
        error = str(finding.get("error_detectado") or "Firma de error SQL")
        status = finding.get("http_status") or "N/D"
        dbms = str(finding.get("dbms") or "No determinado")
        confidence = str(finding.get("confianza") or "No determinada")
        waf = str(finding.get("waf") or "No detectado")
        registrar = str(finding.get("registrar") or "No disponible")
        whois_country = str(finding.get("whois_country") or "No disponible")
        enrichment_source = str(finding.get("enrichment_source") or "No disponible")
        found_at = str(finding.get("created_at") or now_iso())

        def cell(value: Any) -> str:
            return str(value).replace("|", "\\|").replace("\n", " ").strip()

        return f"""# [Security Report] Posible SQL Injection en {url}

**Fecha del hallazgo:** {found_at}  
**Herramienta:** {APP_NAME} v{APP_VERSION}  
**Clasificación:** Divulgación responsable — hallazgo no confirmado  
**Estado:** Pendiente de validación por el equipo responsable

---

## 1. Resumen

Durante una revisión pasiva de superficie de exposición se identificó que el
parámetro `{param}` de la URL indicada devuelve un mensaje de error asociado al
motor de base de datos cuando se envía una comilla simple (`'`).

## 2. Tipo de Vulnerabilidad

Tipo de Vulnerabilidad: SQL Injection (Error-Based)

## 3. URL Afectada y Parámetro

| Campo | Valor |
|---|---|
| URL | `{cell(url)}` |
| Parámetro | `{cell(param)}` |
| Método | GET |
| Código HTTP | {cell(status)} |
| Motor de base de datos | {cell(dbms)} |
| WAF detectado | {cell(waf)} |
| Confianza del triaje | {cell(confidence)} |
| Firma detectada | {cell(error)} |

## 4. Evidencia

```text
{evidence}
```

> La evidencia se limita al mensaje de error. No se extrajeron datos, no se
> ejecutaron técnicas de Blind SQLi ni Time-Based y no se intentó explotar la
> vulnerabilidad.

## 5. Impacto Potencial

{IMPACT}

## 6. Contacto Sugerido

| Campo | Valor |
|---|---|
| Organización | {cell(organization)} |
| Registrador | {cell(registrar)} |
| País WHOIS | {cell(whois_country)} |
| Contacto | {cell(contact)} |
| security.txt | {cell(security_txt)} |
| Fuente de enriquecimiento | {cell(enrichment_source)} |

Si el contacto no es válido, se recomienda localizar el canal oficial de
seguridad o el buzón de la oficina de TI/CSIRT del organismo.

## 7. Recomendación

{RECOMMENDATION}

## 8. Aviso

> {DISCLAIMER_NOTE}

---

*Reporte generado automáticamente por {APP_NAME} v{APP_VERSION}. Este documento
no constituye una prueba de penetración ni una confirmación de explotabilidad.*
"""

    # ------------------------------------------------------------------
    def build_json(self, finding: dict[str, Any]) -> str:
        """Representación estructurada para automatización o integración."""
        payload = {
            "tool": APP_NAME,
            "version": APP_VERSION,
            "generated_at": now_iso(),
            "finding": finding,
            "disclaimer": DISCLAIMER_NOTE,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)

    # ------------------------------------------------------------------
    def build_scan_markdown(
        self, scan: dict[str, Any], findings: list[dict[str, Any]]
    ) -> str:
        scan_id = scan.get("id") or "N/D"
        created = str(scan.get("created_at") or now_iso())
        country = str(scan.get("country") or "N/D")
        domain_type = str(scan.get("domain_type") or "N/D")
        keywords = str(scan.get("keywords") or "—")
        dork = str(scan.get("dork_used") or "—")
        status = str(scan.get("status") or "N/D")
        urls_found = scan.get("urls_found") or 0

        counts: dict[str, int] = {}
        for finding in findings:
            state = str(finding.get("estado") or "pendiente")
            counts[state] = counts.get(state, 0) + 1
        vulns = [f for f in findings if f.get("estado") == ESTADO_VULN]

        def cell(value: Any) -> str:
            return str(value).replace("|", "\\|").replace("\n", " ").strip()

        lines: list[str] = [
            f"# [Security Report] Caza #{scan_id} — superficie de exposición",
            "",
            f"**Fecha:** {created}  ",
            f"**Herramienta:** {APP_NAME} v{APP_VERSION}  ",
            "**Clasificación:** Divulgación responsable — hallazgos no confirmados",
            "",
            "---",
            "",
            "## 1. Resumen de la caza",
            "",
            "| Campo | Valor |",
            "|---|---|",
            f"| País | {cell(country)} |",
            f"| Tipo de dominio | {cell(domain_type)} |",
            f"| Palabras clave | {cell(keywords)} |",
            f"| Estado de la caza | {cell(status)} |",
            f"| URLs encontradas | {cell(urls_found)} |",
            f"| Hallazgos registrados | {len(findings)} |",
            f"| Posibles SQLi | {len(vulns)} |",
            "",
            f"**Dorks utilizados:** `{cell(dork)}`",
            "",
            "### Distribución por estado",
            "",
            "| Estado | Cantidad |",
            "|---|---:|",
        ]
        for state, label in ESTADO_LABELS.items():
            if counts.get(state):
                lines.append(f"| {label} | {counts[state]} |")
        if not findings:
            lines.append("| Sin hallazgos | 0 |")
        lines.extend(
            [
                "",
                "## 2. Hallazgos",
                "",
            ]
        )
        if findings:
            lines.extend(
                [
                    "| # | URL | Parámetro | Estado | Motor | WAF | Confianza |",
                    "|---:|---|---|---|---|---|---|",
                ]
            )
            for index, finding in enumerate(findings, start=1):
                lines.append(
                    "| {index} | `{url}` | `{param}` | {state} | {dbms} | {waf} | {confidence} |".format(
                        index=index,
                        url=cell(finding.get("url") or ""),
                        param=cell(finding.get("parametro") or "—"),
                        state=cell(
                            ESTADO_LABELS.get(
                                str(finding.get("estado")), finding.get("estado") or ""
                            )
                        ),
                        dbms=cell(finding.get("dbms") or "—"),
                        waf=cell(finding.get("waf") or "—"),
                        confidence=cell(finding.get("confianza") or "—"),
                    )
                )
        else:
            lines.append("No se registraron hallazgos en esta caza.")

        if vulns:
            lines.extend(["", "## 3. Detalle de posibles vulnerabilidades", ""])
            for index, finding in enumerate(vulns, start=1):
                evidence = str(finding.get("evidencia") or "").strip()
                if not evidence:
                    evidence = "No se capturó evidencia textual."
                evidence = truncate(evidence, MAX_EVIDENCE_CHARS).replace("```", "'''")
                lines.extend(
                    [
                        f"### Hallazgo {index}: `{finding.get('url') or ''}`",
                        "",
                        f"- **Parámetro:** `{finding.get('parametro') or 'No identificado'}`",
                        f"- **Estado:** {ESTADO_LABELS.get(str(finding.get('estado')), finding.get('estado') or '')}",
                        f"- **Motor:** {finding.get('dbms') or 'No determinado'}",
                        f"- **WAF:** {finding.get('waf') or 'No detectado'}",
                        f"- **Confianza:** {finding.get('confianza') or 'No determinada'}",
                        f"- **HTTP:** {finding.get('http_status') or 'N/D'}",
                        f"- **Firma:** {finding.get('error_detectado') or 'No disponible'}",
                        f"- **Contacto:** {finding.get('contacto') or 'No disponible'}",
                        f"- **Organización:** {finding.get('organizacion') or 'No disponible'}",
                        f"- **Registrador:** {finding.get('registrar') or 'No disponible'}",
                        f"- **País WHOIS:** {finding.get('whois_country') or 'No disponible'}",
                        f"- **security.txt:** {finding.get('security_txt') or 'No encontrado'}",
                        f"- **Fuente de enriquecimiento:** {finding.get('enrichment_source') or 'No disponible'}",
                        "",
                        "```text",
                        evidence,
                        "```",
                        "",
                    ]
                )

        lines.extend(
            [
                "## 4. Impacto Potencial",
                "",
                IMPACT,
                "",
                "## 5. Recomendación",
                "",
                RECOMMENDATION,
                "",
                "## 6. Aviso",
                "",
                f"> {DISCLAIMER_NOTE}",
                "",
                "---",
                "",
                f"*Reporte generado automáticamente por {APP_NAME} v{APP_VERSION}. "
                "No constituye una prueba de penetración ni una confirmación de "
                "explotabilidad.*",
                "",
            ]
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def build_scan_html(
        self, scan: dict[str, Any], findings: list[dict[str, Any]]
    ) -> str:
        scan_id = scan.get("id") or "N/D"
        created = str(scan.get("created_at") or now_iso())
        country = str(scan.get("country") or "N/D")
        domain_type = str(scan.get("domain_type") or "N/D")
        keywords = str(scan.get("keywords") or "—")
        dork = str(scan.get("dork_used") or "—")
        status = str(scan.get("status") or "N/D")
        urls_found = scan.get("urls_found") or 0
        counts: dict[str, int] = {}
        for finding in findings:
            state = str(finding.get("estado") or "pendiente")
            counts[state] = counts.get(state, 0) + 1
        vulns = [f for f in findings if f.get("estado") == ESTADO_VULN]

        def esc(value: Any) -> str:
            return html.escape(str(value), quote=True)

        summary_rows = "".join(
            f"<tr><th>{esc(label)}</th><td>{esc(counts[state])}</td></tr>"
            for state, label in ESTADO_LABELS.items()
            if counts.get(state)
        )
        if not summary_rows:
            summary_rows = "<tr><th>Sin hallazgos</th><td>0</td></tr>"

        finding_rows = ""
        for index, finding in enumerate(findings, start=1):
            finding_rows += (
                "<tr>"
                f"<td>{index}</td>"
                f"<td><code>{esc(finding.get('url') or '')}</code></td>"
                f"<td><code>{esc(finding.get('parametro') or '—')}</code></td>"
                f"<td>{esc(ESTADO_LABELS.get(str(finding.get('estado')), finding.get('estado') or ''))}</td>"
                f"<td>{esc(finding.get('dbms') or '—')}</td>"
                f"<td>{esc(finding.get('waf') or '—')}</td>"
                f"<td>{esc(finding.get('confianza') or '—')}</td>"
                "</tr>"
            )
        if not finding_rows:
            finding_rows = '<tr><td colspan="7">No se registraron hallazgos.</td></tr>'

        detail_blocks = ""
        for index, finding in enumerate(vulns, start=1):
            evidence = str(finding.get("evidencia") or "").strip()
            if not evidence:
                evidence = "No se capturó evidencia textual."
            evidence = truncate(evidence, MAX_EVIDENCE_CHARS)
            detail_blocks += f"""
      <h3>Hallazgo {index}: <code>{esc(finding.get('url') or '')}</code></h3>
      <table>
        <tr><th>Parámetro</th><td><code>{esc(finding.get('parametro') or 'No identificado')}</code></td></tr>
        <tr><th>Estado</th><td>{esc(ESTADO_LABELS.get(str(finding.get('estado')), finding.get('estado') or ''))}</td></tr>
        <tr><th>Motor</th><td>{esc(finding.get('dbms') or 'No determinado')}</td></tr>
        <tr><th>WAF</th><td>{esc(finding.get('waf') or 'No detectado')}</td></tr>
        <tr><th>Confianza</th><td>{esc(finding.get('confianza') or 'No determinada')}</td></tr>
        <tr><th>HTTP</th><td>{esc(finding.get('http_status') or 'N/D')}</td></tr>
        <tr><th>Firma</th><td>{esc(finding.get('error_detectado') or 'No disponible')}</td></tr>
        <tr><th>Contacto</th><td>{esc(finding.get('contacto') or 'No disponible')}</td></tr>
        <tr><th>Organización</th><td>{esc(finding.get('organizacion') or 'No disponible')}</td></tr>
        <tr><th>Registrador</th><td>{esc(finding.get('registrar') or 'No disponible')}</td></tr>
        <tr><th>País WHOIS</th><td>{esc(finding.get('whois_country') or 'No disponible')}</td></tr>
        <tr><th>security.txt</th><td>{esc(finding.get('security_txt') or 'No encontrado')}</td></tr>
        <tr><th>Fuente de enriquecimiento</th><td>{esc(finding.get('enrichment_source') or 'No disponible')}</td></tr>
      </table>
      <pre>{esc(evidence)}</pre>
"""
        if not detail_blocks:
            detail_blocks = "<p>No se identificaron posibles vulnerabilidades.</p>"

        css = """
        :root { color-scheme: dark; }
        * { box-sizing: border-box; }
        body { margin: 0; padding: 40px 20px; background: #0d1117; color: #e6edf3;
               font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
               line-height: 1.65; }
        main { max-width: 1100px; margin: 0 auto; }
        .card { background: #151b23; border: 1px solid #26303d; border-radius: 14px;
                padding: 36px 40px; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 999px;
                 background: #3b1d1d; color: #f87171; font-size: 12px; font-weight: 700;
                 letter-spacing: .04em; text-transform: uppercase; }
        h1 { font-size: 26px; line-height: 1.3; margin: 18px 0 8px; }
        h2 { font-size: 17px; margin: 34px 0 10px; padding-bottom: 6px;
             border-bottom: 1px solid #26303d; color: #22d3ee; }
        h3 { font-size: 14px; margin: 24px 0 8px; color: #fca5a5; }
        .meta { color: #8b98a9; font-size: 13px; }
        .meta strong { color: #e6edf3; }
        table { width: 100%; border-collapse: collapse; margin: 12px 0; }
        th, td { text-align: left; padding: 9px 12px; font-size: 14px;
                 border-bottom: 1px solid #26303d; vertical-align: top; }
        th { color: #8b98a9; font-weight: 600; width: 190px; }
        td:first-child { width: auto; }
        code, pre { font-family: "SFMono-Regular", Consolas, monospace; }
        code { color: #7dd3fc; word-break: break-all; }
        pre { background: #0b0f14; border: 1px solid #26303d; border-radius: 10px;
              padding: 16px; overflow-x: auto; white-space: pre-wrap;
              word-break: break-word; color: #fca5a5; font-size: 13px; }
        .note { background: #1c222b; border-left: 4px solid #fbbf24;
                padding: 14px 18px; border-radius: 8px; color: #d6dee8;
                font-size: 14px; margin: 18px 0; }
        ul { padding-left: 22px; }
        li { margin: 6px 0; }
        footer { color: #8b98a9; font-size: 12px; margin-top: 28px; }
        """
        body = f"""
<main>
  <div class="card">
    <span class="badge">Hallazgos no confirmados</span>
    <h1>[Security Report] Caza #{esc(scan_id)} — superficie de exposición</h1>
    <p class="meta">
      <strong>Fecha:</strong> {esc(created)}<br>
      <strong>Herramienta:</strong> {esc(APP_NAME)} v{esc(APP_VERSION)}<br>
      <strong>Clasificación:</strong> Divulgación responsable — pendiente de validación
    </p>

    <h2>1. Resumen de la caza</h2>
    <table>
      <tr><th>País</th><td>{esc(country)}</td></tr>
      <tr><th>Tipo de dominio</th><td>{esc(domain_type)}</td></tr>
      <tr><th>Palabras clave</th><td>{esc(keywords)}</td></tr>
      <tr><th>Estado de la caza</th><td>{esc(status)}</td></tr>
      <tr><th>URLs encontradas</th><td>{esc(urls_found)}</td></tr>
      <tr><th>Hallazgos registrados</th><td>{len(findings)}</td></tr>
      <tr><th>Posibles SQLi</th><td>{len(vulns)}</td></tr>
      <tr><th>Dorks</th><td><code>{esc(dork)}</code></td></tr>
    </table>
    <h3>Distribución por estado</h3>
    <table>{summary_rows}</table>

    <h2>2. Hallazgos</h2>
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Parámetro</th><th>Estado</th><th>Motor</th><th>WAF</th><th>Confianza</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>

    <h2>3. Detalle de posibles vulnerabilidades</h2>
    {detail_blocks}

    <h2>4. Impacto Potencial</h2>
    <p>{esc(IMPACT)}</p>

    <h2>5. Recomendación</h2>
    <ul>
      <li>Validar y sanear todas las entradas en el servidor (lista blanca de
      tipos, longitudes y formatos). No confiar en validaciones del cliente.</li>
      <li>Usar consultas parametrizadas (<em>prepared statements</em>) o un ORM
      que las genere. Nunca concatenar entrada del usuario en la sentencia SQL.</li>
      <li>Aplicar mínimo privilegio al usuario de base de datos de la aplicación
      (sin DDL, sin acceso a otras bases).</li>
      <li>Devolver mensajes de error genéricos y registrar el detalle en logs
      internos, sin exponer rutas, versiones ni estructura de tablas.</li>
      <li>Revisar los logs del servidor web y de la base de datos para descartar
      intentos previos sobre el mismo parámetro.</li>
      <li>Considerar un WAF como control compensatorio, nunca como sustituto del
      saneamiento de código.</li>
    </ul>

    <h2>6. Aviso</h2>
    <div class="note">{esc(DISCLAIMER_NOTE)}</div>

    <footer>
      Reporte generado automáticamente por {esc(APP_NAME)} v{esc(APP_VERSION)}.
      Este documento no constituye una prueba de penetración ni una confirmación
      de explotabilidad.
    </footer>
  </div>
</main>
"""
        return (
            "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>[Security Report] Caza #{esc(scan_id)}</title>\n"
            f"<style>{css}</style>\n</head>\n<body>{body}</body>\n</html>\n"
        )

    # ------------------------------------------------------------------
    def build_scan_json(
        self, scan: dict[str, Any], findings: list[dict[str, Any]]
    ) -> str:
        scan_payload = dict(scan)
        raw_duplicates = scan_payload.pop("duplicadas_json", None)
        duplicates: list[dict[str, Any]] = []
        if raw_duplicates:
            try:
                parsed = json.loads(str(raw_duplicates))
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, list):
                duplicates = parsed
        payload = {
            "tool": APP_NAME,
            "version": APP_VERSION,
            "generated_at": now_iso(),
            "scan": scan_payload,
            "duplicates": duplicates,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "posibles_vuln": sum(
                    1 for f in findings if f.get("estado") == ESTADO_VULN
                ),
                "duplicadas": int(scan.get("duplicadas") or 0),
            },
            "disclaimer": DISCLAIMER_NOTE,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)

    # ------------------------------------------------------------------
    def build_html(self, finding: dict[str, Any]) -> str:
        url = str(finding.get("url") or "")
        param = str(finding.get("parametro") or "No identificado")
        evidence = str(finding.get("evidencia") or "").strip()
        if not evidence:
            evidence = "No se capturó evidencia textual. Repetir la prueba de forma autorizada."
        evidence = truncate(evidence, MAX_EVIDENCE_CHARS)

        contact = str(finding.get("contacto") or "No disponible")
        organization = str(finding.get("organizacion") or "No disponible")
        security_txt = str(finding.get("security_txt") or "No encontrado")
        error = str(finding.get("error_detectado") or "Firma de error SQL")
        status = finding.get("http_status") or "N/D"
        dbms = str(finding.get("dbms") or "No determinado")
        confidence = str(finding.get("confianza") or "No determinada")
        waf = str(finding.get("waf") or "No detectado")
        registrar = str(finding.get("registrar") or "No disponible")
        whois_country = str(finding.get("whois_country") or "No disponible")
        enrichment_source = str(finding.get("enrichment_source") or "No disponible")
        found_at = str(finding.get("created_at") or now_iso())

        def esc(value: Any) -> str:
            return html.escape(str(value), quote=True)

        css = """
        :root { color-scheme: dark; }
        * { box-sizing: border-box; }
        body {
            margin: 0; padding: 40px 20px;
            background: #0d1117; color: #e6edf3;
            font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.65;
        }
        main { max-width: 900px; margin: 0 auto; }
        .card {
            background: #151b23; border: 1px solid #26303d;
            border-radius: 14px; padding: 36px 40px;
        }
        .badge {
            display: inline-block; padding: 4px 12px; border-radius: 999px;
            background: #3b1d1d; color: #f87171; font-size: 12px;
            font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
        }
        h1 { font-size: 26px; line-height: 1.3; margin: 18px 0 8px; }
        h2 {
            font-size: 17px; margin: 34px 0 10px; padding-bottom: 6px;
            border-bottom: 1px solid #26303d; color: #22d3ee;
        }
        .meta { color: #8b98a9; font-size: 13px; }
        .meta strong { color: #e6edf3; }
        table { width: 100%; border-collapse: collapse; margin: 12px 0; }
        th, td {
            text-align: left; padding: 9px 12px; font-size: 14px;
            border-bottom: 1px solid #26303d; vertical-align: top;
        }
        th { color: #8b98a9; font-weight: 600; width: 190px; }
        code, pre { font-family: "SFMono-Regular", Consolas, monospace; }
        code { color: #7dd3fc; word-break: break-all; }
        pre {
            background: #0b0f14; border: 1px solid #26303d; border-radius: 10px;
            padding: 16px; overflow-x: auto; white-space: pre-wrap;
            word-break: break-word; color: #fca5a5; font-size: 13px;
        }
        .note {
            background: #1c222b; border-left: 4px solid #fbbf24;
            padding: 14px 18px; border-radius: 8px; color: #d6dee8;
            font-size: 14px; margin: 18px 0;
        }
        ul { padding-left: 22px; }
        li { margin: 6px 0; }
        footer { color: #8b98a9; font-size: 12px; margin-top: 28px; }
        a { color: #22d3ee; }
        """

        body = f"""
<main>
  <div class="card">
    <span class="badge">Hallazgo no confirmado</span>
    <h1>[Security Report] Posible SQL Injection en {esc(url)}</h1>
    <p class="meta">
      <strong>Fecha del hallazgo:</strong> {esc(found_at)}<br>
      <strong>Herramienta:</strong> {esc(APP_NAME)} v{esc(APP_VERSION)}<br>
      <strong>Clasificación:</strong> Divulgación responsable — pendiente de validación
    </p>

    <h2>1. Resumen</h2>
    <p>Durante una revisión pasiva de superficie de exposición se identificó que
    el parámetro <code>{esc(param)}</code> devuelve un mensaje de error asociado
    al motor de base de datos cuando se envía una comilla simple
    (<code>'</code>).</p>

    <h2>2. Tipo de Vulnerabilidad</h2>
    <p>Tipo de Vulnerabilidad: SQL Injection (Error-Based)</p>

    <h2>3. URL Afectada y Parámetro</h2>
    <table>
      <tr><th>URL</th><td><code>{esc(url)}</code></td></tr>
      <tr><th>Parámetro</th><td><code>{esc(param)}</code></td></tr>
      <tr><th>Método</th><td>GET</td></tr>
      <tr><th>Código HTTP</th><td>{esc(status)}</td></tr>
      <tr><th>Motor de base de datos</th><td>{esc(dbms)}</td></tr>
      <tr><th>WAF detectado</th><td>{esc(waf)}</td></tr>
      <tr><th>Confianza del triaje</th><td>{esc(confidence)}</td></tr>
      <tr><th>Firma detectada</th><td>{esc(error)}</td></tr>
    </table>

    <h2>4. Evidencia</h2>
    <pre>{esc(evidence)}</pre>
    <div class="note">
      La evidencia se limita al mensaje de error. No se extrajeron datos, no se
      ejecutaron técnicas de Blind SQLi ni Time-Based y no se intentó explotar
      la vulnerabilidad.
    </div>

    <h2>5. Impacto Potencial</h2>
    <p>{esc(IMPACT)}</p>

    <h2>6. Contacto Sugerido</h2>
    <table>
      <tr><th>Organización</th><td>{esc(organization)}</td></tr>
      <tr><th>Registrador</th><td>{esc(registrar)}</td></tr>
      <tr><th>País WHOIS</th><td>{esc(whois_country)}</td></tr>
      <tr><th>Contacto</th><td>{esc(contact)}</td></tr>
      <tr><th>security.txt</th><td>{esc(security_txt)}</td></tr>
      <tr><th>Fuente de enriquecimiento</th><td>{esc(enrichment_source)}</td></tr>
    </table>
    <p>Si el contacto no es válido, se recomienda localizar el canal oficial de
    seguridad o el buzón de la oficina de TI/CSIRT del organismo.</p>

    <h2>7. Recomendación</h2>
    <ul>
      <li>Validar y sanear todas las entradas en el servidor (lista blanca de
      tipos, longitudes y formatos). No confiar en validaciones del cliente.</li>
      <li>Usar consultas parametrizadas (<em>prepared statements</em>) o un ORM
      que las genere. Nunca concatenar entrada del usuario en la sentencia SQL.</li>
      <li>Aplicar mínimo privilegio al usuario de base de datos de la aplicación
      (sin DDL, sin acceso a otras bases).</li>
      <li>Devolver mensajes de error genéricos y registrar el detalle en logs
      internos, sin exponer rutas, versiones ni estructura de tablas.</li>
      <li>Revisar los logs del servidor web y de la base de datos para descartar
      intentos previos sobre el mismo parámetro.</li>
      <li>Considerar un WAF como control compensatorio, nunca como sustituto del
      saneamiento de código.</li>
    </ul>

    <h2>8. Aviso</h2>
    <div class="note">{esc(DISCLAIMER_NOTE)}</div>

    <footer>
      Reporte generado automáticamente por {esc(APP_NAME)} v{esc(APP_VERSION)}.
      Este documento no constituye una prueba de penetración ni una confirmación
      de explotabilidad.
    </footer>
  </div>
</main>
"""
        return (
            "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>[Security Report] Posible SQL Injection en {esc(url)}</title>\n"
            f"<style>{css}</style>\n</head>\n<body>{body}</body>\n</html>\n"
        )


# ==========================================================================
# Orquestador de la caza  (de core/orchestrator.py)
# ==========================================================================
"""Orquestador de una caza: dorks → búsqueda → escaneo → enriquecimiento.

Se ejecuta en un hilo de trabajo y comunica todo a la GUI mediante una
``queue.Queue``. Ningún widget se toca desde aquí.
"""

import logging
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


@dataclass
class HuntParams:
    country: str
    domain_type: str
    keywords: str = ""
    manual_dork: str = ""
    max_results: int = 25
    do_scan: bool = True
    do_enrich: bool = True
    dorks: list[Dork] | None = field(default=None)
    target_urls: list[str] = field(default_factory=list)
    max_urls: int = MAX_URLS_PER_HUNT
    engines: list[str] | None = None
    rotate: bool = False
    # Alcance opcional por dominio: allowlist/denylist de hostnames.
    allow_domains: list[str] = field(default_factory=list)
    deny_domains: list[str] = field(default_factory=list)
    # Fase ACTIVA opcional: None ⇒ desactivada. Solo con autorización escrita.
    sqlmap: SqlmapConfig | None = None


class HuntOrchestrator:
    def __init__(
        self,
        db,
        events: queue.Queue,
        cancel_event: threading.Event,
        params: HuntParams,
    ) -> None:
        self.db = db
        self.events = events
        self.cancel = cancel_event
        self.params = params

        self.engine = DorkEngine()
        self.search = SearchEngine(max_results=params.max_results)
        self.engines = list(params.engines or SEARCH_ENGINES)
        self.rotate = bool(params.rotate)
        self.scanner = PassiveScanner()
        self.whois = WhoisLookup()

        self.scan_id: int | None = None
        self._dorks: list[Dork] = list(params.dorks or [])
        self._urls: list[str] = []
        self._seen: set[str] = set()
        self.url_sources: dict[str, list[str]] = {}
        self._sources_lock = threading.Lock()
        self._counts = {"urls": 0, "vulns": 0}
        self._status = "completado"
        self.sqlmap = params.sqlmap if (
            params.sqlmap and params.sqlmap.enabled
        ) else None
        self._sqlmap_counts: dict[str, int] | None = None

    # ------------------------------------------------------------------
    def run(self) -> None:
        started = time.monotonic()
        try:
            self._execute()
        except Exception as exc:  # pragma: no cover - salvaguarda de la GUI
            logger.exception("Fallo no controlado durante la caza")
            self._status = "error"
            self._log("error", f"Error inesperado: {exc}")
            self._emit({"type": "error", "message": str(exc)})
        finally:
            duplicates = self.duplicates()
            if self.scan_id is not None:
                try:
                    self.db.save_scan_duplicates(self.scan_id, duplicates)
                except Exception:  # pragma: no cover - salvaguarda de la GUI
                    logger.exception("No se pudieron guardar las URLs duplicadas")
                self.db.finish_scan(self.scan_id, self._status, len(self._urls))
            self._emit(
                {
                    "type": "done",
                    "summary": {
                        "scan_id": self.scan_id,
                        "urls": len(self._urls),
                        "vulns": self._counts["vulns"],
                        "duplicates": len(duplicates),
                        "cancelled": self.cancel.is_set(),
                        "elapsed": round(time.monotonic() - started, 1),
                        "status": self._status,
                        "sqlmap": dict(self._sqlmap_counts)
                        if self._sqlmap_counts
                        else None,
                    },
                }
            )

    # ------------------------------------------------------------------
    def _execute(self) -> None:
        manual_targets = normalize_target_urls(self.params.target_urls)
        if self.params.target_urls and not manual_targets:
            raise ValueError(
                "Ninguna URL manual es válida. Usa http(s):// y al menos un parámetro."
            )
        if manual_targets:
            in_scope: list[str] = []
            skipped_scope = 0
            for url in manual_targets:
                try:
                    host = (urlparse(url).hostname or "").lower()
                except ValueError:
                    skipped_scope += 1
                    continue
                if domain_allowed(
                    host, self.params.allow_domains, self.params.deny_domains
                ):
                    in_scope.append(url)
                else:
                    skipped_scope += 1
            if skipped_scope:
                self._log(
                    "warn",
                    f"Se excluyeron {skipped_scope} URLs por la lista de dominios "
                    "(allowlist/denylist).",
                )
            if not in_scope and manual_targets:
                raise ValueError(
                    "Todas las URLs manuales quedaron fuera del alcance definido "
                    "por la lista de dominios."
                )
            manual_targets = in_scope
            limit = max(1, int(self.params.max_urls))
            self._urls = manual_targets[:limit]
            self._seen = set(self._urls)
            self._log("info", "Objetivo manual: URL directa")
            self._log("info", f"URLs manuales válidas: {len(self._urls)}")
            for url in self._urls:
                self._record_url_source(url, "URL manual")
                self._emit({"type": "candidate", "url": url})
            dork_used = "URL manual: " + " | ".join(self._urls)
        else:
            if not self._dorks:
                self._dorks = self.engine.build(
                    self.params.country,
                    self.params.domain_type,
                    self.params.keywords,
                    self.params.manual_dork,
                )
            if not self._dorks:
                raise ValueError("No se pudo generar ningún dork con los filtros dados.")

            self._log(
                "info", f"Objetivo: {self.params.country} / {self.params.domain_type}"
            )
            self._log("info", f"Dorks generados: {len(self._dorks)}")
            for dork in self._dorks:
                self._log("muted", f"  · {dork.query}")
            dork_used = " | ".join(d.query for d in self._dorks)

        self.scan_id = self.db.create_scan(
            dork_used=dork_used,
            country=self.params.country,
            domain_type=self.params.domain_type,
            keywords=self.params.keywords,
        )
        self._emit({"type": "scan_started", "scan_id": self.scan_id})

        if manual_targets:
            self._progress(0.25, "URLs manuales listas")
        else:
            self._search_phase()
        if self.cancel.is_set():
            self._status = "cancelado"
            return

        self._scan_phase()
        if self.cancel.is_set():
            self._status = "cancelado"
            return

        self._enrich_phase()
        if self.cancel.is_set():
            self._status = "cancelado"
            return

        self._sqlmap_phase()
        if self.cancel.is_set():
            self._status = "cancelado"
            return

        self._progress(1.0, "Completado")
        self._log(
            "ok",
            f"Caza finalizada: {len(self._urls)} URLs, "
            f"{self._counts['vulns']} posibles vulnerabilidades.",
        )

    # ------------------------------------------------------------------
    def _search_phase(self) -> None:
        scope = self._dorks[0].scope_suffix if self._dorks else ""
        if not scope:
            self._log(
                "warn",
                "El dork no incluye site:; el alcance no está acotado a un dominio.",
            )

        total = len(self._dorks)
        limit = max(1, int(self.params.max_urls))
        skipped_no_params = 0
        skipped_scope = 0
        self._log(
            "info",
            "Motores: " + ", ".join(self.engines or SEARCH_ENGINES),
        )
        if self.rotate and len(self.engines) > 1:
            self._log(
                "info",
                "Rotación de motores activada: cada dork prioriza un motor distinto.",
            )
        for index, dork in enumerate(self._dorks):
            if self.cancel.is_set():
                return
            if len(self._urls) >= limit:
                break

            order = (
                rotation_order(self.engines, index)
                if self.rotate
                else self.engines
            )
            if self.rotate and len(order) > 1:
                self._log("muted", f"  Motor principal: {order[0]}")
            self._log("info", f"Buscando [{index + 1}/{total}]: {dork.query}")
            try:
                found = self.search.search(
                    dork.query,
                    self.params.max_results,
                    self.cancel,
                    log=self._log,
                    engines=order,
                )
            except Exception as exc:
                self._log("warn", f"La búsqueda falló: {exc}")
                continue

            new = 0
            for url in found:
                if self.cancel.is_set():
                    return
                if scope and not _host_in_scope(url, scope):
                    continue
                # Filtro opcional de alcance por dominios (denylist gana).
                host = (urlparse(url).hostname or "").lower()
                if not domain_allowed(
                    host, self.params.allow_domains, self.params.deny_domains
                ):
                    skipped_scope += 1
                    continue
                # Solo tiene sentido escanear URLs con cadena de consulta.
                if not urlparse(url).query:
                    skipped_no_params += 1
                    continue
                self._record_url_source(url, dork.query)
                if url in self._seen:
                    continue
                self._seen.add(url)
                self._urls.append(url)
                new += 1
                self._emit({"type": "candidate", "url": url})
                if len(self._urls) >= limit:
                    break

            self._log(
                "ok" if new else "warn",
                f"  {new} URLs nuevas · total {len(self._urls)}",
            )
            self._progress(
                0.25 * (index + 1) / total,
                f"Buscando candidatos ({index + 1}/{total})",
            )

        if skipped_no_params:
            self._log(
                "muted",
                f"Se descartaron {skipped_no_params} resultados sin parámetros.",
            )
        if skipped_scope:
            self._log(
                "muted",
                f"Se descartaron {skipped_scope} resultados por la lista de "
                "dominios (allowlist/denylist).",
            )
        if len(self._urls) >= limit:
            self._log(
                "warn",
                f"Se alcanzó el límite de {limit} URLs por caza.",
            )
        duplicates = self.duplicates()
        if duplicates:
            self._log(
                "info",
                f"URLs repetidas en varios dorks: {len(duplicates)} "
                "(revisables con el botón Duplicadas).",
            )

    # ------------------------------------------------------------------
    def _record_url_source(self, url: str, source: str) -> None:
        """Registra de qué dork salió cada URL (para duplicados)."""
        with self._sources_lock:
            sources = self.url_sources.setdefault(url, [])
            if source not in sources:
                sources.append(source)

    def duplicates(self) -> list[dict[str, Any]]:
        """URLs encontradas por más de un dork, ordenadas por repeticiones."""
        with self._sources_lock:
            items = [
                {"url": url, "count": len(sources), "sources": list(sources)}
                for url, sources in self.url_sources.items()
                if len(sources) > 1
            ]
        items.sort(key=lambda item: (-int(item["count"]), str(item["url"])))
        return items

    # ------------------------------------------------------------------
    def _scan_phase(self) -> None:
        if not self.params.do_scan:
            self._log("warn", "Modo recolección: no se enviarán peticiones de escaneo.")
            self._progress(0.80, "Recolección completada")
            return
        if not self._urls:
            self._log("warn", "No hay URLs para escanear.")
            return

        total = len(self._urls)
        self._log(
            "info",
            f"Escaneo pasivo de {total} URLs (una comilla por URL, GET)...",
        )
        done = 0
        pool = ThreadPoolExecutor(max_workers=SCAN_WORKERS, thread_name_prefix="scan")
        try:
            futures = {
                pool.submit(self.scanner.scan_url, url, self.cancel): url
                for url in self._urls
            }
            for future in as_completed(futures):
                url = futures[future]
                if self.cancel.is_set():
                    for pending in futures:
                        pending.cancel()
                    break
                try:
                    result = future.result()
                except Exception as exc:
                    result = ScanResult(
                        url=url,
                        domain=(urlparse(url).hostname or ""),
                        estado=ESTADO_ERROR,
                        mensaje=str(exc),
                    )
                self._store_result(result)
                done += 1
                self._progress(
                    0.25 + 0.40 * (done / total),
                    f"Escaneando ({done}/{total})",
                )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    def _store_result(self, result: ScanResult) -> None:
        assert self.scan_id is not None
        finding_id = self.db.add_finding(
            self.scan_id,
            result.url,
            domain=result.domain,
            parametro=result.parametro,
            estado=result.estado,
            error_detectado=result.error_detectado,
            evidencia=result.evidencia,
            http_status=result.http_status,
            dbms=result.dbms,
            confianza=result.confianza,
            waf=result.waf,
        )
        finding = self.db.get_finding(finding_id)
        if finding is None:
            return
        self._emit({"type": "result", "finding": finding})

        if result.estado == ESTADO_VULN:
            self._counts["vulns"] += 1
            details = f"parámetro: {result.parametro}"
            if result.dbms:
                details += f" · motor: {result.dbms}"
            if result.confianza:
                details += f" · confianza: {result.confianza}"
            if result.waf:
                details += f" · WAF: {result.waf}"
            self._log("warn", f"Posible SQLi: {result.url} [{details}]")
        elif result.estado == ESTADO_ERROR and result.mensaje:
            self._log("muted", f"Error al probar {result.url}: {result.mensaje}")

    # ------------------------------------------------------------------
    def _enrich_phase(self) -> None:
        if not self.params.do_enrich:
            self._log("info", "Enriquecimiento WHOIS/security.txt desactivado.")
            self._progress(1.0, "Completado")
            return

        assert self.scan_id is not None
        findings = [
            f
            for f in self.db.list_findings(self.scan_id)
            if f.get("estado") == ESTADO_VULN
        ]
        if not findings:
            self._log("info", "No hay hallazgos que enriquecer.")
            self._progress(1.0, "Completado")
            return

        self._log(
            "info",
            f"Consultando WHOIS y security.txt para {len(findings)} hallazgo(s)...",
        )
        for index, finding in enumerate(findings):
            if self.cancel.is_set():
                return
            try:
                info = self.whois.lookup(finding["url"], self.cancel)
            except Exception as exc:
                self._log(
                    "warn",
                    f"WHOIS falló para {finding.get('domain') or finding['url']}: {exc}",
                )
                continue

            self.db.update_finding(
                finding["id"],
                contacto=info.best_contact,
                organizacion=info.organization_display,
                registrar=info.registrar,
                whois_country=info.country,
                security_txt=info.security_txt_url or "",
                enrichment_source=info.source,
            )
            updated = self.db.get_finding(finding["id"])
            if updated:
                self._emit({"type": "result", "finding": updated})
            self._log("ok", f"  {info.domain} → {info.best_contact}")
            self._progress(
                0.65 + 0.15 * (index + 1) / len(findings),
                "Enriqueciendo contactos",
            )

    # ------------------------------------------------------------------
    def _sqlmap_phase(self) -> None:
        """Fase OPCIONAL de verificación activa con SQLMap.

        Solo corre si el usuario la activó explícitamente (checkbox o flag
        CLI). Por diseño DorkHunter Pro sigue siendo pasivo.
        """
        if self.sqlmap is None:
            return
        assert self.scan_id is not None
        targets = self._sqlmap_targets()
        if not targets:
            self._log("info", "SQLMap: sin URLs candidatas que verificar.")
            self._progress(0.80, "Completado (sin verificación activa)")
            return

        problems = validate_sqlmap_config(self.sqlmap)
        if problems:
            for problem in problems:
                self._log("error", f"SQLMap desactivado: {problem}")
            self._log(
                "warn",
                "La verificación activa se omitió; el triaje pasivo se conserva.",
            )
            return

        self._log(
            "warn",
            f"SQLMap (prueba ACTIVA) sobre {len(targets)} URL(s). "
            "Continúa SOLO con autorización escrita del propietario.",
        )
        if self.sqlmap.use_proxychains:
            self._log("info", "SQLMap se ejecutará a través de proxychains4.")
        if self.sqlmap.enumerate_dbs:
            self._log(
                "warn",
                "SQLMap con --dbs: enumerará bases de datos (extracción de datos).",
            )

        if self.sqlmap.output_dir is None:
            self.sqlmap.output_dir = REPORTS_DIR / "sqlmap" / f"scan_{self.scan_id}"

        runner = SqlmapRunner(self.sqlmap, self.db, self._emit, self.cancel)

        def on_progress(done: int, total: int) -> None:
            self._progress(
                0.80 + 0.20 * (done / total),
                f"SQLMap ({done}/{total})",
            )

        counts = runner.run(targets, on_progress=on_progress)
        self._sqlmap_counts = counts
        self._log(
            "ok",
            "SQLMap completado: "
            f"{counts[SQLMAP_VULNERABLE]} vulnerable(s), "
            f"{counts[SQLMAP_CLEAN]} sin inyección, "
            f"{counts[SQLMAP_ERROR]} con error.",
        )

    # ------------------------------------------------------------------
    def _sqlmap_targets(self) -> list[dict[str, Any]]:
        """Selecciona las URLs que SQLMap debe verificar.

        ``vulns``: solo hallazgos ``posible_vuln`` del triaje pasivo.
        ``all``: todas las URLs de la caza.
        ``auto`` (por defecto): los ``posible_vuln`` y, si no hubo ninguno,
        el respaldo con todas las URLs que tengan parámetros.
        """
        assert self.scan_id is not None
        findings = self.db.list_findings(self.scan_id)
        mode = self.sqlmap.targets
        used_fallback = False
        selected = findings
        if mode == TARGET_VULNS:
            selected = [
                f for f in findings if f.get("estado") == ESTADO_VULN
            ]
        elif mode == TARGET_AUTO:
            selected = [
                f for f in findings if f.get("estado") == ESTADO_VULN
            ]
            if not selected:
                # Respeto al usuario: una URL con parámetros sigue siendo
                # auditable por SQLMap aunque el pasivo no viera nada.
                selected = [
                    f
                    for f in findings
                    if f.get("parametro") or "?" in str(f.get("url") or "")
                ]
                used_fallback = bool(selected)

        targets: list[dict[str, Any]] = []
        for finding in selected:
            url = str(finding.get("url") or "")
            if not url:
                continue
            targets.append(
                {"finding_id": finding.get("id"), "url": url}
            )

        if mode == TARGET_ALL:
            self._log("info", f"SQLMap objetivo: TODAS las URLs ({len(targets)}).")
        elif mode == TARGET_VULNS or (mode == TARGET_AUTO and not used_fallback):
            self._log(
                "info",
                f"SQLMap objetivo: solo posibles vulns ({len(targets)}).",
            )
        else:
            self._log(
                "info",
                "SQLMap: 0 posibles vulns en el triaje pasivo; "
                f"respaldo: verificar {len(targets)} URL(s) con parámetros.",
            )
        return targets

    # ------------------------------------------------------------------
    def _progress(self, value: float, label: str) -> None:
        self._emit(
            {
                "type": "progress",
                "value": max(0.0, min(1.0, float(value))),
                "label": label,
            }
        )

    def _log(self, level: str, message: str) -> None:
        self._emit({"type": "log", "level": level, "message": message})

    def _emit(self, event: dict) -> None:
        self.events.put(event)


def normalize_target_urls(urls: list[str] | None) -> list[str]:
    """Normaliza URLs directas y descarta las que no se pueden auditar.

    Solo se aceptan HTTP(S) con cadena de consulta. Las URLs sin esquema se
    asumen HTTPS, que es el caso habitual al pegar un enlace en la GUI/CLI.
    """
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in urls or []:
        value = str(raw or "").strip()
        if not value:
            continue
        if value.startswith("//"):
            value = "https:" + value
        elif "://" not in value:
            value = "https://" + value
        try:
            parsed = urlparse(value)
        except ValueError:
            continue
        if parsed.scheme.lower() not in {"http", "https"}:
            continue
        if not parsed.netloc or not parsed.query:
            continue
        normalized = parsed._replace(fragment="").geturl()
        if normalized in seen:
            continue
        seen.add(normalized)
        cleaned.append(normalized)
    return cleaned


def _host_in_scope(url: str, suffix: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    suffix = (suffix or "").lower().lstrip(".")
    if not suffix:
        return True
    return host == suffix or host.endswith("." + suffix)


def parse_domain_list(text: str) -> list[str]:
    """Convierte "uni.edu.co, gov.co" en ["uni.edu.co", "gov.co"].

    Acepta comas, punto y coma, espacios y saltos de línea como separadores.
    Quita prefijos comodín ("*.dominio") y dominios vacíos.
    """
    entries: list[str] = []
    seen: set[str] = set()
    for token in str(text or "").replace(";", ",").replace("\n", ",").split(","):
        value = token.strip().lower()
        while value.startswith("*."):
            value = value[2:]
        value = value.strip(".")
        if value and value not in seen:
            seen.add(value)
            entries.append(value)
    return entries


def _domain_matches(host: str, entry: str) -> bool:
    host = (host or "").lower().lstrip(".")
    entry = (entry or "").lower().lstrip("*.").lstrip(".")
    if not entry:
        return False
    return host == entry or host.endswith("." + entry)


def domain_allowed(
    host: str,
    allow: list[str] | tuple[str, ...] | None,
    deny: list[str] | tuple[str, ...] | None,
) -> bool:
    """True si ``host`` respeta la lista de exclusión y, si hay allowlist,
    pertenece a ella. La lista de exclusión siempre gana."""
    if any(_domain_matches(host, entry) for entry in (deny or [])):
        return False
    allowlist = [entry for entry in (allow or []) if entry]
    if allowlist and not any(_domain_matches(host, entry) for entry in allowlist):
        return False
    return True


def rotation_order(
    engines: list[str] | tuple[str, ...],
    index: int,
) -> list[str]:
    """Orden de motores para el dork ``index`` en modo rotación.

    Cada dork empieza por un motor distinto y conserva el resto como
    respaldo, de modo que una caza usa todos los motores aunque el primero
    devuelva resultados suficientes.
    """
    values = list(engines or [])
    if not values:
        return []
    if len(values) == 1:
        return values
    start = max(0, int(index)) % len(values)
    return values[start:] + values[:start]


# ==========================================================================
# SQLite (historial)  (de database/db_manager.py)
# ==========================================================================
"""Gestión de SQLite con acceso seguro desde varios hilos.

La GUI y los hilos de trabajo comparten una única conexión protegida por un
``RLock``. SQLite en modo WAL tolera bien este patrón y evita el clásico
``database is locked``.
"""

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    finished_at   TEXT,
    dork_used     TEXT NOT NULL,
    country       TEXT,
    domain_type   TEXT,
    keywords      TEXT,
    status        TEXT NOT NULL DEFAULT 'running',
    urls_found    INTEGER NOT NULL DEFAULT 0,
    duplicadas    INTEGER NOT NULL DEFAULT 0,
    duplicadas_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    url             TEXT NOT NULL,
    domain          TEXT,
    parametro       TEXT,
    estado          TEXT NOT NULL DEFAULT 'pendiente',
    error_detectado TEXT,
    evidencia       TEXT,
    http_status     INTEGER,
    dbms            TEXT,
    confianza       TEXT,
    contacto        TEXT,
    organizacion    TEXT,
    registrar       TEXT,
    whois_country   TEXT,
    security_txt    TEXT,
    enrichment_source TEXT,
    reporte_path    TEXT,
    estado_reporte  TEXT NOT NULL DEFAULT 'sin_reporte',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    sqlmap_estado   TEXT,
    sqlmap_output   TEXT,
    waf             TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique
    ON findings(scan_id, url, COALESCE(parametro, ''));

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_estado ON findings(estado);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

_FINDING_FIELDS = {
    "domain",
    "parametro",
    "estado",
    "error_detectado",
    "evidencia",
    "http_status",
    "dbms",
    "confianza",
    "contacto",
    "organizacion",
    "registrar",
    "whois_country",
    "security_txt",
    "enrichment_source",
    "reporte_path",
    "estado_reporte",
    "sqlmap_estado",
    "sqlmap_output",
    "waf",
}

# Columnas añadidas después de la primera versión del esquema. SQLite no
# modifica una tabla existente con CREATE TABLE IF NOT EXISTS, así que las
# añadimos de forma idempotente al abrir la base de datos.
_FINDING_COLUMN_MIGRATIONS: dict[str, str] = {
    "dbms": "TEXT",
    "confianza": "TEXT",
    "registrar": "TEXT",
    "whois_country": "TEXT",
    "enrichment_source": "TEXT",
    "sqlmap_estado": "TEXT",
    "sqlmap_output": "TEXT",
    "waf": "TEXT",
}

# Columnas añadidas a ``scans`` para el resumen de URLs duplicadas.
_SCAN_COLUMN_MIGRATIONS: dict[str, str] = {
    "duplicadas": "INTEGER NOT NULL DEFAULT 0",
    "duplicadas_json": "TEXT",
}


class DatabaseManager:
    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), timeout=30, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._ensure_columns()
            self._conn.commit()

    def _ensure_columns(self) -> None:
        """Migra bases de datos creadas por versiones anteriores."""
        self._ensure_table_columns("findings", _FINDING_COLUMN_MIGRATIONS)
        self._ensure_table_columns("scans", _SCAN_COLUMN_MIGRATIONS)

    def _ensure_table_columns(
        self, table: str, migrations: dict[str, str]
    ) -> None:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {str(row["name"]) for row in rows}
        for name, column_type in migrations.items():
            if name not in existing:
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {column_type}"
                )

    # ------------------------------------------------------------------
    # Escaneos
    # ------------------------------------------------------------------
    def create_scan(
        self,
        dork_used: str,
        country: str = "",
        domain_type: str = "",
        keywords: str = "",
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO scans (created_at, dork_used, country, domain_type, keywords, status)
                VALUES (?, ?, ?, ?, ?, 'running')
                """,
                (now_iso(), dork_used, country, domain_type, keywords),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: str, urls_found: int) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE scans
                   SET finished_at = ?, status = ?, urls_found = ?
                 WHERE id = ?
                """,
                (now_iso(), status, int(urls_found), scan_id),
            )
            self._conn.commit()

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return dict(row) if row else None

    def save_scan_duplicates(
        self, scan_id: int, duplicates: list[dict[str, Any]]
    ) -> None:
        """Guarda el resumen de URLs encontradas por varios dorks."""
        payload = json.dumps(duplicates, ensure_ascii=False)
        with self._lock:
            self._conn.execute(
                """
                UPDATE scans
                   SET duplicadas = ?, duplicadas_json = ?
                 WHERE id = ?
                """,
                (len(duplicates), payload, scan_id),
            )
            self._conn.commit()

    def get_scan_duplicates(self, scan_id: int) -> list[dict[str, Any]]:
        """Recupera las URLs duplicadas guardadas para una caza."""
        with self._lock:
            row = self._conn.execute(
                "SELECT duplicadas_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if not row or not row["duplicadas_json"]:
            return []
        try:
            data = json.loads(str(row["duplicadas_json"]))
        except (TypeError, ValueError):
            return []
        return data if isinstance(data, list) else []

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def list_scans_with_counts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Historial enriquecido con número de hallazgos y posibles SQLi."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT s.*,
                       COUNT(f.id) AS findings_count,
                       COALESCE(SUM(
                           CASE WHEN f.estado = 'posible_vuln' THEN 1 ELSE 0 END
                       ), 0) AS vulns_count
                  FROM scans AS s
                  LEFT JOIN findings AS f ON f.scan_id = s.id
                 GROUP BY s.id
                 ORDER BY s.id DESC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Hallazgos
    # ------------------------------------------------------------------
    def add_finding(
        self,
        scan_id: int,
        url: str,
        domain: str = "",
        parametro: str = "",
        estado: str = "pendiente",
        **fields: Any,
    ) -> int:
        """Inserta o actualiza un hallazgo identificado por (scan, url, parámetro)."""
        ts = now_iso()
        extra = {k: v for k, v in fields.items() if k in _FINDING_FIELDS}
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO findings
                    (scan_id, url, domain, parametro, estado, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, url, domain, parametro, estado, ts, ts),
            )
            row = self._conn.execute(
                """
                SELECT id FROM findings
                 WHERE scan_id = ? AND url = ? AND COALESCE(parametro, '') = ?
                """,
                (scan_id, url, parametro or ""),
            ).fetchone()
            finding_id = int(row["id"])
            if extra:
                assignments = ", ".join(f"{key} = ?" for key in extra)
                values = list(extra.values()) + [ts, finding_id]
                self._conn.execute(
                    f"UPDATE findings SET {assignments}, updated_at = ? WHERE id = ?",
                    values,
                )
            self._conn.commit()
            return finding_id

    def update_finding(self, finding_id: int, **fields: Any) -> None:
        allowed = {k: v for k, v in fields.items() if k in _FINDING_FIELDS}
        if not allowed:
            return
        assignments = ", ".join(f"{key} = ?" for key in allowed)
        values = list(allowed.values()) + [now_iso(), finding_id]
        with self._lock:
            self._conn.execute(
                f"UPDATE findings SET {assignments}, updated_at = ? WHERE id = ?",
                values,
            )
            self._conn.commit()

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
        return dict(row) if row else None

    def set_finding_sqlmap(
        self, finding_id: int, estado: str, output_path: str = ""
    ) -> None:
        """Guarda el veredicto de SQLMap para un hallazgo."""
        self.update_finding(
            finding_id,
            sqlmap_estado=estado,
            sqlmap_output=output_path or "",
        )

    def list_findings(
        self, scan_id: int | None = None, only_vulns: bool = False
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM findings"
        clauses: list[str] = []
        params: list[Any] = []
        if scan_id is not None:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if only_vulns:
            clauses.append("estado = 'posible_vuln'")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id ASC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def summary(self, scan_id: int) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT estado, COUNT(*) AS total FROM findings WHERE scan_id = ? GROUP BY estado",
                (scan_id,),
            ).fetchall()
        return {str(r["estado"]): int(r["total"]) for r in rows}

    # ------------------------------------------------------------------
    # Configuración persistente (disclaimer, preferencias)
    # ------------------------------------------------------------------
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
            finally:
                self._conn.close()


# ==========================================================================
# Interfaz de línea de comandos  (de cli.py)
# ==========================================================================
"""Modo CLI de DorkHunter Pro (sin Tkinter).

Pensado para automatización, servidores sin escritorio y ejecución desde
terminal. Mantiene exactamente el mismo alcance pasivo que la GUI: dorks,
búsqueda, una comilla por URL y enriquecimiento opcional.

Ejemplos:

    python cli.py --country Colombia --type "Educativo (edu)" --yes
    python cli.py --url "https://dominio.com/item.php?id=1" --yes --json salida.json
    python cli.py --dork "site:edu.co inurl:id=" --no-enrich --report caza.md --yes
    python cli.py --dork "site:edu.co inurl:id=" --engines "brave,bing,mojeek" --yes

Verificación ACTIVA opcional (solo con autorización escrita):

    python cli.py --url "https://dominio.com/item.php?id=1" --yes --sqlmap
    python cli.py --url "https://dominio.com/item.php?id=1" --yes \
        --sqlmap --sqlmap-dbs --proxychains
"""

import argparse
import csv
import queue
import sys
import threading
from pathlib import Path
from typing import Any


CSV_FIELDS = (
    "ID",
    "URL",
    "Dominio",
    "Parámetro",
    "Estado",
    "Motor",
    "WAF",
    "Confianza",
    "Error detectado",
    "HTTP",
    "SQLMap",
    "Contacto",
    "Organización",
    "Registrador",
    "País WHOIS",
    "security.txt",
    "Fuente enriquecimiento",
    "Estado reporte",
    "Fecha",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dorkhunter-cli",
        description=(
            "Auditoría pasiva de superficie de exposición mediante dorks y "
            "detección de errores SQL. No explota vulnerabilidades."
        ),
        epilog=(
            "Usa esta herramienta únicamente en sistemas propios o con "
            "autorización escrita. El flag --yes confirma esa autorización."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    parser.add_argument("--country", default="Colombia", help="País objetivo")
    parser.add_argument(
        "--type",
        dest="domain_type",
        default="Educativo (edu)",
        help="Tipo de dominio (Educativo (edu), Gubernamental (gov), ...)",
    )
    parser.add_argument("--keywords", default="", help="Palabras clave opcionales")
    parser.add_argument("--dork", default="", help="Dork manual (omite país/tipo)")
    parser.add_argument(
        "--list-countries",
        action="store_true",
        help="Muestra los países disponibles y sale",
    )
    parser.add_argument(
        "--list-types",
        action="store_true",
        help="Muestra los tipos de dominio disponibles y sale",
    )
    parser.add_argument(
        "--url",
        action="append",
        default=[],
        help="URL directa con parámetros; se puede repetir",
    )
    parser.add_argument(
        "--url-file",
        dest="url_file",
        help=(
            "Archivo .txt con URLs (una por línea; # para comentarios). "
            "Compatible con waybackurls/gau/exports de Burp."
        ),
    )
    parser.add_argument(
        "--domain-sources",
        dest="domain_sources",
        default="",
        help=(
            "Dominio(s) separados por coma para fuentes pasivas "
            "(Wayback CDX + OTX); crt.sh lista subdominios."
        ),
    )
    parser.add_argument(
        "--allow-domains",
        dest="allow_domains",
        default="",
        help="Lista blanca de dominios (coma separada); si se define, solo se auditan hosts de estos dominios o subdominios",
    )
    parser.add_argument(
        "--deny-domains",
        dest="deny_domains",
        default="",
        help="Lista negra de dominios (coma separada); excluye hosts de estos dominios aunque estén en la lista blanca",
    )
    parser.add_argument(
        "--engines",
        default="auto",
        help=(
            "Motores de búsqueda separados por coma "
            "(duckduckgo,brave,bing,mojeek[,yahoo,yandex]) o 'auto'."
        ),
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_DORK_COUNT,
        help=f"Número de dorks a generar (por defecto {DEFAULT_DORK_COUNT})",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=MAX_RESULTS_PER_DORK,
        help="Resultados por consulta de búsqueda",
    )
    parser.add_argument(
        "--max-urls",
        type=int,
        default=MAX_URLS_PER_HUNT,
        help="Tope de URLs por caza",
    )
    parser.add_argument("--no-scan", action="store_true", help="Solo recolectar URLs")
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Rotar los motores entre dorks (usa todos en una misma caza)",
    )
    parser.add_argument(
        "--no-enrich", action="store_true", help="No consultar WHOIS/security.txt"
    )
    parser.add_argument(
        "--sqlmap",
        action="store_true",
        help=(
            "Fase ACTIVA opcional: verificar con SQLMap los hallazgos "
            "posible_vuln; si no hay ninguno, respaldo con todas las URLs "
            "que tengan parámetros. Solo con autorización escrita."
        ),
    )
    parser.add_argument(
        "--sqlmap-all",
        action="store_true",
        help="Con --sqlmap: verificar TODAS las URLs, no solo las posibles vulns",
    )
    parser.add_argument(
        "--sqlmap-dbs",
        action="store_true",
        help=(
            "Con --sqlmap: añade --dbs, que EXTRAe bases de datos. "
            "Solo si tu autorización lo permite."
        ),
    )
    parser.add_argument(
        "--proxychains",
        action="store_true",
        help="Con --sqlmap: ejecutar sqlmap envuelto en proxychains4",
    )
    parser.add_argument(
        "--sqlmap-workers",
        type=int,
        default=SQLMAP_WORKERS,
        help=(
            f"Procesos sqlmap simultáneos (por defecto {SQLMAP_WORKERS}, "
            "máximo 8)"
        ),
    )
    parser.add_argument(
        "--sqlmap-threads",
        type=int,
        default=1,
        help="Hilos internos de sqlmap por proceso (--threads; por defecto 1)",
    )
    parser.add_argument(
        "--sqlmap-bin",
        default=SQLMAP_BIN,
        help=f"Ruta del binario sqlmap (por defecto {SQLMAP_BIN!r})",
    )
    parser.add_argument(
        "--sqlmap-timeout",
        type=int,
        default=SQLMAP_TIMEOUT,
        help=f"Segundos máximos por URL (por defecto {SQLMAP_TIMEOUT})",
    )
    parser.add_argument(
        "--sqlmap-preset",
        choices=("seguro", "estandar", "profundo"),
        default="seguro",
        help=(
            "Intensidad de SQLMap: seguro (batch), estandar (--level=2 --risk=1) "
            "o profundo (--level=3 --risk=2)"
        ),
    )
    parser.add_argument(
        "--sqlmap-flags",
        dest="sqlmap_flags",
        default="",
        help="Flags extra para sqlmap, separados por espacios (p. ej. \"--forms --titles\")",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirma que tienes autorización escrita para la prueba",
    )
    parser.add_argument("--db", default=str(DB_PATH), help="Ruta alternativa de SQLite")
    parser.add_argument("--json", dest="json_path", help="Exportar la caza a JSON")
    parser.add_argument("--csv", dest="csv_path", help="Exportar hallazgos a CSV")
    parser.add_argument(
        "--report",
        dest="report_path",
        help="Reporte agregado (.md, .html o .json)",
    )
    parser.add_argument("--quiet", action="store_true", help="Menos salida por consola")
    parser.add_argument(
        "--verbose", action="store_true", help="Mostrar URLs candidatas y progreso"
    )
    return parser


def _authorize(yes: bool, sqlmap_active: bool = False) -> bool:
    if yes:
        return True
    scope = (
        "Además del triaje pasivo (una comilla), has activado SQLMap, que envía "
        "payloads reales y, con --dbs, extrae bases de datos.\n"
        if sqlmap_active
        else "No explota vulnerabilidades; solo envía una comilla simple y "
        "busca mensajes de error SQL.\n"
    )
    print(
        f"{APP_NAME} v{APP_VERSION}\n"
        "Aviso: usa esta herramienta solo en sistemas propios o con autorización "
        f"escrita. {scope}\n"
    )
    if not sys.stdin.isatty():
        print(
            "Entorno no interactivo: añade --yes para confirmar la autorización.",
            file=sys.stderr,
        )
        return False
    answer = input("¿Confirmas que tienes autorización escrita? [s/N]: ")
    return answer.strip().lower() in {"s", "si", "sí", "y", "yes"}


def _confirm_sqlmap_cli(yes: bool, enumerate_dbs: bool, use_proxychains: bool) -> bool:
    """Confirmación específica para la fase ACTIVA con SQLMap."""
    if yes:
        return True
    extras = []
    if enumerate_dbs:
        extras.append("--dbs (EXTRAE bases de datos)")
    if use_proxychains:
        extras.append("proxychains4")
    detail = f" Incluye: {', '.join(extras)}." if extras else ""
    print(
        "\nADVERTENCIA — verificación activa con SQLMap\n"
        "SQLMap enviará payloads reales contra las URLs seleccionadas y puede "
        "generar cientos de peticiones." + detail + "\n"
        "Ejecuta esto ÚNICAMENTE sobre sistemas de tu propiedad o con "
        "autorización escrita y vigente.\n"
    )
    if not sys.stdin.isatty():
        print(
            "Entorno no interactivo: añade --yes para confirmar la prueba activa.",
            file=sys.stderr,
        )
        return False
    answer = input("¿Confirmas la prueba ACTIVA con SQLMap? [s/N]: ")
    return answer.strip().lower() in {"s", "si", "sí", "y", "yes"}


def _print_event(
    event: dict[str, Any], quiet: bool, verbose: bool
) -> None:
    kind = event.get("type")
    if kind == "log":
        if not quiet:
            level = str(event.get("level") or "info").upper()
            print(f"[{level}] {event.get('message', '')}")
    elif kind == "scan_started":
        if not quiet:
            print(f"Caza #{event.get('scan_id')} creada.")
    elif kind == "candidate" and verbose:
        print(f"  + {event.get('url', '')}")
    elif kind == "progress" and verbose:
        value = float(event.get("value", 0.0))
        print(f"  {int(round(value * 100)):3d}% {event.get('label', '')}")
    elif kind == "result":
        finding = event.get("finding") or {}
        if finding.get("estado") == ESTADO_VULN and not quiet:
            details = [f"parámetro={finding.get('parametro') or '—'}"]
            if finding.get("dbms"):
                details.append(f"motor={finding['dbms']}")
            if finding.get("confianza"):
                details.append(f"confianza={finding['confianza']}")
            if finding.get("waf"):
                details.append(f"waf={finding['waf']}")
            print(f"[VULN] {finding.get('url', '')} ({', '.join(details)})")
    elif kind == "sqlmap_started" and verbose:
        print(f"[SQLMAP W{event.get('worker', '?')}] {event.get('url', '')}")
    elif kind == "sqlmap_line" and verbose:
        worker = event.get("worker", "?")
        print(f"  [W{worker}] {event.get('line', '')}")
    elif kind == "sqlmap":
        estado = str(event.get("estado") or "")
        label = event.get("estado_label") or SQLMAP_LABELS.get(estado, estado)
        if not quiet or estado == SQLMAP_VULNERABLE:
            print(f"[SQLMAP] {event.get('url', '')}: {label}")
    elif kind == "error":
        print(f"[ERROR] {event.get('message', 'Error desconocido')}", file=sys.stderr)


def _write_csv(path: Path, findings: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in findings:
            confidence = str(row.get("confianza") or "")
            writer.writerow(
                {
                    "ID": row.get("id"),
                    "URL": row.get("url"),
                    "Dominio": row.get("domain"),
                    "Parámetro": row.get("parametro"),
                    "Estado": ESTADO_LABELS.get(
                        str(row.get("estado")), row.get("estado")
                    ),
                    "Motor": row.get("dbms") or "",
                    "WAF": row.get("waf") or "",
                    "Confianza": CONFIANZA_LABELS.get(confidence, confidence),
                    "Error detectado": row.get("error_detectado"),
                    "HTTP": row.get("http_status"),
                    "SQLMap": SQLMAP_LABELS.get(
                        str(row.get("sqlmap_estado") or ""), ""
                    ),
                    "Contacto": row.get("contacto"),
                    "Organización": row.get("organizacion"),
                    "Registrador": row.get("registrar") or "",
                    "País WHOIS": row.get("whois_country") or "",
                    "security.txt": row.get("security_txt"),
                    "Fuente enriquecimiento": row.get("enrichment_source") or "",
                    "Estado reporte": row.get("estado_reporte"),
                    "Fecha": row.get("created_at"),
                }
            )


def load_url_file(path: Path) -> list[str]:
    """Lee URLs de un archivo .txt (una por línea, # para comentarios)."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    urls: list[str] = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        urls.append(value)
    return urls


def _write_report(path: Path, scan: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = path.suffix.lower().lstrip(".") or "md"
    generator = ReportGenerator(REPORTS_DIR)
    builders = {
        "md": generator.build_scan_markdown,
        "html": generator.build_scan_html,
        "json": generator.build_scan_json,
    }
    if fmt not in builders:
        raise ValueError("El reporte debe terminar en .md, .html o .json.")
    path.write_text(builders[fmt](scan, findings), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_countries:
        for category, countries in COUNTRY_CATEGORIES.items():
            print(f"[{category}]")
            for country in countries:
                print(f"  {country}")
        return 0
    if args.list_types:
        print("\n".join(DOMAIN_TYPES))
        return 0

    try:
        engines = normalize_engines(args.engines)
    except ValueError as exc:
        print(f"Motores de búsqueda inválidos: {exc}", file=sys.stderr)
        return 2

    if not _authorize(bool(args.yes), sqlmap_active=bool(args.sqlmap)):
        return 2

    sqlmap_config: SqlmapConfig | None = None
    if args.sqlmap:
        if not _confirm_sqlmap_cli(
            bool(args.yes), bool(args.sqlmap_dbs), bool(args.proxychains)
        ):
            return 2
        extra_flags = preset_extra_flags(args.sqlmap_preset) + parse_extra_flags(
            args.sqlmap_flags
        )
        sqlmap_config = SqlmapConfig(
            enabled=True,
            sqlmap_bin=str(args.sqlmap_bin),
            use_proxychains=bool(args.proxychains),
            enumerate_dbs=bool(args.sqlmap_dbs),
            targets=TARGET_ALL if args.sqlmap_all else TARGET_VULNS,
            timeout=max(30, int(args.sqlmap_timeout)),
            workers=max(1, int(args.sqlmap_workers)),
            sqlmap_threads=max(1, int(args.sqlmap_threads)),
            extra_flags=extra_flags,
        )
        problems = validate_sqlmap_config(sqlmap_config)
        if problems:
            for problem in problems:
                print(f"SQLMap desactivado: {problem}", file=sys.stderr)
            return 2

    targets = normalize_target_urls(args.url)
    if args.url and not targets:
        print(
            "Ninguna --url es válida: usa http(s) y al menos un parámetro.",
            file=sys.stderr,
        )
        return 2

    if args.url_file:
        try:
            file_urls = load_url_file(Path(args.url_file))
        except OSError as exc:
            print(f"No se pudo leer el archivo de URLs: {exc}", file=sys.stderr)
            return 2
        before = len(targets)
        targets = normalize_target_urls(list(args.url) + file_urls)
        added = len(targets) - before
        if added <= 0:
            print(
                "El archivo de URLs no aportó URLs válidas "
                "(http(s) y al menos un parámetro).",
                file=sys.stderr,
            )
            return 2
        print(f"Archivo de URLs: {added} URL(s) válidas añadidas.")

    if args.domain_sources and not targets:
        domains = parse_domain_list(args.domain_sources)
        if domains:
            # collect_domain_urls() ya vive en este mismo archivo (sección de
            # fuentes pasivas). Importarlo de core.* rompía la copia standalone.
            print(
                f"Fuentes pasivas (Wayback CDX + OTX + crt.sh) para: "
                f"{', '.join(domains)}"
            )
            passive_targets = collect_domain_urls(
                domains, log=lambda level, msg: print(f"[{level.upper()}] {msg}")
            )
            targets = normalize_target_urls(passive_targets)
            if not targets:
                print(
                    "Las fuentes pasivas no devolvieron URLs con parámetros; "
                    "se continúa con la búsqueda de dorks.",
                    file=sys.stderr,
                )

    dorks = []
    if not targets:
        try:
            dorks = DorkEngine().build(
                args.country,
                args.domain_type,
                args.keywords,
                args.dork,
                limit=max(1, args.depth),
            )
        except ValueError as exc:
            print(f"Filtros inválidos: {exc}", file=sys.stderr)
            return 2

    params = HuntParams(
        country=args.country,
        domain_type=args.domain_type,
        keywords=args.keywords,
        manual_dork=args.dork,
        max_results=max(1, args.max_results),
        do_scan=not args.no_scan,
        do_enrich=not args.no_enrich,
        dorks=dorks,
        target_urls=targets,
        max_urls=max(1, args.max_urls),
        engines=engines,
        rotate=bool(args.rotate),
        allow_domains=parse_domain_list(args.allow_domains),
        deny_domains=parse_domain_list(args.deny_domains),
        sqlmap=sqlmap_config,
    )

    db = DatabaseManager(Path(args.db))
    events: queue.Queue[dict[str, Any]] = queue.Queue()
    cancel = threading.Event()
    orchestrator = HuntOrchestrator(db, events, cancel, params)
    worker = threading.Thread(target=orchestrator.run, name="hunt-cli", daemon=True)
    worker.start()

    interrupted = False
    try:
        while worker.is_alive() or not events.empty():
            try:
                event = events.get(timeout=0.2)
            except queue.Empty:
                continue
            _print_event(event, bool(args.quiet), bool(args.verbose))
    except KeyboardInterrupt:
        interrupted = True
        cancel.set()
        print("\nDetención solicitada; esperando peticiones en curso…", file=sys.stderr)
        worker.join(timeout=10)
        while not events.empty():
            try:
                _print_event(events.get_nowait(), bool(args.quiet), bool(args.verbose))
            except queue.Empty:
                break
    finally:
        worker.join(timeout=2)

    if worker.is_alive():
        print(
            "La caza sigue esperando una respuesta de red; el proceso terminará "
            "sin cerrar la base de datos.",
            file=sys.stderr,
        )
        return 130

    scan_id = orchestrator.scan_id
    if scan_id is None:
        db.close()
        return 130 if interrupted else 1

    scan = db.get_scan(scan_id) or {"id": scan_id}
    findings = db.list_findings(scan_id)
    vulns = [f for f in findings if f.get("estado") == ESTADO_VULN]

    duplicates = orchestrator.duplicates()
    print(
        f"\nCaza #{scan_id}: {len(findings)} hallazgo(s), "
        f"{len(vulns)} posible(s) SQLi, "
        f"{len(duplicates)} URL(s) duplicada(s)."
    )
    for finding in vulns:
        print(
            f"  - {finding.get('url')} "
            f"[{finding.get('parametro') or '—'} · "
            f"{finding.get('dbms') or 'motor N/D'} · "
            f"confianza {finding.get('confianza') or 'N/D'}]"
        )

    sqlmap_checked = [f for f in findings if f.get("sqlmap_estado")]
    if sqlmap_checked:
        sqlmap_vulns = [
            f for f in sqlmap_checked
            if f.get("sqlmap_estado") == SQLMAP_VULNERABLE
        ]
        print(
            f"\nSQLMap: {len(sqlmap_checked)} URL(s) verificada(s), "
            f"{len(sqlmap_vulns)} vulnerable(s)."
        )
        for finding in sqlmap_checked:
            estado = str(finding.get("sqlmap_estado"))
            label = SQLMAP_LABELS.get(estado, estado)
            print(f"  - {finding.get('url')} → {label}")

    try:
        if args.json_path:
            json_path = Path(args.json_path)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                ReportGenerator(REPORTS_DIR).build_scan_json(scan, findings),
                encoding="utf-8",
            )
            print(f"JSON: {json_path}")
        if args.csv_path:
            csv_path = Path(args.csv_path)
            _write_csv(csv_path, findings)
            print(f"CSV: {csv_path}")
        if args.report_path:
            report_path = Path(args.report_path)
            _write_report(report_path, scan, findings)
            print(f"Reporte: {report_path}")
    except (OSError, ValueError) as exc:
        print(f"No se pudo exportar: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()

    if interrupted:
        return 130
    return 0 if scan.get("status") != "error" else 1


if __name__ == "__main__":
    raise SystemExit(main())
