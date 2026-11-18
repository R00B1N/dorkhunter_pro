"""Configuración central de DorkHunter Pro.

Todos los valores ajustables viven aquí para evitar constantes dispersas.
Los límites de red son deliberadamente conservadores: la herramienta hace
triaje pasivo, no explotación.
"""
from __future__ import annotations

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
