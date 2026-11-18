"""Fuentes pasivas de URLs y subdominios (Wayback, OTX, crt.sh).

Todo lo que hace este módulo son lecturas públicas contra terceros de OSINT
(web.archive.org, otx.alienvault.com, crt.sh). **Nunca** contacta al objetivo:
las URLs que devuelve se incorporan a la caza y solo se prueban si el usuario
lo autoriza en la fase de triaje/verificación.

Cada fuente es tolerante a fallos: si la petición falla, se devuelve una lista
vacía y la caza continúa con el resto de fuentes.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

import requests

from config import USER_AGENT

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
