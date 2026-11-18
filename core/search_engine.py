"""Recolección de URLs en varios buscadores públicos (sin Google).

Para cada dork se combina:

1. la librería ``ddgs`` con un backend concreto (DuckDuckGo, Brave, Mojeek).
2. el HTML público de Bing, Brave y Mojeek si la librería falla o no trae nada.

Google se descarta a propósito porque es el motor que más bloquea el triaje
automatizado. Todos los motores se consultan con el mismo ``User-Agent``
honesto y respetan un espaciado mínimo entre peticiones.
"""
from __future__ import annotations

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

from config import (
    SEARCH_DELAY,
    SEARCH_ENGINES,
    SEARCH_RETRIES,
    SEARCH_TIMEOUT,
    USER_AGENT,
)

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
