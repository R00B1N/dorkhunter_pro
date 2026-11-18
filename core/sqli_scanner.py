"""Detección pasiva de errores SQL.

Alcance deliberadamente limitado:

* Una petición GET de línea base y **una** petición GET con una comilla simple
  añadida al primer parámetro auditable.
* Solo se busca la aparición de firmas de error del motor de base de datos.
* No hay payloads de unión, booleanos, temporales ni extracción de datos.

Este módulo no debe ampliarse para explotar la vulnerabilidad. Su función es
generar un indicio que un equipo autorizado pueda confirmar.
"""
from __future__ import annotations

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

from config import (
    HTTP_TIMEOUT,
    MAX_BODY_BYTES,
    MAX_EVIDENCE_CHARS,
    MAX_REDIRECTS,
    SCAN_DELAY_PER_HOST,
    USER_AGENT,
)
from utils.helpers import redact_sensitive, strip_html, truncate

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
