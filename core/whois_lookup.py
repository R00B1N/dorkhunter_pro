"""Enriquecimiento de hallazgos: WHOIS + security.txt.

``python-whois`` se usa cuando está instalado, pero la consulta se ejecuta en
un hilo con tiempo límite para que una conexión colgada no bloquee la caza.
Si falla, se usa un cliente WHOIS por socket (RFC 3912) con timeouts explícitos.
"""
from __future__ import annotations

import logging
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import urllib3

from config import USER_AGENT, WHOIS_DELAY, WHOIS_TIMEOUT

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
