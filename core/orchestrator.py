"""Orquestador de una caza: dorks → búsqueda → escaneo → enriquecimiento.

Se ejecuta en un hilo de trabajo y comunica todo a la GUI mediante una
``queue.Queue``. Ningún widget se toca desde aquí.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from config import (
    MAX_URLS_PER_HUNT,
    REPORTS_DIR,
    SCAN_WORKERS,
    SEARCH_ENGINES,
)
from core.dork_engine import Dork, DorkEngine
from core.search_engine import SearchEngine
from core.sqli_scanner import (
    ESTADO_ERROR,
    ESTADO_VULN,
    PassiveScanner,
    ScanResult,
)
from core.sqlmap_runner import (
    SQLMAP_CLEAN,
    SQLMAP_ERROR,
    SQLMAP_VULNERABLE,
    SqlmapConfig,
    SqlmapRunner,
    TARGET_ALL,
    TARGET_AUTO,
    TARGET_VULNS,
    validate_sqlmap_config,
)
from core.whois_lookup import WhoisLookup

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
