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
from __future__ import annotations

import argparse
import csv
import queue
import sys
import threading
from pathlib import Path
from typing import Any

from config import (
    APP_NAME,
    APP_VERSION,
    DB_PATH,
    DEFAULT_DORK_COUNT,
    MAX_RESULTS_PER_DORK,
    MAX_URLS_PER_HUNT,
    REPORTS_DIR,
    SQLMAP_BIN,
    SQLMAP_TIMEOUT,
    SQLMAP_WORKERS,
)
from core.dork_engine import COUNTRY_CATEGORIES, DOMAIN_TYPES, DorkEngine
from core.orchestrator import (
    HuntOrchestrator,
    HuntParams,
    normalize_target_urls,
    parse_domain_list,
)
from core.search_engine import normalize_engines
from core.report_generator import ReportGenerator
from core.sqli_scanner import CONFIANZA_LABELS, ESTADO_LABELS, ESTADO_VULN
from core.sqlmap_runner import (
    SQLMAP_LABELS,
    SQLMAP_VULNERABLE,
    SqlmapConfig,
    TARGET_ALL,
    TARGET_VULNS,
    parse_extra_flags,
    preset_extra_flags,
    validate_sqlmap_config,
)
from database.db_manager import DatabaseManager

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
            from core.passive_sources import collect_domain_urls

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
