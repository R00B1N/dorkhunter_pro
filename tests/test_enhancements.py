"""Pruebas de las mejoras de triaje, reportes, historial y CLI."""
from __future__ import annotations

import json
import queue
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from cli import _write_csv, _write_report, build_parser
from config import MAX_URLS_PER_HUNT
from core.orchestrator import (
    HuntOrchestrator,
    HuntParams,
    normalize_target_urls,
    rotation_order,
)
from core.report_generator import DISCLAIMER_NOTE, ReportGenerator
from core.sqli_scanner import (
    CONFIANZA_ALTA,
    CONFIANZA_BAJA,
    CONFIANZA_MEDIA,
    ESTADO_OK,
    ESTADO_OMITIDO,
    ESTADO_VULN,
    PassiveScanner,
    _candidate_params,
    _confidence_for,
    detect_error,
)
from database.db_manager import DatabaseManager


class ScannerEnhancementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                error = (
                    "Warning: mysql_fetch_array() expects parameter 1 to be "
                    "resource. You have an error in your SQL syntax near '1'"
                )
                if self.path.startswith("/always"):
                    body = f"<html><body>{error}</body></html>"
                elif "%27" in self.path or "'" in self.path:
                    body = f"<html><body>{error}</body></html>"
                else:
                    body = "<html><body>OK</body></html>"
                data = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args) -> None:
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_priority_and_tracking_params(self) -> None:
        candidates = _candidate_params("utm_source=news&page=2&id=10&q=hola")
        self.assertEqual(candidates[0][0], "id")
        self.assertEqual(candidates[1][0], "page")
        self.assertEqual(_candidate_params("utm_source=x&fbclid=y"), [])

    def test_confidence_and_dbms(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(f"http://127.0.0.1:{self.port}/item.php?id=1")
        self.assertEqual(result.estado, ESTADO_VULN)
        self.assertEqual(result.dbms, "MySQL")
        self.assertEqual(result.confianza, CONFIANZA_ALTA)

    def test_baseline_error_is_not_attributed(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(f"http://127.0.0.1:{self.port}/always.php?id=1")
        self.assertEqual(result.estado, ESTADO_OK)
        self.assertIn("línea base", result.mensaje)

    def test_tracking_only_url_is_omitted(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(
            f"http://127.0.0.1:{self.port}/item.php?utm_source=news"
        )
        self.assertEqual(result.estado, ESTADO_OMITIDO)

    def test_expanded_signatures(self) -> None:
        cases = {
            "MSSQL": "Unclosed quotation mark after the character string",
            "PostgreSQL": 'ERROR: syntax error at or near "\'"',
            "Oracle": "ORA-01756: quoted string not properly terminated",
            "SQLite": 'sqlite3.OperationalError: near "\'"',
            "DB2": "DB2 SQL Error: SQLCODE=-104",
            "Firebird": "Dynamic SQL Error: unexpected end of statement",
            "Access": "Microsoft JET Database Engine error",
        }
        for expected, text in cases.items():
            with self.subTest(expected=expected):
                engine, _match = detect_error(text)
                self.assertEqual(engine, expected)

    def test_confidence_helper(self) -> None:
        self.assertEqual(_confidence_for("MySQL", False, 200, 200), CONFIANZA_ALTA)
        self.assertEqual(_confidence_for("MySQL", True, None, 200), CONFIANZA_MEDIA)
        self.assertEqual(_confidence_for("MySQL", False, 200, 500), CONFIANZA_MEDIA)
        self.assertEqual(_confidence_for("SQL", True, None, 200), CONFIANZA_BAJA)


class OrchestratorEnhancementTests(unittest.TestCase):
    def test_normalize_target_urls(self) -> None:
        urls = [
            "https://uni.edu.co/item.php?id=1",
            "uni.edu.co/otro.php?page=2",
            "//uni.edu.co/tercero.php?q=hola",
            "ftp://uni.edu.co/file",
            "https://uni.edu.co/sin-parametros",
            "https://uni.edu.co/item.php?id=1",
        ]
        self.assertEqual(
            normalize_target_urls(urls),
            [
                "https://uni.edu.co/item.php?id=1",
                "https://uni.edu.co/otro.php?page=2",
                "https://uni.edu.co/tercero.php?q=hola",
            ],
        )

    def test_hunt_params_defaults(self) -> None:
        params = HuntParams(country="Colombia", domain_type="Todos")
        self.assertEqual(params.max_urls, MAX_URLS_PER_HUNT)
        self.assertEqual(params.target_urls, [])
        self.assertFalse(params.rotate)

    def test_rotation_order(self) -> None:
        engines = ["duckduckgo", "brave", "bing", "mojeek"]
        self.assertEqual(rotation_order(engines, 0), engines)
        self.assertEqual(
            rotation_order(engines, 1),
            ["brave", "bing", "mojeek", "duckduckgo"],
        )
        self.assertEqual(
            rotation_order(engines, 3),
            ["mojeek", "duckduckgo", "brave", "bing"],
        )
        self.assertEqual(rotation_order(engines, 4), engines)
        self.assertEqual(rotation_order(["brave"], 9), ["brave"])
        self.assertEqual(rotation_order([], 2), [])
        self.assertEqual(rotation_order(engines, -1), engines)

    def test_duplicate_tracking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            try:
                params = HuntParams(country="Colombia", domain_type="Todos")
                orchestrator = HuntOrchestrator(
                    db, queue.Queue(), threading.Event(), params
                )
                url = "https://uni.edu.co/item.php?id=1"
                orchestrator._record_url_source(url, "dork A")
                orchestrator._record_url_source(url, "dork A")
                orchestrator._record_url_source(url, "dork B")
                orchestrator._record_url_source(
                    "https://uni.edu.co/ok.php?id=2", "dork A"
                )
                duplicates = orchestrator.duplicates()
                self.assertEqual(len(duplicates), 1)
                self.assertEqual(duplicates[0]["url"], url)
                self.assertEqual(duplicates[0]["count"], 2)
                self.assertEqual(
                    duplicates[0]["sources"], ["dork A", "dork B"]
                )
            finally:
                db.close()


class DatabaseEnhancementTests(unittest.TestCase):
    def test_metadata_and_history_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            try:
                scan_id = db.create_scan("site:edu.co inurl:id=", "Colombia", "edu")
                finding_id = db.add_finding(
                    scan_id,
                    "https://uni.edu.co/item.php?id=1",
                    domain="uni.edu.co",
                    parametro="id",
                    estado=ESTADO_VULN,
                    dbms="MySQL",
                    confianza="alta",
                    registrar="Registrador de Prueba",
                    whois_country="CO",
                    enrichment_source="python-whois",
                )
                finding = db.get_finding(finding_id)
                assert finding is not None
                self.assertEqual(finding["dbms"], "MySQL")
                self.assertEqual(finding["confianza"], "alta")
                self.assertEqual(finding["registrar"], "Registrador de Prueba")
                self.assertEqual(finding["whois_country"], "CO")
                self.assertEqual(finding["enrichment_source"], "python-whois")

                db.add_finding(
                    scan_id,
                    "https://uni.edu.co/ok.php?id=1",
                    domain="uni.edu.co",
                    parametro="id",
                    estado=ESTADO_OK,
                )
                history = db.list_scans_with_counts()
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0]["findings_count"], 2)
                self.assertEqual(history[0]["vulns_count"], 1)
            finally:
                db.close()

    def test_duplicates_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            try:
                scan_id = db.create_scan("dork", "Colombia", "edu")
                duplicates = [
                    {
                        "url": "https://uni.edu.co/item.php?id=1",
                        "count": 2,
                        "sources": [
                            "site:edu.co inurl:id=",
                            "site:edu.co inurl:page=",
                        ],
                    }
                ]
                db.save_scan_duplicates(scan_id, duplicates)
                self.assertEqual(db.get_scan_duplicates(scan_id), duplicates)
                scan = db.get_scan(scan_id)
                assert scan is not None
                self.assertEqual(scan["duplicadas"], 1)
                self.assertEqual(db.get_scan_duplicates(scan_id + 999), [])
            finally:
                db.close()

    def test_scan_duplicate_columns_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old_scans.db"
            conn = sqlite3.connect(path)
            conn.executescript(
                """
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    finished_at TEXT,
                    dork_used TEXT NOT NULL,
                    country TEXT,
                    domain_type TEXT,
                    keywords TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    urls_found INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.commit()
            conn.close()

            db = DatabaseManager(path)
            try:
                columns = {
                    str(row["name"])
                    for row in db._conn.execute(
                        "PRAGMA table_info(scans)"
                    ).fetchall()
                }
                self.assertIn("duplicadas", columns)
                self.assertIn("duplicadas_json", columns)
                scan_id = db.create_scan("dork", "Colombia", "edu")
                db.save_scan_duplicates(scan_id, [])
                self.assertEqual(db.get_scan_duplicates(scan_id), [])
            finally:
                db.close()

    def test_schema_migration_from_old_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            conn = sqlite3.connect(path)
            conn.executescript(
                """
                CREATE TABLE findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    domain TEXT,
                    parametro TEXT,
                    estado TEXT NOT NULL DEFAULT 'pendiente',
                    error_detectado TEXT,
                    evidencia TEXT,
                    http_status INTEGER,
                    contacto TEXT,
                    organizacion TEXT,
                    security_txt TEXT,
                    reporte_path TEXT,
                    estado_reporte TEXT NOT NULL DEFAULT 'sin_reporte',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX idx_findings_unique
                    ON findings(scan_id, url, COALESCE(parametro, ''));
                """
            )
            conn.commit()
            conn.close()

            db = DatabaseManager(path)
            try:
                columns = {
                    str(row["name"])
                    for row in db._conn.execute("PRAGMA table_info(findings)").fetchall()
                }
                self.assertIn("dbms", columns)
                self.assertIn("confianza", columns)
                self.assertIn("registrar", columns)
                self.assertIn("whois_country", columns)
                self.assertIn("enrichment_source", columns)

                scan_columns = {
                    str(row["name"])
                    for row in db._conn.execute(
                        "PRAGMA table_info(scans)"
                    ).fetchall()
                }
                self.assertIn("duplicadas", scan_columns)
                self.assertIn("duplicadas_json", scan_columns)

                scan_id = db.create_scan("dork", "Colombia", "edu")
                finding_id = db.add_finding(
                    scan_id,
                    "https://uni.edu.co/item.php?id=1",
                    domain="uni.edu.co",
                    parametro="id",
                    dbms="SQLite",
                    confianza="media",
                )
                self.assertEqual(db.get_finding(finding_id)["dbms"], "SQLite")
            finally:
                db.close()


class ReportEnhancementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = {
            "id": 10,
            "url": "https://uni.edu.co/item.php?id=1",
            "domain": "uni.edu.co",
            "parametro": "id",
            "estado": ESTADO_VULN,
            "evidencia": "You have an error in your SQL syntax",
            "error_detectado": "MySQL: You have an error in your SQL syntax",
            "http_status": 200,
            "dbms": "MySQL",
            "confianza": "alta",
            "contacto": "security@uni.edu.co",
            "organizacion": "Universidad de Prueba",
            "registrar": "Registrador de Prueba",
            "whois_country": "CO",
            "security_txt": "https://uni.edu.co/.well-known/security.txt",
            "enrichment_source": "python-whois",
            "estado_reporte": "sin_reporte",
            "created_at": "2026-01-01T00:00:00-05:00",
        }
        self.scan = {
            "id": 7,
            "created_at": "2026-01-01T00:00:00-05:00",
            "country": "Colombia",
            "domain_type": "Educativo (edu)",
            "keywords": "",
            "dork_used": "site:edu.co inurl:id=",
            "status": "completado",
            "urls_found": 1,
        }
        self.findings = [
            self.finding,
            {
                "id": 11,
                "url": "https://uni.edu.co/ok.php?id=1",
                "domain": "uni.edu.co",
                "parametro": "id",
                "estado": ESTADO_OK,
                "dbms": "",
                "confianza": "",
            },
        ]

    def test_finding_report_includes_triage_metadata(self) -> None:
        generator = ReportGenerator(tempfile.mkdtemp())
        markdown = generator.build_markdown(self.finding)
        self.assertIn("Motor de base de datos", markdown)
        self.assertIn("Confianza del triaje", markdown)
        self.assertIn("Registrador", markdown)
        self.assertIn("País WHOIS", markdown)
        self.assertIn("MySQL", markdown)
        self.assertIn("alta", markdown)

        html = generator.build_html(self.finding)
        self.assertIn("Motor de base de datos", html)
        self.assertIn("Registrador", html)

    def test_scan_report_markdown_html_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            generator = ReportGenerator(tmp)
            markdown = generator.build_scan_markdown(self.scan, self.findings)
            self.assertIn("Caza #7", markdown)
            self.assertIn("Posibles SQLi", markdown)
            self.assertIn("MySQL", markdown)
            self.assertIn("security@uni.edu.co", markdown)
            self.assertIn(DISCLAIMER_NOTE, markdown)

            html = generator.build_scan_html(self.scan, self.findings)
            self.assertIn("<html", html)
            self.assertIn("Caza #7", html)
            self.assertIn(DISCLAIMER_NOTE, html)

            payload = json.loads(generator.build_scan_json(self.scan, self.findings))
            self.assertEqual(payload["summary"]["total"], 2)
            self.assertEqual(payload["summary"]["posibles_vuln"], 1)
            self.assertEqual(payload["scan"]["id"], 7)

            scan_with_dups = dict(self.scan)
            scan_with_dups["duplicadas"] = 1
            scan_with_dups["duplicadas_json"] = json.dumps(
                [
                    {
                        "url": "https://uni.edu.co/item.php?id=1",
                        "count": 2,
                        "sources": ["dork A", "dork B"],
                    }
                ]
            )
            dup_payload = json.loads(
                generator.build_scan_json(scan_with_dups, self.findings)
            )
            self.assertEqual(dup_payload["summary"]["duplicadas"], 1)
            self.assertEqual(dup_payload["duplicates"][0]["count"], 2)
            self.assertNotIn("duplicadas_json", dup_payload["scan"])

            path = generator.generate_scan(self.scan, self.findings, "json")
            self.assertEqual(path.suffix, ".json")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["scan"]["id"], 7)

            finding_path = generator.generate(self.finding, "json")
            self.assertEqual(
                json.loads(finding_path.read_text(encoding="utf-8"))["finding"]["id"],
                10,
            )


class CliEnhancementTests(unittest.TestCase):
    def test_parser_and_exports(self) -> None:
        args = build_parser().parse_args(
            [
                "--url",
                "https://uni.edu.co/item.php?id=1",
                "--yes",
                "--max-urls",
                "3",
                "--rotate",
            ]
        )
        self.assertTrue(args.yes)
        self.assertTrue(args.rotate)
        self.assertEqual(args.max_urls, 3)
        self.assertEqual(args.url, ["https://uni.edu.co/item.php?id=1"])

        finding = {
            "id": 1,
            "url": "https://uni.edu.co/item.php?id=1",
            "domain": "uni.edu.co",
            "parametro": "id",
            "estado": ESTADO_VULN,
            "dbms": "MySQL",
            "confianza": "alta",
            "error_detectado": "MySQL: syntax error",
            "http_status": 200,
            "contacto": "security@uni.edu.co",
            "organizacion": "Universidad",
            "registrar": "Registrador",
            "whois_country": "CO",
            "security_txt": "",
            "enrichment_source": "python-whois",
            "estado_reporte": "sin_reporte",
            "created_at": "2026-01-01T00:00:00-05:00",
        }
        scan = {
            "id": 1,
            "created_at": "2026-01-01T00:00:00-05:00",
            "country": "Colombia",
            "domain_type": "Educativo (edu)",
            "keywords": "",
            "dork_used": "site:edu.co inurl:id=",
            "status": "completado",
            "urls_found": 1,
        }
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "hallazgos.csv"
            _write_csv(csv_path, [finding])
            csv_text = csv_path.read_text(encoding="utf-8-sig")
            self.assertIn("Motor", csv_text)
            self.assertIn("MySQL", csv_text)

            report_path = Path(tmp) / "caza.md"
            _write_report(report_path, scan, [finding])
            self.assertIn("Caza #1", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
