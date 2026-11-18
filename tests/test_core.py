"""Pruebas de los módulos que no dependen de Tkinter.

Ejecutar desde la raíz del proyecto:

    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.dork_engine import (
    COUNTRIES,
    COUNTRY_CATEGORIES,
    KEYWORD_SUGGESTIONS,
    VULNERABLE_PARAMS,
    DorkEngine,
    suggest_keywords,
)
from core.report_generator import DISCLAIMER_NOTE, ReportGenerator
from core.search_engine import SearchEngine, decode_ddg_link, translate_query
from core.sqli_scanner import (
    ESTADO_VULN,
    PassiveScanner,
    detect_error,
    extract_evidence,
)
from core.whois_lookup import _parse_security_txt, root_domain
from database.db_manager import DatabaseManager


class DorkEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DorkEngine()

    def test_colombia_educativo(self) -> None:
        dorks = self.engine.build("Colombia", "Educativo (edu)", limit=2)
        self.assertEqual(len(dorks), 2)
        self.assertIn("site:edu.co", dorks[0].query)
        self.assertIn("inurl:id=", dorks[0].query)
        self.assertEqual(dorks[0].scope_suffix, "edu.co")

    def test_keywords_use_intext(self) -> None:
        dork = self.engine.preview("México", "Gubernamental (gov)", "pagos en línea")
        self.assertIn("site:gob.mx", dork)
        self.assertIn('intext:"pagos en línea"', dork)

    def test_multiple_keywords_become_separate_intext(self) -> None:
        dork = self.engine.preview(
            "Colombia", "Educativo (edu)", "matrícula, pagos, Matrícula"
        )
        self.assertIn("intext:matrícula intext:pagos", dork)
        self.assertNotIn("matrícula,", dork)
        self.assertEqual(dork.count("intext:"), 2)

    def test_manual_dork(self) -> None:
        dorks = self.engine.build(
            "Colombia",
            "Educativo (edu)",
            manual_dork='site:edu.co inurl:"index.php?id="',
        )
        self.assertEqual(len(dorks), 1)
        self.assertEqual(dorks[0].scope_suffix, "edu.co")

    def test_international_requires_manual(self) -> None:
        with self.assertRaises(ValueError):
            self.engine.build("Todos / Internacional", "Todos")

    def test_gov_override(self) -> None:
        self.assertEqual(
            self.engine.suffix_for("Uruguay", "Gubernamental (gov)"), "gub.uy"
        )
        self.assertEqual(
            self.engine.suffix_for("Colombia", "Gubernamental (gob)"), "gob.co"
        )

    def test_countries_are_categorized(self) -> None:
        categorized = [
            country
            for group in COUNTRY_CATEGORIES.values()
            for country in group
        ]
        self.assertEqual(len(categorized), len(set(categorized)))
        self.assertEqual(set(categorized), set(COUNTRIES))
        self.assertGreaterEqual(len(COUNTRIES), 70)
        self.assertIn("Colombia", COUNTRY_CATEGORIES["Latinoamérica"])
        self.assertIn("Francia", COUNTRY_CATEGORIES["Europa"])
        self.assertIn("Japón", COUNTRY_CATEGORIES["Asia y Oceanía"])
        self.assertIn("Kenia", COUNTRY_CATEGORIES["África y Oriente Medio"])

    def test_new_country_suffixes(self) -> None:
        self.assertEqual(
            self.engine.suffix_for("Francia", "Gubernamental (gov)"), "gouv.fr"
        )
        self.assertEqual(
            self.engine.suffix_for("Canadá", "Gubernamental (gov)"), "gc.ca"
        )
        self.assertEqual(
            self.engine.suffix_for("Nueva Zelanda", "Gubernamental (gov)"),
            "govt.nz",
        )
        self.assertEqual(
            self.engine.suffix_for("Suiza", "Gubernamental (gov)"), "admin.ch"
        )
        self.assertEqual(
            self.engine.suffix_for("Japón", "Educativo (edu)"), "edu.jp"
        )

    def test_keyword_suggestions(self) -> None:
        self.assertIn("matrícula", suggest_keywords("matri"))
        self.assertIn("matrícula", suggest_keywords("MATRICULA"))
        self.assertEqual(suggest_keywords("zzz"), [])
        self.assertEqual(len(suggest_keywords("", limit=4)), 4)
        self.assertLessEqual(len(suggest_keywords("a", limit=3)), 3)
        self.assertTrue(KEYWORD_SUGGESTIONS)

    def test_depth_allows_more_dorks(self) -> None:
        dorks = self.engine.build("Colombia", "Educativo (edu)", limit=24)
        self.assertEqual(len(dorks), 24)
        self.assertGreaterEqual(len(VULNERABLE_PARAMS), 48)
        self.assertEqual(len(set(VULNERABLE_PARAMS)), len(VULNERABLE_PARAMS))


class RootDomainTests(unittest.TestCase):
    def test_common_cases(self) -> None:
        self.assertEqual(root_domain("https://www.uni.edu.co/x?id=1"), "uni.edu.co")
        self.assertEqual(root_domain("www.example.com"), "example.com")
        self.assertEqual(root_domain("https://a.b.example.co.uk/"), "example.co.uk")
        self.assertEqual(root_domain("https://portal.gov.co/"), "portal.gov.co")
        self.assertEqual(root_domain("https://www.gov.co/"), "gov.co")
        self.assertEqual(root_domain("127.0.0.1"), "127.0.0.1")

    def test_security_txt_parser(self) -> None:
        text = (
            "# comentario\n"
            "Contact: mailto:security@uni.edu.co\n"
            "Contact: https://uni.edu.co/report\n"
            "Expires: 2030-01-01T00:00:00Z\n"
        )
        self.assertEqual(
            _parse_security_txt(text),
            ["security@uni.edu.co", "https://uni.edu.co/report"],
        )


class DatabaseTests(unittest.TestCase):
    def test_crud(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            try:
                scan_id = db.create_scan("site:edu.co inurl:id=", "Colombia", "edu")
                finding_id = db.add_finding(
                    scan_id,
                    "https://uni.edu.co/item.php?id=1",
                    domain="uni.edu.co",
                    parametro="id",
                    estado="ok",
                )
                db.update_finding(
                    finding_id,
                    estado=ESTADO_VULN,
                    evidencia="You have an error in your SQL syntax",
                    contacto="security@uni.edu.co",
                )
                finding = db.get_finding(finding_id)
                self.assertIsNotNone(finding)
                assert finding is not None
                self.assertEqual(finding["estado"], ESTADO_VULN)
                self.assertEqual(finding["contacto"], "security@uni.edu.co")

                # El upsert no debe duplicar (scan, url, parámetro).
                again = db.add_finding(
                    scan_id,
                    "https://uni.edu.co/item.php?id=1",
                    domain="uni.edu.co",
                    parametro="id",
                )
                self.assertEqual(again, finding_id)
                self.assertEqual(len(db.list_findings(scan_id)), 1)
                self.assertEqual(db.summary(scan_id)[ESTADO_VULN], 1)

                db.set_setting("disclaimer_accepted_version", "1.0")
                self.assertEqual(
                    db.get_setting("disclaimer_accepted_version"), "1.0"
                )
                db.finish_scan(scan_id, "completado", 1)
                self.assertEqual(db.get_scan(scan_id)["status"], "completado")
            finally:
                db.close()


class ReportTests(unittest.TestCase):
    def test_markdown_and_html(self) -> None:
        finding = {
            "url": "https://uni.edu.co/item.php?id=1",
            "domain": "uni.edu.co",
            "parametro": "id",
            "evidencia": "You have an error in your SQL syntax",
            "error_detectado": "MySQL: You have an error in your SQL syntax",
            "http_status": 200,
            "contacto": "security@uni.edu.co",
            "organizacion": "Universidad de Prueba",
            "security_txt": "https://uni.edu.co/.well-known/security.txt",
            "created_at": "2026-01-01T00:00:00-05:00",
        }
        with tempfile.TemporaryDirectory() as tmp:
            generator = ReportGenerator(tmp)
            md_path = generator.generate(finding, "md")
            html_path = generator.generate(finding, "html")

            md = md_path.read_text(encoding="utf-8")
            self.assertIn(
                "[Security Report] Posible SQL Injection en "
                "https://uni.edu.co/item.php?id=1",
                md,
            )
            self.assertIn("Tipo de Vulnerabilidad: SQL Injection (Error-Based)", md)
            self.assertIn(DISCLAIMER_NOTE, md)
            self.assertIn("security@uni.edu.co", md)

            html = html_path.read_text(encoding="utf-8")
            self.assertIn("<html", html)
            self.assertIn("SQL Injection (Error-Based)", html)
            self.assertIn("security@uni.edu.co", html)
            self.assertIn(DISCLAIMER_NOTE, html)


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if "%27" in self.path or "'" in self.path:
                    body = (
                        "<html><body>Warning: mysql_fetch_array() expects "
                        "parameter 1 to be resource. You have an error in "
                        "your SQL syntax near '1''</body></html>"
                    )
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

    def test_detects_error_based_sqli(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(
            f"http://127.0.0.1:{self.port}/item.php?id=1"
        )
        self.assertEqual(result.estado, ESTADO_VULN)
        self.assertEqual(result.parametro, "id")
        self.assertIn("mysql_fetch_array", result.evidencia.lower())

    def test_skips_destructive_params(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(
            f"http://127.0.0.1:{self.port}/logout.php?action=delete"
        )
        self.assertEqual(result.estado, "omitido")

    def test_signature_helpers(self) -> None:
        engine, match = detect_error("You have an error in your SQL syntax")
        self.assertEqual(engine, "MySQL")
        self.assertIsNotNone(match)
        evidence = extract_evidence(
            "<p>You have an error in your SQL syntax near '1'</p>", match
        )
        self.assertIn("SQL syntax", evidence)
        self.assertNotIn("<p>", evidence)


class SearchHelperTests(unittest.TestCase):
    def test_translate(self) -> None:
        self.assertEqual(
            translate_query('site:edu.co intext:"pagos en linea" inurl:id='),
            'site:edu.co "pagos en linea" inurl:id=',
        )
        self.assertEqual(translate_query("ext:php id"), "filetype:php id")

    def test_decode_redirect(self) -> None:
        href = (
            "//duckduckgo.com/l/?uddg=https%3A%2F%2Funi.edu.co%2Fitem.php%3Fid%3D1"
        )
        self.assertEqual(
            decode_ddg_link(href), "https://uni.edu.co/item.php?id=1"
        )

    def test_clean_filters_duplicates_and_binaries(self) -> None:
        engine = SearchEngine(delay=0)
        urls = [
            "https://uni.edu.co/item.php?id=1",
            "https://uni.edu.co/item.php?id=1",
            "https://uni.edu.co/manual.pdf",
            "https://uni.edu.co/manual.pdf?download=1",
            "ftp://uni.edu.co/file",
            "https://duckduckgo.com/y.js",
            "https://otro.edu.co/index.php?page=2",
        ]
        cleaned = engine._clean(urls, 10)
        self.assertEqual(
            cleaned,
            [
                "https://uni.edu.co/item.php?id=1",
                "https://uni.edu.co/manual.pdf?download=1",
                "https://otro.edu.co/index.php?page=2",
            ],
        )


if __name__ == "__main__":
    unittest.main()
