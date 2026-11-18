"""Pruebas del lote de potencia: WAF, alcance por dominios, fuentes pasivas,
presets de SQLMap, importación de .txt y migración de columna ``waf``."""
from __future__ import annotations

import csv
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

from cli import CSV_FIELDS, build_parser, load_url_file
from config import MAX_URLS_PER_HUNT
from core import orchestrator as orchestrator_module
from core.orchestrator import (
    HuntOrchestrator,
    HuntParams,
    domain_allowed,
    normalize_target_urls,
    parse_domain_list,
)
from core.passive_sources import (
    filter_param_urls,
    parse_crtsh,
    parse_otx,
    parse_wayback_cdx,
)
from core.sqli_scanner import (
    ESTADO_BLOQUEADO,
    ESTADO_OK,
    ESTADO_VULN,
    PassiveScanner,
    ScanResult,
    detect_waf,
)
from core.sqlmap_runner import (
    SqlmapConfig,
    build_sqlmap_command,
    parse_extra_flags,
    preset_extra_flags,
)
from database.db_manager import DatabaseManager


class WafDetectionTests(unittest.TestCase):
    def test_cloudflare_by_header(self) -> None:
        self.assertEqual(
            detect_waf({"Server": "cloudflare", "Cf-Ray": "abc"}, ""), "Cloudflare"
        )
        self.assertEqual(detect_waf({"Cf-Ray": "abc"}, ""), "Cloudflare")

    def test_known_wafs(self) -> None:
        self.assertEqual(detect_waf({"x-amzn-waf-action": "block"}, ""), "AWS WAF")
        self.assertEqual(detect_waf({"X-Sucuri-ID": "1"}, ""), "Sucuri")
        self.assertEqual(detect_waf({"X-IInfo": "9"}, ""), "Imperva")
        self.assertEqual(detect_waf({"Server": "AkamaiGHost"}, ""), "Akamai")
        self.assertEqual(
            detect_waf({"Cookie": "BIGipServer=pool1"}, ""), "F5 BIG-IP"
        )
        self.assertEqual(detect_waf({}, "blocked by Mod_Security"), "ModSecurity")
        self.assertEqual(
            detect_waf({}, "Your request was blocked by Wordfence firewall"),
            "Wordfence",
        )
        self.assertEqual(detect_waf({"X-Protected-By": "wallarm"}, ""), "Wallarm")

    def test_no_waf(self) -> None:
        self.assertEqual(detect_waf({"Server": "nginx"}, "hola mundo"), "")
        self.assertEqual(detect_waf(None, ""), "")
        self.assertEqual(detect_waf({}, ""), "")


class WafScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                error = (
                    "You have an error in your SQL syntax near '1' "
                    "(MySQL server version)"
                )
                if self.path.startswith("/blocked"):
                    body, status = "<html>Access denied</html>", 403
                elif self.path.startswith("/vuln"):
                    injected = "%27" in self.path or "'" in self.path
                    body = error if injected else "<html><body>OK</body></html>"
                    status = 200
                else:
                    body, status = "<html><body>OK</body></html>", 200
                data = body.encode("utf-8")
                self.send_response_only(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Server", "cloudflare")
                self.send_header("Cf-Ray", "abc123")
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

    def test_waf_tagged_on_clean_result(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(f"http://127.0.0.1:{self.port}/page.php?id=1")
        self.assertEqual(result.estado, ESTADO_OK)
        self.assertEqual(result.waf, "Cloudflare")
        self.assertIn("WAF detectado: Cloudflare", result.mensaje)

    def test_waf_tagged_on_vuln_result(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(f"http://127.0.0.1:{self.port}/vuln.php?id=1")
        self.assertEqual(result.estado, ESTADO_VULN)
        self.assertEqual(result.waf, "Cloudflare")

    def test_waf_named_in_blocked_message(self) -> None:
        scanner = PassiveScanner(delay=0)
        result = scanner.scan_url(f"http://127.0.0.1:{self.port}/blocked.php?id=1")
        self.assertEqual(result.estado, ESTADO_BLOQUEADO)
        self.assertEqual(result.waf, "Cloudflare")
        self.assertIn("HTTP 403 (WAF: Cloudflare)", result.mensaje)


class DomainScopeTests(unittest.TestCase):
    def test_parse_domain_list(self) -> None:
        self.assertEqual(
            parse_domain_list("uni.edu.co, gov.co;*.otro.com\nlast.org"),
            ["uni.edu.co", "gov.co", "otro.com", "last.org"],
        )
        self.assertEqual(parse_domain_list(""), [])
        self.assertEqual(parse_domain_list("  ,  "), [])

    def test_domain_allowed_suffix_and_deny_wins(self) -> None:
        allow = ["uni.edu.co"]
        deny = ["lab.uni.edu.co"]
        self.assertTrue(domain_allowed("uni.edu.co", allow, deny))
        self.assertTrue(domain_allowed("www.uni.edu.co", allow, deny))
        self.assertFalse(domain_allowed("otro.edu.co", allow, deny))
        # La denylist gana aunque el host esté en la allowlist.
        self.assertFalse(domain_allowed("lab.uni.edu.co", allow, deny))
        # Sin allowlist todo pasa salvo lo excluido.
        self.assertFalse(domain_allowed("otro.edu.co", [], ["otro.edu.co"]))
        self.assertTrue(domain_allowed("otro.edu.co", [], ["otra.com"]))
        self.assertTrue(domain_allowed("cualquiera.com", [], []))

    def test_manual_targets_respect_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            try:
                params = HuntParams(
                    country="Manual",
                    domain_type="URL directa",
                    target_urls=[
                        "https://uni.edu.co/item.php?id=1",
                        "https://otro.com/x.php?id=2",
                    ],
                    do_scan=False,
                    do_enrich=False,
                    allow_domains=["uni.edu.co"],
                )
                orchestrator = HuntOrchestrator(
                    db, queue.Queue(), threading.Event(), params
                )
                orchestrator._execute()
                self.assertEqual(
                    orchestrator._urls, ["https://uni.edu.co/item.php?id=1"]
                )
            finally:
                db.close()

    def test_all_manual_targets_out_of_scope_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            try:
                params = HuntParams(
                    country="Manual",
                    domain_type="URL directa",
                    target_urls=["https://otro.com/x.php?id=2"],
                    do_scan=False,
                    do_enrich=False,
                    allow_domains=["uni.edu.co"],
                )
                orchestrator = HuntOrchestrator(
                    db, queue.Queue(), threading.Event(), params
                )
                with self.assertRaises(ValueError):
                    orchestrator._execute()
                self.assertIsNone(orchestrator.scan_id)
            finally:
                db.close()

    def test_hunt_params_scope_defaults(self) -> None:
        params = HuntParams(country="Colombia", domain_type="Todos")
        self.assertEqual(params.allow_domains, [])
        self.assertEqual(params.deny_domains, [])
        self.assertEqual(params.max_urls, MAX_URLS_PER_HUNT)


class PassiveSourceParserTests(unittest.TestCase):
    def test_parse_wayback_cdx(self) -> None:
        rows = [
            ["original"],
            ["http://uni.edu.co/item.php?id=1"],
            ["http://uni.edu.co/list.php?page=2"],
            ["http://uni.edu.co/solo.txt"],
        ]
        self.assertEqual(
            parse_wayback_cdx(rows),
            [
                "http://uni.edu.co/item.php?id=1",
                "http://uni.edu.co/list.php?page=2",
                "http://uni.edu.co/solo.txt",
            ],
        )
        # Filas más cortas que la cabecera se ignoran sin explotar.
        self.assertEqual(
            parse_wayback_cdx([["original", "timestamp"], ["http://a.com/z.php?q=1"]]),
            ["http://a.com/z.php?q=1"],
        )
        self.assertEqual(parse_wayback_cdx([]), [])
        self.assertEqual(parse_wayback_cdx([["timestamp"]]), [])
        self.assertEqual(parse_wayback_cdx(None), [])

    def test_parse_otx(self) -> None:
        payload = {
            "url_list": [
                {"url": "http://uni.edu.co/a.php?id=1"},
                {"url": ""},
                "http://uni.edu.co/b.php?x=2",
            ]
        }
        self.assertEqual(
            parse_otx(payload),
            ["http://uni.edu.co/a.php?id=1", "http://uni.edu.co/b.php?x=2"],
        )
        self.assertEqual(parse_otx([{"url": "http://a.com/c.php?z=3"}]),
                         ["http://a.com/c.php?z=3"])
        self.assertEqual(parse_otx(None), [])
        self.assertEqual(parse_otx({"error": "x"}), [])

    def test_parse_crtsh(self) -> None:
        rows = [
            {"name_value": "*.uni.edu.co\nwww.uni.edu.co"},
            {"name_value": "mail.uni.edu.co"},
            {"name_value": "uni.edu.co"},
            "no-dict",
        ]
        self.assertEqual(
            parse_crtsh(rows),
            ["mail.uni.edu.co", "uni.edu.co", "www.uni.edu.co"],
        )
        self.assertEqual(parse_crtsh(None), [])

    def test_filter_param_urls(self) -> None:
        urls = [
            "http://a.com/x.php?id=1",
            "http://a.com/x.php?id=1",  # duplicada
            "https://b.com/y.php?page=2#frag",
            "/relative.php?id=3",
            "https://c.com/sin-parametros",
            "sin-esquema.com/z.php?id=4",
            "",
        ]
        self.assertEqual(
            filter_param_urls(urls),
            [
                "http://a.com/x.php?id=1",
                "https://b.com/y.php?page=2#frag",
            ],
        )


class SqlmapPresetTests(unittest.TestCase):
    def test_preset_flags(self) -> None:
        self.assertEqual(preset_extra_flags("seguro"), ())
        self.assertEqual(
            preset_extra_flags("estandar"), ("--level", "2", "--risk", "1")
        )
        self.assertEqual(
            preset_extra_flags("profundo"), ("--level", "3", "--risk", "2")
        )
        # Alias con tilde y mayúsculas.
        self.assertEqual(
            preset_extra_flags("Estándar"), ("--level", "2", "--risk", "1")
        )
        self.assertEqual(preset_extra_flags("desconocido"), ())

    def test_parse_extra_flags(self) -> None:
        self.assertEqual(parse_extra_flags(""), ())
        self.assertEqual(parse_extra_flags("--forms --titles"), ("--forms", "--titles"))
        self.assertEqual(
            parse_extra_flags('--cookie "a b"'),
            ("--cookie", "a b"),
        )
        self.assertEqual(parse_extra_flags(None), ())
        # Comillas sin cerrar: no debe lanzar excepción.
        self.assertEqual(parse_extra_flags("--forms 'x"), ("--forms", "'x"))

    def test_preset_in_command(self) -> None:
        config = SqlmapConfig(
            enabled=True,
            extra_flags=preset_extra_flags("estandar")
            + parse_extra_flags("--forms"),
        )
        command = build_sqlmap_command("http://a.com/x.php?id=1", config)
        self.assertIn("--level", command)
        self.assertIn("2", command)
        self.assertIn("--risk", command)
        self.assertIn("1", command)
        self.assertIn("--forms", command)

    def test_command_without_preset(self) -> None:
        config = SqlmapConfig(enabled=True)
        command = build_sqlmap_command("http://a.com/x.php?id=1", config)
        self.assertNotIn("--level", command)
        self.assertNotIn("--risk", command)


class UrlFileAndCliTests(unittest.TestCase):
    def test_load_url_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "urls.txt"
            path.write_text(
                "# comentario\n"
                "https://a.com/x.php?id=1\n"
                "\n"
                "  \n"
                "https://b.com/y.php?page=2\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_url_file(path),
                ["https://a.com/x.php?id=1", "https://b.com/y.php?page=2"],
            )

    def test_parser_new_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "--url-file", "urls.txt",
                "--domain-sources", "uni.edu.co, gov.co",
                "--allow-domains", "uni.edu.co,*.gov.co",
                "--deny-domains", "otro.com",
                "--sqlmap-preset", "profundo",
                "--sqlmap-flags", "--forms --titles",
            ]
        )
        self.assertEqual(args.url_file, "urls.txt")
        self.assertEqual(args.domain_sources, "uni.edu.co, gov.co")
        self.assertEqual(args.allow_domains, "uni.edu.co,*.gov.co")
        self.assertEqual(args.deny_domains, "otro.com")
        self.assertEqual(args.sqlmap_preset, "profundo")
        self.assertEqual(args.sqlmap_flags, "--forms --titles")
        # Valores por defecto.
        defaults = parser.parse_args([])
        self.assertEqual(defaults.sqlmap_preset, "seguro")
        self.assertEqual(defaults.sqlmap_flags, "")
        self.assertEqual(defaults.allow_domains, "")
        self.assertEqual(defaults.url_file, None)

    def test_csv_fields_include_waf(self) -> None:
        self.assertIn("WAF", CSV_FIELDS)
        self.assertLess(CSV_FIELDS.index("WAF"), CSV_FIELDS.index("Confianza"))


class WafDatabaseTests(unittest.TestCase):
    def test_waf_column_migrated_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db = DatabaseManager(db_path)
            try:
                with sqlite3.connect(db_path) as conn:
                    columns = {
                        row[1] for row in conn.execute("PRAGMA table_info(findings)")
                    }
                self.assertIn("waf", columns)

                scan_id = db.create_scan("test", "Manual", "Cola")
                finding_id = db.add_finding(
                    scan_id,
                    "https://uni.edu.co/item.php?id=1",
                    estado=ESTADO_OK,
                    waf="Cloudflare",
                )
                finding = db.get_finding(finding_id)
                self.assertEqual(finding.get("waf"), "Cloudflare")
            finally:
                db.close()


class ScannerResultDefaultsTests(unittest.TestCase):
    def test_scan_result_has_waf_default(self) -> None:
        result = ScanResult(url="https://a.com/x.php?id=1", domain="a.com")
        self.assertEqual(result.waf, "")


if __name__ == "__main__":
    unittest.main()
