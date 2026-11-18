"""Pruebas de la fase opcional de verificación activa con SQLMap."""
from __future__ import annotations

import queue
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from cli import _write_csv, build_parser
from config import SQLMAP_TIMEOUT, SQLMAP_WORKERS
from core.orchestrator import HuntOrchestrator, HuntParams
from core.sqli_scanner import ESTADO_VULN
from core.sqlmap_runner import (
    SQLMAP_CLEAN,
    SQLMAP_ERROR,
    SQLMAP_LABELS,
    SQLMAP_VULNERABLE,
    SqlmapConfig,
    SqlmapRunner,
    TARGET_ALL,
    TARGET_AUTO,
    TARGET_VULNS,
    build_sqlmap_command,
    validate_sqlmap_config,
)
from database.db_manager import DatabaseManager


def _make_executable(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


class SqlmapCommandTests(unittest.TestCase):
    def test_command_matches_user_specification(self) -> None:
        """proxychains4 sqlmap -u URL --batch --random-agent --dbs --output-dir"""
        config = SqlmapConfig(
            enabled=True,
            sqlmap_bin="sqlmap",
            proxychains_bin="proxychains4",
            use_proxychains=True,
            enumerate_dbs=True,
            output_dir=Path("/tmp/dh"),
        )
        url = "https://dominio.com/item.php?id=1"
        command = build_sqlmap_command(url, config)
        self.assertEqual(
            command,
            [
                "proxychains4",
                "sqlmap",
                "-u",
                url,
                "--batch",
                "--random-agent",
                "--dbs",
                "--output-dir",
                "/tmp/dh",
            ],
        )

    def test_command_without_optional_wrappers(self) -> None:
        config = SqlmapConfig(
            enabled=True,
            use_proxychains=False,
            enumerate_dbs=False,
            random_agent=False,
        )
        command = build_sqlmap_command("https://x.com/a.php?id=1", config)
        self.assertEqual(command[0], "sqlmap")
        self.assertNotIn("proxychains4", command)
        self.assertNotIn("--dbs", command)
        self.assertNotIn("--random-agent", command)
        self.assertIn("--batch", command)

    def test_extra_flags_go_last(self) -> None:
        config = SqlmapConfig(
            enabled=True,
            extra_flags=("--level", "2", "--risk", "1"),
            output_dir=None,
        )
        command = build_sqlmap_command("https://x.com/a.php?id=1", config)
        self.assertEqual(command[-4:], ["--level", "2", "--risk", "1"])
        self.assertNotIn("--output-dir", command)

    def test_command_with_internal_threads(self) -> None:
        config = SqlmapConfig(enabled=True, sqlmap_threads=4)
        command = build_sqlmap_command("https://x.com/a.php?id=1", config)
        self.assertIn("--threads=4", command)

    def test_url_stays_a_single_argument(self) -> None:
        """Sin shell: la URL con comillas no puede inyectar comandos."""
        config = SqlmapConfig(enabled=True)
        url = "https://x.com/a.php?id=1' AND '1'='1 -- &x= y"
        command = build_sqlmap_command(url, config)
        self.assertIn(url, command)

    def test_config_defaults_and_clamps(self) -> None:
        config = SqlmapConfig()
        self.assertFalse(config.enabled)
        self.assertFalse(config.use_proxychains)
        self.assertFalse(config.enumerate_dbs)
        self.assertTrue(config.random_agent)
        self.assertEqual(config.targets, TARGET_AUTO)
        self.assertEqual(config.workers, SQLMAP_WORKERS)
        self.assertEqual(config.sqlmap_threads, 1)
        self.assertEqual(config.timeout, SQLMAP_TIMEOUT)

        clamped = SqlmapConfig(workers=0, timeout=1, targets="otro", sqlmap_threads=0)
        self.assertEqual(clamped.workers, 1)
        self.assertEqual(clamped.sqlmap_threads, 1)
        self.assertEqual(clamped.timeout, 30)
        self.assertEqual(clamped.targets, TARGET_AUTO)

        capped = SqlmapConfig(workers=99)
        self.assertEqual(capped.workers, 8)


class SqlmapValidationTests(unittest.TestCase):
    def test_missing_binaries_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "no-existe")
            config = SqlmapConfig(
                enabled=True, sqlmap_bin=missing, use_proxychains=True,
                proxychains_bin=missing,
            )
            problems = validate_sqlmap_config(config)
            self.assertEqual(len(problems), 2)
            self.assertIn("SQLMap", problems[0])
            self.assertIn("proxychains", problems[1])

    def test_proxychains_not_requested_needs_no_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sqlmap_bin = _make_executable(Path(tmp), "sqlmap", "exit 0")
            config = SqlmapConfig(
                enabled=True,
                sqlmap_bin=str(sqlmap_bin),
                use_proxychains=False,
                proxychains_bin="/definitivamente/no/existe",
            )
            self.assertEqual(validate_sqlmap_config(config), [])

    def test_valid_config_has_no_problems(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sqlmap_bin = _make_executable(Path(tmp), "sqlmap", "exit 0")
            proxy_bin = _make_executable(Path(tmp), "proxychains4", "exit 0")
            config = SqlmapConfig(
                enabled=True,
                sqlmap_bin=str(sqlmap_bin),
                proxychains_bin=str(proxy_bin),
                use_proxychains=True,
            )
            self.assertEqual(validate_sqlmap_config(config), [])


class SqlmapRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.db = DatabaseManager(self.base / "db.sqlite")
        self.scan_id = self.db.create_scan("dork de prueba")
        self.vuln_id = self.db.add_finding(
            self.scan_id,
            "https://vuln.com/item.php?id=1",
            parametro="id",
            estado=ESTADO_VULN,
        )
        self.other_id = self.db.add_finding(
            self.scan_id,
            "https://other.com/page.php?q=2",
            parametro="q",
            estado="pendiente",
        )
        self.events: list[dict] = []

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _config(self, script_body: str, **overrides) -> SqlmapConfig:
        fake = _make_executable(self.base, "fake-sqlmap", script_body)
        defaults = dict(
            enabled=True,
            sqlmap_bin=str(fake),
            workers=2,
            timeout=60,
            output_dir=self.base / "sqlmap_out",
        )
        defaults.update(overrides)
        return SqlmapConfig(**defaults)

    def _runner(self, config: SqlmapConfig) -> SqlmapRunner:
        return SqlmapRunner(config, self.db, self.events.append, threading.Event())

    def _sqlmap_events(self) -> list[dict]:
        return [e for e in self.events if e.get("type") == "sqlmap"]

    # ------------------------------------------------------------------
    def test_runner_detects_vulnerable_and_persists(self) -> None:
        config = self._config(
            "echo \"GET parameter 'id' is vulnerable. Do you want to keep?\"\n"
            "echo \"sqlmap identified the following injection\"\n"
            "exit 0\n"
        )
        counts = self._runner(config).run(
            [{"finding_id": self.vuln_id, "url": "https://vuln.com/item.php?id=1"}]
        )
        self.assertEqual(counts[SQLMAP_VULNERABLE], 1)
        finding = self.db.get_finding(self.vuln_id)
        self.assertEqual(finding["sqlmap_estado"], SQLMAP_VULNERABLE)
        self.assertTrue(finding["sqlmap_output"])
        self.assertTrue(Path(finding["sqlmap_output"]).read_text(
            encoding="utf-8").startswith("GET parameter"))
        event = self._sqlmap_events()[0]
        self.assertEqual(event["finding_id"], self.vuln_id)
        self.assertEqual(event["estado_label"], "Vulnerable")

    def test_runner_marks_clean_when_no_marker(self) -> None:
        config = self._config(
            "echo 'all tested parameters do not appear to be injectable'\nexit 0\n"
        )
        counts = self._runner(config).run(
            [{"finding_id": self.other_id, "url": "https://other.com/page.php?q=2"}]
        )
        self.assertEqual(counts[SQLMAP_CLEAN], 1)
        self.assertEqual(
            self.db.get_finding(self.other_id)["sqlmap_estado"], SQLMAP_CLEAN
        )

    def test_runner_marks_error_on_nonzero_exit(self) -> None:
        config = self._config("echo boom >&2\nexit 3\n")
        counts = self._runner(config).run(
            [{"finding_id": self.vuln_id, "url": "https://vuln.com/item.php?id=1"}]
        )
        self.assertEqual(counts[SQLMAP_ERROR], 1)
        self.assertEqual(
            self.db.get_finding(self.vuln_id)["sqlmap_estado"], SQLMAP_ERROR
        )

    def test_timeout_becomes_error(self) -> None:
        config = self._config("sleep 5\nexit 0\n", timeout=60)
        # Saltamos la validación de __post_init__ para no ralentizar la prueba.
        config.timeout = 1
        counts = self._runner(config).run(
            [{"finding_id": self.vuln_id, "url": "https://vuln.com/item.php?id=1"}]
        )
        self.assertEqual(counts[SQLMAP_ERROR], 1)
        self.assertEqual(
            self.db.get_finding(self.vuln_id)["sqlmap_estado"], SQLMAP_ERROR
        )

    def test_cancel_skips_everything(self) -> None:
        config = self._config("exit 0\n")
        cancel = threading.Event()
        cancel.set()
        runner = SqlmapRunner(config, self.db, self.events.append, cancel)
        counts = runner.run(
            [{"finding_id": self.vuln_id, "url": "https://vuln.com/item.php?id=1"}]
        )
        self.assertEqual(sum(counts.values()), 0)
        self.assertIsNone(self.db.get_finding(self.vuln_id)["sqlmap_estado"])
        self.assertEqual(self._sqlmap_events(), [])

    def test_cancel_terminates_running_process(self) -> None:
        import time

        config = self._config("sleep 5\nexit 0\n")
        cancel = threading.Event()
        events: list[dict] = []
        runner = SqlmapRunner(config, self.db, events.append, cancel)
        result: list[dict] = []

        def target() -> None:
            result.append(
                runner.run(
                    [
                        {
                            "finding_id": self.vuln_id,
                            "url": "https://vuln.com/item.php?id=1",
                        }
                    ]
                )
            )

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(
            e.get("type") == "sqlmap_started" for e in events
        ):
            time.sleep(0.02)
        self.assertTrue(
            any(e.get("type") == "sqlmap_started" for e in events),
            "el proceso debió anunciar su arranque",
        )
        cancel.set()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive(), "la cancelación debió liberar el run")
        estados = [e.get("estado") for e in events if e.get("type") == "sqlmap"]
        self.assertEqual(estados, [SQLMAP_ERROR])

    def test_runner_streams_lines_live(self) -> None:
        config = self._config(
            "echo 'testing connection to the target URL'\n"
            "echo \"GET parameter 'id' is vulnerable.\"\n"
            "echo 'identified the following injection'\n"
            "exit 0\n",
            workers=1,
        )
        counts = self._runner(config).run(
            [{"finding_id": self.vuln_id, "url": "https://vuln.com/item.php?id=1"}]
        )
        self.assertEqual(counts[SQLMAP_VULNERABLE], 1)

        started = [
            e for e in self.events if e.get("type") == "sqlmap_started"
        ]
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0]["worker"], 1)
        self.assertEqual(started[0]["url"], "https://vuln.com/item.php?id=1")

        line_events = [e for e in self.events if e.get("type") == "sqlmap_line"]
        self.assertGreaterEqual(len(line_events), 3)
        self.assertTrue(
            all(e["worker"] == 1 for e in line_events),
            "cada línea lleva el ID de su worker",
        )
        self.assertTrue(
            any("is vulnerable" in e["line"] for e in line_events)
        )

        output = Path(
            self.db.get_finding(self.vuln_id)["sqlmap_output"]
        ).read_text(encoding="utf-8")
        self.assertIn("testing connection to the target URL", output)

    def test_multiple_urls_run_in_parallel(self) -> None:
        config = self._config("exit 0\n", workers=2)
        items = [
            {"finding_id": self.vuln_id, "url": "https://vuln.com/item.php?id=1"},
            {"finding_id": self.other_id, "url": "https://other.com/page.php?q=2"},
        ]
        counts = self._runner(config).run(items)
        self.assertEqual(sum(counts.values()), 2)
        self.assertEqual(len(self._sqlmap_events()), 2)


class DatabaseSqlmapTests(unittest.TestCase):
    def test_set_finding_sqlmap_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "db.sqlite")
            try:
                scan_id = db.create_scan("d")
                finding_id = db.add_finding(
                    scan_id, "https://x.com/a.php?id=1", estado=ESTADO_VULN
                )
                db.set_finding_sqlmap(finding_id, SQLMAP_VULNERABLE, "/ruta/out.txt")
                finding = db.get_finding(finding_id)
                self.assertEqual(finding["sqlmap_estado"], SQLMAP_VULNERABLE)
                self.assertEqual(finding["sqlmap_output"], "/ruta/out.txt")
            finally:
                db.close()

    def test_migration_adds_sqlmap_columns_to_legacy_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.sqlite"
            conn = sqlite3.connect(str(path))
            # Esquema antiguo: sin dbms, confianza, registrar, whois_country,
            # enrichment_source ni las columnas de SQLMap.
            conn.executescript(
                """
                CREATE TABLE findings (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id         INTEGER NOT NULL,
                    url             TEXT NOT NULL,
                    domain          TEXT,
                    parametro       TEXT,
                    estado          TEXT NOT NULL DEFAULT 'pendiente',
                    error_detectado TEXT,
                    evidencia       TEXT,
                    http_status     INTEGER,
                    contacto        TEXT,
                    organizacion    TEXT,
                    security_txt    TEXT,
                    reporte_path    TEXT,
                    estado_reporte  TEXT NOT NULL DEFAULT 'sin_reporte',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );
                """
            )
            conn.commit()
            conn.close()

            db = DatabaseManager(path)
            try:
                columns = {
                    str(row["name"])
                    for row in db._conn.execute("PRAGMA table_info(findings)")
                }
                self.assertIn("sqlmap_estado", columns)
                self.assertIn("sqlmap_output", columns)
                scan_id = db.create_scan("d")
                finding_id = db.add_finding(
                    scan_id, "https://x.com/a.php?id=1", estado=ESTADO_VULN
                )
                db.set_finding_sqlmap(finding_id, SQLMAP_CLEAN, "")
                self.assertEqual(
                    db.get_finding(finding_id)["sqlmap_estado"], SQLMAP_CLEAN
                )
            finally:
                db.close()


class OrchestratorSqlmapTests(unittest.TestCase):
    def test_hunt_params_sqlmap_defaults_to_none(self) -> None:
        params = HuntParams(country="Colombia", domain_type="Educativo (edu)")
        self.assertIsNone(params.sqlmap)

    def test_sqlmap_targets_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "db.sqlite")
            try:
                scan_id = db.create_scan("d")
                vuln_id = db.add_finding(
                    scan_id,
                    "https://vuln.com/item.php?id=1",
                    parametro="id",
                    estado=ESTADO_VULN,
                )
                db.add_finding(
                    scan_id,
                    "https://clean.com/page.php?q=2",
                    parametro="q",
                    estado="pendiente",
                )
                orch = HuntOrchestrator(
                    db,
                    queue.Queue(),
                    threading.Event(),
                    HuntParams(
                        country="Colombia",
                        domain_type="Educativo (edu)",
                        target_urls=["https://vuln.com/item.php?id=1"],
                        do_scan=False,
                        do_enrich=False,
                        sqlmap=SqlmapConfig(enabled=True),
                    ),
                )
                orch.scan_id = scan_id

                self.assertEqual(
                    orch._sqlmap_targets(),
                    [
                        {
                            "finding_id": vuln_id,
                            "url": "https://vuln.com/item.php?id=1",
                        }
                    ],
                )

                orch.sqlmap.targets = TARGET_ALL
                targets = orch._sqlmap_targets()
                self.assertEqual(len(targets), 2)
                self.assertIn(vuln_id, {t["finding_id"] for t in targets})
            finally:
                db.close()

    def test_sqlmap_targets_auto_fallback_when_no_vulns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "db.sqlite")
            try:
                scan_id = db.create_scan("d")
                db.add_finding(
                    scan_id,
                    "https://a.com/x.php?id=1",
                    parametro="id",
                    estado="ok",
                )
                db.add_finding(
                    scan_id,
                    "https://b.com/y.php?q=2",
                    parametro="q",
                    estado="pendiente",
                )
                orch = HuntOrchestrator(
                    db,
                    queue.Queue(),
                    threading.Event(),
                    HuntParams(
                        country="Colombia",
                        domain_type="Educativo (edu)",
                        target_urls=["https://a.com/x.php?id=1"],
                        do_scan=False,
                        do_enrich=False,
                        sqlmap=SqlmapConfig(enabled=True),  # auto por defecto
                    ),
                )
                orch.scan_id = scan_id

                # Sin posibles vulns: el modo auto usa el respaldo con todas
                # las URLs que tengan parámetros.
                targets = orch._sqlmap_targets()
                self.assertEqual(len(targets), 2)
                self.assertEqual(
                    {t["url"] for t in targets},
                    {"https://a.com/x.php?id=1", "https://b.com/y.php?q=2"},
                )

                # En modo estricto (solo vulns) y sin hallazgos: nada.
                orch.sqlmap.targets = TARGET_VULNS
                self.assertEqual(orch._sqlmap_targets(), [])
            finally:
                db.close()


class CliSqlmapFlagsTests(unittest.TestCase):
    def test_flags_parse(self) -> None:
        args = build_parser().parse_args(
            [
                "--url", "https://uni.edu.co/item.php?id=1",
                "--yes",
                "--sqlmap",
                "--sqlmap-all",
                "--sqlmap-dbs",
                "--proxychains",
                "--sqlmap-workers", "3",
                "--sqlmap-threads", "5",
                "--sqlmap-bin", "/usr/bin/sqlmap",
                "--sqlmap-timeout", "120",
            ]
        )
        self.assertTrue(args.sqlmap)
        self.assertTrue(args.sqlmap_all)
        self.assertTrue(args.sqlmap_dbs)
        self.assertTrue(args.proxychains)
        self.assertEqual(args.sqlmap_workers, 3)
        self.assertEqual(args.sqlmap_threads, 5)
        self.assertEqual(args.sqlmap_bin, "/usr/bin/sqlmap")
        self.assertEqual(args.sqlmap_timeout, 120)

    def test_flags_default_off(self) -> None:
        args = build_parser().parse_args(["--url", "https://uni.edu.co/x.php?id=1"])
        self.assertFalse(args.sqlmap)
        self.assertFalse(args.sqlmap_all)
        self.assertFalse(args.sqlmap_dbs)
        self.assertFalse(args.proxychains)
        self.assertEqual(args.sqlmap_workers, SQLMAP_WORKERS)
        self.assertEqual(args.sqlmap_threads, 1)
        self.assertEqual(args.sqlmap_timeout, SQLMAP_TIMEOUT)

    def test_csv_includes_sqlmap_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "hallazgos.csv"
            finding = {
                "id": 1,
                "url": "https://uni.edu.co/item.php?id=1",
                "domain": "uni.edu.co",
                "parametro": "id",
                "estado": ESTADO_VULN,
                "dbms": "MySQL",
                "confianza": "alta",
                "error_detectado": "syntax error",
                "http_status": 200,
                "sqlmap_estado": SQLMAP_VULNERABLE,
                "created_at": "2026-01-01T00:00:00-05:00",
            }
            _write_csv(csv_path, [finding])
            text = csv_path.read_text(encoding="utf-8-sig")
            self.assertIn("SQLMap", text)
            self.assertIn(SQLMAP_LABELS[SQLMAP_VULNERABLE], text)


if __name__ == "__main__":
    unittest.main()
