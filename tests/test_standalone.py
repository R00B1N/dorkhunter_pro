"""Pruebas de la copia mono-script (standalone/dorkhunter_pro_mono.py).

La copia se genera a partir de los módulos del proyecto; aquí se verifica que
existe, compila, se importa limpio y expone la misma API que los módulos
originales (paridad). No requiere Tkinter ni red.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

MONO_PATH = BASE_DIR / "standalone" / "dorkhunter_pro_mono.py"


def load_mono():
    spec = importlib.util.spec_from_file_location(
        "dorkhunter_pro_mono", MONO_PATH
    )
    module = importlib.util.module_from_spec(spec)
    # Registrar antes de ejecutar: los @dataclass resuelven su módulo vía
    # sys.modules y fallarían sin este paso.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class MonoScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not MONO_PATH.is_file():
            raise unittest.SkipTest(
                "standalone/dorkhunter_pro_mono.py no existe (regenerar)"
            )
        cls.source = MONO_PATH.read_text(encoding="utf-8")

    def test_compiles_as_single_file(self) -> None:
        compile(self.source, str(MONO_PATH), "exec")

    def test_single_main_guard(self) -> None:
        self.assertEqual(self.source.count('if __name__ == "__main__":'), 1)

    def test_api_parity_with_modules(self) -> None:
        mono = load_mono()
        for name in (
            "main",
            "build_parser",
            "load_url_file",
            "CSV_FIELDS",
            "DorkEngine",
            "SearchEngine",
            "PassiveScanner",
            "ScanResult",
            "detect_waf",
            "detect_error",
            "HuntOrchestrator",
            "HuntParams",
            "domain_allowed",
            "parse_domain_list",
            "normalize_target_urls",
            "collect_domain_urls",
            "SqlmapConfig",
            "SqlmapRunner",
            "preset_extra_flags",
            "parse_extra_flags",
            "validate_sqlmap_config",
            "ReportGenerator",
            "DatabaseManager",
            "COUNTRY_CATEGORIES",
            "DOMAIN_TYPES",
            "APP_VERSION",
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(mono, name))

    def test_workers_cap_is_eight(self) -> None:
        mono = load_mono()
        self.assertEqual(mono.SqlmapConfig(workers=99).workers, 8)

    def test_csv_fields_include_waf(self) -> None:
        mono = load_mono()
        self.assertIn("WAF", mono.CSV_FIELDS)

    def test_parser_new_flags(self) -> None:
        mono = load_mono()
        args = mono.build_parser().parse_args(
            [
                "--url-file", "u.txt",
                "--domain-sources", "uni.edu.co",
                "--allow-domains", "uni.edu.co",
                "--deny-domains", "otro.com",
                "--sqlmap-preset", "profundo",
                "--sqlmap-flags=--forms",
                "--sqlmap-workers", "8",
            ]
        )
        self.assertEqual(args.url_file, "u.txt")
        self.assertEqual(args.sqlmap_workers, 8)

    def test_functions_behave_like_original(self) -> None:
        mono = load_mono()
        self.assertEqual(mono.detect_waf({"cf-ray": "x"}, ""), "Cloudflare")
        self.assertTrue(mono.domain_allowed("a.uni.edu.co", ["uni.edu.co"], []))
        self.assertFalse(mono.domain_allowed("x.com", ["uni.edu.co"], []))
        self.assertEqual(
            mono.preset_extra_flags("profundo"), ("--level", "3", "--risk", "2")
        )
        self.assertEqual(
            mono.normalize_target_urls(["a.com/x.php?id=1"]),
            ["https://a.com/x.php?id=1"],
        )

    def test_scope_is_not_modified_by_usage(self) -> None:
        """El config del mono apunta a data/reports junto al propio script."""
        mono = load_mono()
        self.assertIn("standalone", str(mono.DATA_DIR))


if __name__ == "__main__":
    unittest.main()
