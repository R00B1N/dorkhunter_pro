"""Pruebas de los motores de búsqueda y del desempate entre proveedores."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config import SEARCH_ENGINES
from core.search_engine import (
    ENGINE_LABELS,
    SearchEngine,
    SUPPORTED_ENGINES,
    _extract_site_host,
    _unwrap_bing_url,
    normalize_engines,
    translate_query_for_engine,
)


class EngineNormalizationTests(unittest.TestCase):
    def test_normalize_defaults_and_auto(self) -> None:
        self.assertEqual(normalize_engines(None), list(SEARCH_ENGINES))
        self.assertEqual(normalize_engines(""), list(SEARCH_ENGINES))
        self.assertEqual(normalize_engines("auto"), list(SEARCH_ENGINES))
        self.assertEqual(normalize_engines("Auto, brave"), list(SEARCH_ENGINES))

    def test_normalize_explicit_engines(self) -> None:
        self.assertEqual(
            normalize_engines("brave,bing,mojeek"),
            ["brave", "bing", "mojeek"],
        )
        self.assertEqual(
            normalize_engines(["Brave", " Bing ", "brave"]),
            ["brave", "bing"],
        )

    def test_normalize_rejects_unknown_engine(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            normalize_engines("brave,desconocido")
        self.assertIn("duckduckgo", str(ctx.exception))

    def test_supported_engines_contain_keys(self) -> None:
        for engine in SUPPORTED_ENGINES:
            self.assertIn(engine, ENGINE_LABELS)


class QueryTranslationTests(unittest.TestCase):
    def test_engines_without_inurl_get_quoted_phrase(self) -> None:
        dork = "site:edu.co inurl:index.php?id="
        for engine in ("bing", "brave", "yahoo", "yandex"):
            with self.subTest(engine=engine):
                self.assertEqual(
                    translate_query_for_engine(dork, engine),
                    'site:edu.co "index.php?id="',
                )

    def test_engines_with_inurl_keep_operator(self) -> None:
        dork = "site:edu.co inurl:index.php?id="
        for engine in ("duckduckgo", "mojeek"):
            with self.subTest(engine=engine):
                self.assertEqual(
                    translate_query_for_engine(dork, engine),
                    dork,
                )

    def test_base_operators_translate_per_engine(self) -> None:
        dork = 'login intext:"admin" ext:php inurl:item.php?id='
        self.assertEqual(
            translate_query_for_engine(dork, "bing"),
            'login "admin" filetype:php "item.php?id="',
        )
        self.assertEqual(
            translate_query_for_engine(dork, "mojeek"),
            'login "admin" filetype:php inurl:item.php?id=',
        )

    def test_unknown_engine_does_not_rewrite_inurl(self) -> None:
        dork = "site:edu.co inurl:index.php?id="
        self.assertEqual(
            translate_query_for_engine(dork, "desconocido"), dork
        )


class SiteHostFilterTests(unittest.TestCase):
    def test_extract_site_host_variants(self) -> None:
        self.assertEqual(_extract_site_host("site:edu.co inurl:id="), "edu.co")
        self.assertEqual(
            _extract_site_host('site: www.ejemplo.com "index of"'), "ejemplo.com"
        )
        self.assertEqual(_extract_site_host('site:"gov.co" filetype:pdf'), "gov.co")
        self.assertEqual(_extract_site_host("inurl:index.php?id="), "")

    def test_search_discards_urls_outside_site_scope(self) -> None:
        class Engine(SearchEngine):
            def _search_bing(self, query, limit, cancel_event, log):
                return [
                    "https://index.hu/item.php?id=1",
                    "https://www.uni.edu.co/item.php?id=2",
                    "https://other.edu.co/page.php?id=3",
                ]

        engine = Engine(delay=0)
        engine._ddgs = None
        urls = engine.search("site:edu.co inurl:id=", 10, engines=["bing"])
        self.assertEqual(
            urls,
            [
                "https://www.uni.edu.co/item.php?id=2",
                "https://other.edu.co/page.php?id=3",
            ],
        )

    def test_search_without_site_keeps_all_hosts(self) -> None:
        class Engine(SearchEngine):
            def _search_bing(self, query, limit, cancel_event, log):
                return [
                    "https://index.hu/item.php?id=1",
                    "https://www.uni.edu.co/item.php?id=2",
                ]

        engine = Engine(delay=0)
        engine._ddgs = None
        urls = engine.search("inurl:id=", 10, engines=["bing"])
        self.assertEqual(
            urls,
            [
                "https://index.hu/item.php?id=1",
                "https://www.uni.edu.co/item.php?id=2",
            ],
        )


class BingUnwrapTests(unittest.TestCase):
    def test_unwrap_bing_url(self) -> None:
        href = (
            "https://www.bing.com/ck/a?u=a1aHR0cHM6Ly91bmkuZWR1LmNv"
        )
        self.assertEqual(_unwrap_bing_url(href), "https://uni.edu.co")

    def test_unwrap_keeps_plain_url(self) -> None:
        self.assertEqual(
            _unwrap_bing_url("https://uni.edu.co/item.php?id=1"),
            "https://uni.edu.co/item.php?id=1",
        )


class SearchEngineOrderTests(unittest.TestCase):
    def test_search_prefers_first_engine_until_limit(self) -> None:
        class Engine(SearchEngine):
            calls: list[str] = []

            def _search_brave(
                self, query, limit, cancel_event, log
            ):
                self.calls.append("brave")
                return [
                    "https://brave-target.edu.co/item.php?id=1",
                    "https://brave-target.edu.co/page.php?id=2",
                ]

            def _search_bing(
                self, query, limit, cancel_event, log
            ):
                self.calls.append("bing")
                return []

        engine = Engine(delay=0)
        engine._ddgs = None
        urls = engine.search(
            "site:edu.co inurl:id=", 2, engines=["brave", "bing"]
        )
        self.assertEqual(urls[0], "https://brave-target.edu.co/item.php?id=1")
        self.assertEqual(urls[1], "https://brave-target.edu.co/page.php?id=2")
        self.assertEqual(engine.calls, ["brave"])

    def test_search_falls_back_to_second_engine(self) -> None:
        class Engine(SearchEngine):
            calls: list[str] = []

            def _search_brave(
                self, query, limit, cancel_event, log
            ):
                self.calls.append("brave")
                return []

            def _search_bing(
                self, query, limit, cancel_event, log
            ):
                self.calls.append("bing")
                return ["https://bing-target.edu.co/item.php?id=3"]

        engine = Engine(delay=0)
        engine._ddgs = None
        urls = engine.search(
            "site:edu.co inurl:id=", 10, engines=["brave", "bing"]
        )
        self.assertEqual(urls, ["https://bing-target.edu.co/item.php?id=3"])
        self.assertEqual(engine.calls, ["brave", "bing"])

    def test_search_filters_out_search_engine_domains(self) -> None:
        class Engine(SearchEngine):
            def _search_bing(
                self, query, limit, cancel_event, log
            ):
                return [
                    "https://www.bing.com/ck/a?u=a1aHR0cHM6Ly91bmlkw60sZWR1LmNv",
                    "https://uni.edu.co/item.php?id=1",
                ]

        engine = Engine(delay=0)
        engine._ddgs = None
        urls = engine.search("site:edu.co inurl:id=", 5, engines=["bing"])
        self.assertEqual(urls, ["https://uni.edu.co/item.php?id=1"])


if __name__ == "__main__":
    unittest.main()
