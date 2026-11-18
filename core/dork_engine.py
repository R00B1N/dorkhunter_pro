"""Generación de Google Dorks acotados por país y tipo de dominio.

El motor construye consultas con los operadores ``site:``, ``inurl:`` e
``intext:``. ``core.search_engine`` adapta la consulta a cada buscador: los
que no soportan ``inurl:`` reciben el parámetro como frase entre comillas.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from config import DEFAULT_DORK_COUNT

# ---------------------------------------------------------------------------
# Catálogo de países agrupado por región. El campo ``gov`` solo se declara
# cuando el prefijo real difiere del estándar (México usa gob.mx, Uruguay
# gub.uy, Costa Rica go.cr, Francia gouv.fr, Canadá gc.ca, Suiza admin.ch...).
# ---------------------------------------------------------------------------
COUNTRY_CATEGORIES: dict[str, tuple[str, ...]] = {
    "Todos / Internacional": ("Todos / Internacional",),
    "Latinoamérica": (
        "Argentina",
        "Bolivia",
        "Brasil",
        "Chile",
        "Colombia",
        "Costa Rica",
        "Cuba",
        "Ecuador",
        "El Salvador",
        "Guatemala",
        "Honduras",
        "México",
        "Nicaragua",
        "Panamá",
        "Paraguay",
        "Perú",
        "Puerto Rico",
        "República Dominicana",
        "Uruguay",
        "Venezuela",
    ),
    "Norteamérica y Caribe": (
        "Canadá",
        "Estados Unidos",
        "Bahamas",
        "Barbados",
        "Jamaica",
        "Trinidad y Tobago",
    ),
    "Europa": (
        "Alemania",
        "Austria",
        "Bélgica",
        "Chequia",
        "Dinamarca",
        "España",
        "Finlandia",
        "Francia",
        "Grecia",
        "Hungría",
        "Irlanda",
        "Italia",
        "Noruega",
        "Países Bajos",
        "Polonia",
        "Portugal",
        "Reino Unido",
        "Rumanía",
        "Rusia",
        "Suecia",
        "Suiza",
        "Turquía",
        "Ucrania",
    ),
    "Asia y Oceanía": (
        "Australia",
        "Bangladés",
        "China",
        "Corea del Sur",
        "Filipinas",
        "India",
        "Indonesia",
        "Japón",
        "Malasia",
        "Nueva Zelanda",
        "Pakistán",
        "Singapur",
        "Tailandia",
        "Vietnam",
    ),
    "África y Oriente Medio": (
        "Arabia Saudita",
        "Argelia",
        "Catar",
        "Egipto",
        "Emiratos Árabes Unidos",
        "Ghana",
        "Israel",
        "Kenia",
        "Marruecos",
        "Nigeria",
        "Sudáfrica",
        "Túnez",
    ),
}

COUNTRIES: dict[str, dict[str, str]] = {
    "Todos / Internacional": {"tld": ""},
    # Latinoamérica ------------------------------------------------------
    "Argentina": {"tld": "ar", "gov": "gob"},
    "Bolivia": {"tld": "bo", "gov": "gob"},
    "Brasil": {"tld": "br"},
    "Chile": {"tld": "cl", "gov": "gob"},
    "Colombia": {"tld": "co"},
    "Costa Rica": {"tld": "cr", "gov": "go"},
    "Cuba": {"tld": "cu", "gov": "gob"},
    "Ecuador": {"tld": "ec", "gov": "gob"},
    "El Salvador": {"tld": "sv", "gov": "gob"},
    "Guatemala": {"tld": "gt", "gov": "gob"},
    "Honduras": {"tld": "hn", "gov": "gob"},
    "México": {"tld": "mx", "gov": "gob"},
    "Nicaragua": {"tld": "ni", "gov": "gob"},
    "Panamá": {"tld": "pa", "gov": "gob"},
    "Paraguay": {"tld": "py"},
    "Perú": {"tld": "pe", "gov": "gob"},
    "Puerto Rico": {"tld": "pr"},
    "República Dominicana": {"tld": "do", "gov": "gob"},
    "Uruguay": {"tld": "uy", "gov": "gub"},
    "Venezuela": {"tld": "ve", "gov": "gob"},
    # Norteamérica y Caribe ---------------------------------------------
    "Canadá": {"tld": "ca", "gov": "gc"},
    "Estados Unidos": {"tld": "us"},
    "Bahamas": {"tld": "bs"},
    "Barbados": {"tld": "bb"},
    "Jamaica": {"tld": "jm"},
    "Trinidad y Tobago": {"tld": "tt"},
    # Europa -------------------------------------------------------------
    "Alemania": {"tld": "de", "gov": "bund"},
    "Austria": {"tld": "at", "gov": "gv"},
    "Bélgica": {"tld": "be"},
    "Chequia": {"tld": "cz"},
    "Dinamarca": {"tld": "dk"},
    "España": {"tld": "es", "gov": "gob"},
    "Finlandia": {"tld": "fi"},
    "Francia": {"tld": "fr", "gov": "gouv"},
    "Grecia": {"tld": "gr"},
    "Hungría": {"tld": "hu"},
    "Irlanda": {"tld": "ie"},
    "Italia": {"tld": "it"},
    "Noruega": {"tld": "no"},
    "Países Bajos": {"tld": "nl", "gov": "overheid"},
    "Polonia": {"tld": "pl"},
    "Portugal": {"tld": "pt"},
    "Reino Unido": {"tld": "uk"},
    "Rumanía": {"tld": "ro"},
    "Rusia": {"tld": "ru"},
    "Suecia": {"tld": "se"},
    "Suiza": {"tld": "ch", "gov": "admin"},
    "Turquía": {"tld": "tr"},
    "Ucrania": {"tld": "ua"},
    # Asia y Oceanía -----------------------------------------------------
    "Australia": {"tld": "au"},
    "Bangladés": {"tld": "bd"},
    "China": {"tld": "cn"},
    "Corea del Sur": {"tld": "kr", "gov": "go"},
    "Filipinas": {"tld": "ph"},
    "India": {"tld": "in"},
    "Indonesia": {"tld": "id", "gov": "go"},
    "Japón": {"tld": "jp", "gov": "go"},
    "Malasia": {"tld": "my"},
    "Nueva Zelanda": {"tld": "nz", "gov": "govt"},
    "Pakistán": {"tld": "pk"},
    "Singapur": {"tld": "sg"},
    "Tailandia": {"tld": "th", "gov": "go"},
    "Vietnam": {"tld": "vn"},
    # África y Oriente Medio --------------------------------------------
    "Arabia Saudita": {"tld": "sa"},
    "Argelia": {"tld": "dz"},
    "Catar": {"tld": "qa"},
    "Egipto": {"tld": "eg"},
    "Emiratos Árabes Unidos": {"tld": "ae"},
    "Ghana": {"tld": "gh"},
    "Israel": {"tld": "il"},
    "Kenia": {"tld": "ke", "gov": "go"},
    "Marruecos": {"tld": "ma"},
    "Nigeria": {"tld": "ng"},
    "Sudáfrica": {"tld": "za"},
    "Túnez": {"tld": "tn"},
}

DOMAIN_TYPES: dict[str, str] = {
    "Educativo (edu)": "edu",
    "Gubernamental (gov)": "gov",
    "Gubernamental (gob)": "gob",
    "Militar (mil)": "mil",
    "Organizaciones (org)": "org",
    "Comercial (com)": "com",
    "Redes (net)": "net",
    "Salud (salud)": "salud",
    "Todos": "",
}

# Patrones de parámetros clásicamente vulnerables. El orden importa: los
# primeros son los que se prueban en una caza "Rápida".
VULNERABLE_PARAMS: tuple[str, ...] = (
    "id",
    "cat",
    "page",
    "user",
    "search",
    "item",
    "product",
    "news",
    "article",
    "file",
    "view",
    "lang",
    "q",
    "s",
    "pid",
    "nid",
    "tid",
    "cid",
    "doc",
    "menu",
    "mod",
    "option",
    "cmd",
    "url",
    "path",
    "report",
    "download",
    "album",
    "gallery",
    "year",
    "month",
    "date",
    "keyword",
    "query",
    "idx",
    "cod",
    "codigo",
    "num",
    "folio",
    "ref",
    # Ampliación para cazas profundas (más variedad de parámetros).
    "tipo",
    "categoria",
    "seccion",
    "pagina",
    "noticia",
    "evento",
    "curso",
    "programa",
    "materia",
    "estudiante",
    "docente",
    "profesor",
    "empleado",
    "cliente",
    "proveedor",
    "servicio",
    "solicitud",
    "tramite",
    "formulario",
    "encuesta",
    "foro",
    "tema",
    "blog",
    "video",
    "imagen",
    "archivo",
    "adjunto",
    "plantilla",
    "modulo",
    "accion",
    "tabla",
    "registro",
    "consulta",
    "buscar",
    "clave",
    "area",
    "sede",
    "carrera",
    "convocatoria",
    "normativa",
    "resolucion",
    "acuerdo",
    "circular",
    "informe",
    "acta",
    "planilla",
    "nomina",
    "presupuesto",
    "contrato",
)

# ---------------------------------------------------------------------------
# Sugerencias para el campo de palabras clave (autocompletado de la GUI).
# ---------------------------------------------------------------------------
KEYWORD_SUGGESTIONS: tuple[str, ...] = (
    "admin",
    "login",
    "intranet",
    "portal",
    "sistema",
    "usuarios",
    "matrícula",
    "pagos",
    "facturación",
    "documentos",
    "noticias",
    "eventos",
    "biblioteca",
    "campus",
    "becas",
    "convocatorias",
    "empleo",
    "contratación",
    "licitaciones",
    "reportes",
    "estadísticas",
    "transparencia",
    "datos abiertos",
    "investigación",
    "posgrado",
    "egresados",
    "certificados",
    "boletines",
    "descargas",
    "soporte",
    "ayuda",
    "contacto",
    "formulario",
    "registro",
    "consulta",
)


def _fold(text: str) -> str:
    """Minúsculas sin acentos, para comparar sugerencias."""
    normalized = unicodedata.normalize("NFKD", (text or "").lower())
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def suggest_keywords(prefix: str, limit: int = 6) -> list[str]:
    """Sugerencias para el campo de palabras clave.

    Coincide sin distinguir mayúsculas ni acentos: ``matri`` sugiere
    ``matrícula``. Con un prefijo vacío devuelve las primeras sugerencias.
    """
    folded = _fold((prefix or "").strip())
    if not folded:
        return list(KEYWORD_SUGGESTIONS[: max(1, limit)])
    starts = [word for word in KEYWORD_SUGGESTIONS if _fold(word).startswith(folded)]
    contains = [
        word
        for word in KEYWORD_SUGGESTIONS
        if folded in _fold(word) and word not in starts
    ]
    return (starts + contains)[: max(1, limit)]


_SITE_RE = re.compile(r"\bsite:\s*([^\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Dork:
    query: str
    pattern: str = ""
    label: str = ""
    scope_suffix: str = ""


class DorkEngine:
    def __init__(self, patterns: tuple[str, ...] | None = None) -> None:
        self.patterns = patterns or VULNERABLE_PARAMS

    # ------------------------------------------------------------------
    def suffix_for(self, country: str, domain_type: str) -> str:
        """Devuelve el sufijo de ``site:`` (p. ej. ``edu.co``), o ``''``."""
        info = COUNTRIES.get(country)
        if not info:
            raise ValueError(f"País no soportado: {country}")
        tld = info.get("tld", "")
        if not tld:
            return ""
        prefix = DOMAIN_TYPES.get(domain_type)
        if prefix is None:
            raise ValueError(f"Tipo de dominio no soportado: {domain_type}")
        if not prefix:
            return tld
        if prefix == "gov":
            prefix = info.get("gov", "gov")
        return f"{prefix}.{tld}"

    # ------------------------------------------------------------------
    def build(
        self,
        country: str,
        domain_type: str,
        keywords: str = "",
        manual_dork: str = "",
        limit: int = DEFAULT_DORK_COUNT,
    ) -> list[Dork]:
        """Genera la lista de dorks que se enviarán al buscador."""
        manual = (manual_dork or "").strip()
        if manual:
            scope = ""
            match = _SITE_RE.search(manual)
            if match:
                scope = match.group(1).strip().lower()
            return [
                Dork(
                    query=manual,
                    pattern="manual",
                    label="Dork manual",
                    scope_suffix=scope,
                )
            ]

        suffix = self.suffix_for(country, domain_type)
        if not suffix:
            raise ValueError(
                "Selecciona un país concreto o escribe un dork manual que "
                "incluya site:dominio para acotar el alcance."
            )

        base = f"site:{suffix}"
        keyword_clause = self._normalize_keywords(keywords)
        if keyword_clause:
            # Se usa intext: (estilo Google). search_engine lo traduce para DDG.
            base += f" {keyword_clause}"

        patterns = list(self.patterns[: max(1, limit)])
        return [
            Dork(
                query=f"{base} inurl:{pattern}=",
                pattern=pattern,
                label=f"Parámetro {pattern}",
                scope_suffix=suffix,
            )
            for pattern in patterns
        ]

    # ------------------------------------------------------------------
    def preview(
        self,
        country: str,
        domain_type: str,
        keywords: str = "",
        manual_dork: str = "",
    ) -> str:
        dorks = self.build(
            country, domain_type, keywords, manual_dork, limit=1
        )
        return dorks[0].query

    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_keywords(keywords: str) -> str:
        """Convierte palabras clave en una o varias cláusulas ``intext:``.

        Acepta una frase (``pagos en línea``) o una lista separada por comas
        (``matrícula, pagos``). En el segundo caso se genera un ``intext:`` por
        término para no buscar la coma como parte de la frase.
        """
        value = (keywords or "").strip()
        if not value:
            return ""
        value = value.strip('"').strip()
        if not value:
            return ""
        parts = [
            part.strip().strip('"')
            for part in value.split(",")
            if part.strip().strip('"')
        ]
        if not parts:
            return ""
        unique: list[str] = []
        seen: set[str] = set()
        for part in parts:
            key = part.casefold()
            if key not in seen:
                seen.add(key)
                unique.append(part)
        terms = [
            f'"{part}"' if re.search(r"\s", part) else part
            for part in unique
        ]
        return " ".join(f"intext:{term}" for term in terms)
