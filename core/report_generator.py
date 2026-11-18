"""Generación de reportes de divulgación responsable (Markdown, HTML y JSON)."""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config import APP_NAME, APP_VERSION, MAX_EVIDENCE_CHARS
from core.sqli_scanner import ESTADO_LABELS, ESTADO_VULN
from utils.helpers import now_iso, sanitize_filename, truncate

DISCLAIMER_NOTE = (
    "Este hallazgo fue detectado mediante análisis pasivo de OSINT. "
    "Se recomienda al equipo de TI realizar una prueba de penetración "
    "autorizada para confirmar la vulnerabilidad."
)

RECOMMENDATION = """- Validar y sanear todas las entradas en el servidor (lista blanca de tipos,
  longitudes y formatos). No confiar en validaciones del lado del cliente.
- Usar consultas parametrizadas (prepared statements) o un ORM que las genere.
  Nunca concatenar entrada del usuario en la sentencia SQL.
- Aplicar el principio de mínimo privilegio al usuario de base de datos de la
  aplicación (sin permisos de DDL, sin acceso a otras bases).
- Devolver mensajes de error genéricos al usuario y registrar el detalle en los
  logs internos, sin exponer rutas, versiones ni estructura de tablas.
- Revisar los logs del servidor web y de la base de datos para descartar
  intentos previos sobre el mismo parámetro.
- Considerar un WAF como control compensatorio, nunca como sustituto del
  saneamiento de código."""

IMPACT = """Si la vulnerabilidad se confirma, un atacante podría alterar la lógica de las
consultas SQL y, dependiendo de los privilegios del usuario de base de datos,
leer información sensible, modificar registros o afectar la disponibilidad del
servicio. El impacto real no se evaluó: esta herramienta no extrae datos ni
ejecuta técnicas de explotación."""


class ReportGenerator:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def generate(self, finding: dict[str, Any], fmt: str = "md") -> Path:
        fmt = fmt.lower().lstrip(".")
        if fmt not in {"md", "html", "json"}:
            raise ValueError("Formato no soportado. Usa 'md', 'html' o 'json'.")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        domain = sanitize_filename(finding.get("domain") or "dominio")
        param = sanitize_filename(finding.get("parametro") or "parametro")
        finding_id = sanitize_filename(str(finding.get("id") or "nuevo"))
        path = self.output_dir / (
            f"reporte_{timestamp}_{domain}_{param}_{finding_id}.{fmt}"
        )

        builders = {
            "md": self.build_markdown,
            "html": self.build_html,
            "json": self.build_json,
        }
        path.write_text(builders[fmt](finding), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    def generate_scan(
        self,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
        fmt: str = "md",
    ) -> Path:
        """Genera un reporte agregado de toda una caza."""
        fmt = fmt.lower().lstrip(".")
        if fmt not in {"md", "html", "json"}:
            raise ValueError("Formato no soportado. Usa 'md', 'html' o 'json'.")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        scan_id = sanitize_filename(str(scan.get("id") or "caza"))
        path = self.output_dir / f"reporte_caza_{timestamp}_{scan_id}.{fmt}"
        builders = {
            "md": self.build_scan_markdown,
            "html": self.build_scan_html,
            "json": self.build_scan_json,
        }
        path.write_text(builders[fmt](scan, findings), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    def build_markdown(self, finding: dict[str, Any]) -> str:
        url = str(finding.get("url") or "")
        param = str(finding.get("parametro") or "No identificado")
        evidence = str(finding.get("evidencia") or "").strip()
        if not evidence:
            evidence = "No se capturó evidencia textual. Repetir la prueba de forma autorizada."
        evidence = truncate(evidence, MAX_EVIDENCE_CHARS)
        # Evita que la evidencia cierre el bloque de código del reporte.
        evidence = evidence.replace("```", "'''")

        contact = str(finding.get("contacto") or "No disponible")
        organization = str(finding.get("organizacion") or "No disponible")
        security_txt = str(finding.get("security_txt") or "No encontrado")
        error = str(finding.get("error_detectado") or "Firma de error SQL")
        status = finding.get("http_status") or "N/D"
        dbms = str(finding.get("dbms") or "No determinado")
        confidence = str(finding.get("confianza") or "No determinada")
        waf = str(finding.get("waf") or "No detectado")
        registrar = str(finding.get("registrar") or "No disponible")
        whois_country = str(finding.get("whois_country") or "No disponible")
        enrichment_source = str(finding.get("enrichment_source") or "No disponible")
        found_at = str(finding.get("created_at") or now_iso())

        def cell(value: Any) -> str:
            return str(value).replace("|", "\\|").replace("\n", " ").strip()

        return f"""# [Security Report] Posible SQL Injection en {url}

**Fecha del hallazgo:** {found_at}  
**Herramienta:** {APP_NAME} v{APP_VERSION}  
**Clasificación:** Divulgación responsable — hallazgo no confirmado  
**Estado:** Pendiente de validación por el equipo responsable

---

## 1. Resumen

Durante una revisión pasiva de superficie de exposición se identificó que el
parámetro `{param}` de la URL indicada devuelve un mensaje de error asociado al
motor de base de datos cuando se envía una comilla simple (`'`).

## 2. Tipo de Vulnerabilidad

Tipo de Vulnerabilidad: SQL Injection (Error-Based)

## 3. URL Afectada y Parámetro

| Campo | Valor |
|---|---|
| URL | `{cell(url)}` |
| Parámetro | `{cell(param)}` |
| Método | GET |
| Código HTTP | {cell(status)} |
| Motor de base de datos | {cell(dbms)} |
| WAF detectado | {cell(waf)} |
| Confianza del triaje | {cell(confidence)} |
| Firma detectada | {cell(error)} |

## 4. Evidencia

```text
{evidence}
```

> La evidencia se limita al mensaje de error. No se extrajeron datos, no se
> ejecutaron técnicas de Blind SQLi ni Time-Based y no se intentó explotar la
> vulnerabilidad.

## 5. Impacto Potencial

{IMPACT}

## 6. Contacto Sugerido

| Campo | Valor |
|---|---|
| Organización | {cell(organization)} |
| Registrador | {cell(registrar)} |
| País WHOIS | {cell(whois_country)} |
| Contacto | {cell(contact)} |
| security.txt | {cell(security_txt)} |
| Fuente de enriquecimiento | {cell(enrichment_source)} |

Si el contacto no es válido, se recomienda localizar el canal oficial de
seguridad o el buzón de la oficina de TI/CSIRT del organismo.

## 7. Recomendación

{RECOMMENDATION}

## 8. Aviso

> {DISCLAIMER_NOTE}

---

*Reporte generado automáticamente por {APP_NAME} v{APP_VERSION}. Este documento
no constituye una prueba de penetración ni una confirmación de explotabilidad.*
"""

    # ------------------------------------------------------------------
    def build_json(self, finding: dict[str, Any]) -> str:
        """Representación estructurada para automatización o integración."""
        payload = {
            "tool": APP_NAME,
            "version": APP_VERSION,
            "generated_at": now_iso(),
            "finding": finding,
            "disclaimer": DISCLAIMER_NOTE,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)

    # ------------------------------------------------------------------
    def build_scan_markdown(
        self, scan: dict[str, Any], findings: list[dict[str, Any]]
    ) -> str:
        scan_id = scan.get("id") or "N/D"
        created = str(scan.get("created_at") or now_iso())
        country = str(scan.get("country") or "N/D")
        domain_type = str(scan.get("domain_type") or "N/D")
        keywords = str(scan.get("keywords") or "—")
        dork = str(scan.get("dork_used") or "—")
        status = str(scan.get("status") or "N/D")
        urls_found = scan.get("urls_found") or 0

        counts: dict[str, int] = {}
        for finding in findings:
            state = str(finding.get("estado") or "pendiente")
            counts[state] = counts.get(state, 0) + 1
        vulns = [f for f in findings if f.get("estado") == ESTADO_VULN]

        def cell(value: Any) -> str:
            return str(value).replace("|", "\\|").replace("\n", " ").strip()

        lines: list[str] = [
            f"# [Security Report] Caza #{scan_id} — superficie de exposición",
            "",
            f"**Fecha:** {created}  ",
            f"**Herramienta:** {APP_NAME} v{APP_VERSION}  ",
            "**Clasificación:** Divulgación responsable — hallazgos no confirmados",
            "",
            "---",
            "",
            "## 1. Resumen de la caza",
            "",
            "| Campo | Valor |",
            "|---|---|",
            f"| País | {cell(country)} |",
            f"| Tipo de dominio | {cell(domain_type)} |",
            f"| Palabras clave | {cell(keywords)} |",
            f"| Estado de la caza | {cell(status)} |",
            f"| URLs encontradas | {cell(urls_found)} |",
            f"| Hallazgos registrados | {len(findings)} |",
            f"| Posibles SQLi | {len(vulns)} |",
            "",
            f"**Dorks utilizados:** `{cell(dork)}`",
            "",
            "### Distribución por estado",
            "",
            "| Estado | Cantidad |",
            "|---|---:|",
        ]
        for state, label in ESTADO_LABELS.items():
            if counts.get(state):
                lines.append(f"| {label} | {counts[state]} |")
        if not findings:
            lines.append("| Sin hallazgos | 0 |")
        lines.extend(
            [
                "",
                "## 2. Hallazgos",
                "",
            ]
        )
        if findings:
            lines.extend(
                [
                    "| # | URL | Parámetro | Estado | Motor | WAF | Confianza |",
                    "|---:|---|---|---|---|---|---|",
                ]
            )
            for index, finding in enumerate(findings, start=1):
                lines.append(
                    "| {index} | `{url}` | `{param}` | {state} | {dbms} | {waf} | {confidence} |".format(
                        index=index,
                        url=cell(finding.get("url") or ""),
                        param=cell(finding.get("parametro") or "—"),
                        state=cell(
                            ESTADO_LABELS.get(
                                str(finding.get("estado")), finding.get("estado") or ""
                            )
                        ),
                        dbms=cell(finding.get("dbms") or "—"),
                        waf=cell(finding.get("waf") or "—"),
                        confidence=cell(finding.get("confianza") or "—"),
                    )
                )
        else:
            lines.append("No se registraron hallazgos en esta caza.")

        if vulns:
            lines.extend(["", "## 3. Detalle de posibles vulnerabilidades", ""])
            for index, finding in enumerate(vulns, start=1):
                evidence = str(finding.get("evidencia") or "").strip()
                if not evidence:
                    evidence = "No se capturó evidencia textual."
                evidence = truncate(evidence, MAX_EVIDENCE_CHARS).replace("```", "'''")
                lines.extend(
                    [
                        f"### Hallazgo {index}: `{finding.get('url') or ''}`",
                        "",
                        f"- **Parámetro:** `{finding.get('parametro') or 'No identificado'}`",
                        f"- **Estado:** {ESTADO_LABELS.get(str(finding.get('estado')), finding.get('estado') or '')}",
                        f"- **Motor:** {finding.get('dbms') or 'No determinado'}",
                        f"- **WAF:** {finding.get('waf') or 'No detectado'}",
                        f"- **Confianza:** {finding.get('confianza') or 'No determinada'}",
                        f"- **HTTP:** {finding.get('http_status') or 'N/D'}",
                        f"- **Firma:** {finding.get('error_detectado') or 'No disponible'}",
                        f"- **Contacto:** {finding.get('contacto') or 'No disponible'}",
                        f"- **Organización:** {finding.get('organizacion') or 'No disponible'}",
                        f"- **Registrador:** {finding.get('registrar') or 'No disponible'}",
                        f"- **País WHOIS:** {finding.get('whois_country') or 'No disponible'}",
                        f"- **security.txt:** {finding.get('security_txt') or 'No encontrado'}",
                        f"- **Fuente de enriquecimiento:** {finding.get('enrichment_source') or 'No disponible'}",
                        "",
                        "```text",
                        evidence,
                        "```",
                        "",
                    ]
                )

        lines.extend(
            [
                "## 4. Impacto Potencial",
                "",
                IMPACT,
                "",
                "## 5. Recomendación",
                "",
                RECOMMENDATION,
                "",
                "## 6. Aviso",
                "",
                f"> {DISCLAIMER_NOTE}",
                "",
                "---",
                "",
                f"*Reporte generado automáticamente por {APP_NAME} v{APP_VERSION}. "
                "No constituye una prueba de penetración ni una confirmación de "
                "explotabilidad.*",
                "",
            ]
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def build_scan_html(
        self, scan: dict[str, Any], findings: list[dict[str, Any]]
    ) -> str:
        scan_id = scan.get("id") or "N/D"
        created = str(scan.get("created_at") or now_iso())
        country = str(scan.get("country") or "N/D")
        domain_type = str(scan.get("domain_type") or "N/D")
        keywords = str(scan.get("keywords") or "—")
        dork = str(scan.get("dork_used") or "—")
        status = str(scan.get("status") or "N/D")
        urls_found = scan.get("urls_found") or 0
        counts: dict[str, int] = {}
        for finding in findings:
            state = str(finding.get("estado") or "pendiente")
            counts[state] = counts.get(state, 0) + 1
        vulns = [f for f in findings if f.get("estado") == ESTADO_VULN]

        def esc(value: Any) -> str:
            return html.escape(str(value), quote=True)

        summary_rows = "".join(
            f"<tr><th>{esc(label)}</th><td>{esc(counts[state])}</td></tr>"
            for state, label in ESTADO_LABELS.items()
            if counts.get(state)
        )
        if not summary_rows:
            summary_rows = "<tr><th>Sin hallazgos</th><td>0</td></tr>"

        finding_rows = ""
        for index, finding in enumerate(findings, start=1):
            finding_rows += (
                "<tr>"
                f"<td>{index}</td>"
                f"<td><code>{esc(finding.get('url') or '')}</code></td>"
                f"<td><code>{esc(finding.get('parametro') or '—')}</code></td>"
                f"<td>{esc(ESTADO_LABELS.get(str(finding.get('estado')), finding.get('estado') or ''))}</td>"
                f"<td>{esc(finding.get('dbms') or '—')}</td>"
                f"<td>{esc(finding.get('waf') or '—')}</td>"
                f"<td>{esc(finding.get('confianza') or '—')}</td>"
                "</tr>"
            )
        if not finding_rows:
            finding_rows = '<tr><td colspan="7">No se registraron hallazgos.</td></tr>'

        detail_blocks = ""
        for index, finding in enumerate(vulns, start=1):
            evidence = str(finding.get("evidencia") or "").strip()
            if not evidence:
                evidence = "No se capturó evidencia textual."
            evidence = truncate(evidence, MAX_EVIDENCE_CHARS)
            detail_blocks += f"""
      <h3>Hallazgo {index}: <code>{esc(finding.get('url') or '')}</code></h3>
      <table>
        <tr><th>Parámetro</th><td><code>{esc(finding.get('parametro') or 'No identificado')}</code></td></tr>
        <tr><th>Estado</th><td>{esc(ESTADO_LABELS.get(str(finding.get('estado')), finding.get('estado') or ''))}</td></tr>
        <tr><th>Motor</th><td>{esc(finding.get('dbms') or 'No determinado')}</td></tr>
        <tr><th>WAF</th><td>{esc(finding.get('waf') or 'No detectado')}</td></tr>
        <tr><th>Confianza</th><td>{esc(finding.get('confianza') or 'No determinada')}</td></tr>
        <tr><th>HTTP</th><td>{esc(finding.get('http_status') or 'N/D')}</td></tr>
        <tr><th>Firma</th><td>{esc(finding.get('error_detectado') or 'No disponible')}</td></tr>
        <tr><th>Contacto</th><td>{esc(finding.get('contacto') or 'No disponible')}</td></tr>
        <tr><th>Organización</th><td>{esc(finding.get('organizacion') or 'No disponible')}</td></tr>
        <tr><th>Registrador</th><td>{esc(finding.get('registrar') or 'No disponible')}</td></tr>
        <tr><th>País WHOIS</th><td>{esc(finding.get('whois_country') or 'No disponible')}</td></tr>
        <tr><th>security.txt</th><td>{esc(finding.get('security_txt') or 'No encontrado')}</td></tr>
        <tr><th>Fuente de enriquecimiento</th><td>{esc(finding.get('enrichment_source') or 'No disponible')}</td></tr>
      </table>
      <pre>{esc(evidence)}</pre>
"""
        if not detail_blocks:
            detail_blocks = "<p>No se identificaron posibles vulnerabilidades.</p>"

        css = """
        :root { color-scheme: dark; }
        * { box-sizing: border-box; }
        body { margin: 0; padding: 40px 20px; background: #0d1117; color: #e6edf3;
               font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
               line-height: 1.65; }
        main { max-width: 1100px; margin: 0 auto; }
        .card { background: #151b23; border: 1px solid #26303d; border-radius: 14px;
                padding: 36px 40px; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 999px;
                 background: #3b1d1d; color: #f87171; font-size: 12px; font-weight: 700;
                 letter-spacing: .04em; text-transform: uppercase; }
        h1 { font-size: 26px; line-height: 1.3; margin: 18px 0 8px; }
        h2 { font-size: 17px; margin: 34px 0 10px; padding-bottom: 6px;
             border-bottom: 1px solid #26303d; color: #22d3ee; }
        h3 { font-size: 14px; margin: 24px 0 8px; color: #fca5a5; }
        .meta { color: #8b98a9; font-size: 13px; }
        .meta strong { color: #e6edf3; }
        table { width: 100%; border-collapse: collapse; margin: 12px 0; }
        th, td { text-align: left; padding: 9px 12px; font-size: 14px;
                 border-bottom: 1px solid #26303d; vertical-align: top; }
        th { color: #8b98a9; font-weight: 600; width: 190px; }
        td:first-child { width: auto; }
        code, pre { font-family: "SFMono-Regular", Consolas, monospace; }
        code { color: #7dd3fc; word-break: break-all; }
        pre { background: #0b0f14; border: 1px solid #26303d; border-radius: 10px;
              padding: 16px; overflow-x: auto; white-space: pre-wrap;
              word-break: break-word; color: #fca5a5; font-size: 13px; }
        .note { background: #1c222b; border-left: 4px solid #fbbf24;
                padding: 14px 18px; border-radius: 8px; color: #d6dee8;
                font-size: 14px; margin: 18px 0; }
        ul { padding-left: 22px; }
        li { margin: 6px 0; }
        footer { color: #8b98a9; font-size: 12px; margin-top: 28px; }
        """
        body = f"""
<main>
  <div class="card">
    <span class="badge">Hallazgos no confirmados</span>
    <h1>[Security Report] Caza #{esc(scan_id)} — superficie de exposición</h1>
    <p class="meta">
      <strong>Fecha:</strong> {esc(created)}<br>
      <strong>Herramienta:</strong> {esc(APP_NAME)} v{esc(APP_VERSION)}<br>
      <strong>Clasificación:</strong> Divulgación responsable — pendiente de validación
    </p>

    <h2>1. Resumen de la caza</h2>
    <table>
      <tr><th>País</th><td>{esc(country)}</td></tr>
      <tr><th>Tipo de dominio</th><td>{esc(domain_type)}</td></tr>
      <tr><th>Palabras clave</th><td>{esc(keywords)}</td></tr>
      <tr><th>Estado de la caza</th><td>{esc(status)}</td></tr>
      <tr><th>URLs encontradas</th><td>{esc(urls_found)}</td></tr>
      <tr><th>Hallazgos registrados</th><td>{len(findings)}</td></tr>
      <tr><th>Posibles SQLi</th><td>{len(vulns)}</td></tr>
      <tr><th>Dorks</th><td><code>{esc(dork)}</code></td></tr>
    </table>
    <h3>Distribución por estado</h3>
    <table>{summary_rows}</table>

    <h2>2. Hallazgos</h2>
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Parámetro</th><th>Estado</th><th>Motor</th><th>WAF</th><th>Confianza</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>

    <h2>3. Detalle de posibles vulnerabilidades</h2>
    {detail_blocks}

    <h2>4. Impacto Potencial</h2>
    <p>{esc(IMPACT)}</p>

    <h2>5. Recomendación</h2>
    <ul>
      <li>Validar y sanear todas las entradas en el servidor (lista blanca de
      tipos, longitudes y formatos). No confiar en validaciones del cliente.</li>
      <li>Usar consultas parametrizadas (<em>prepared statements</em>) o un ORM
      que las genere. Nunca concatenar entrada del usuario en la sentencia SQL.</li>
      <li>Aplicar mínimo privilegio al usuario de base de datos de la aplicación
      (sin DDL, sin acceso a otras bases).</li>
      <li>Devolver mensajes de error genéricos y registrar el detalle en logs
      internos, sin exponer rutas, versiones ni estructura de tablas.</li>
      <li>Revisar los logs del servidor web y de la base de datos para descartar
      intentos previos sobre el mismo parámetro.</li>
      <li>Considerar un WAF como control compensatorio, nunca como sustituto del
      saneamiento de código.</li>
    </ul>

    <h2>6. Aviso</h2>
    <div class="note">{esc(DISCLAIMER_NOTE)}</div>

    <footer>
      Reporte generado automáticamente por {esc(APP_NAME)} v{esc(APP_VERSION)}.
      Este documento no constituye una prueba de penetración ni una confirmación
      de explotabilidad.
    </footer>
  </div>
</main>
"""
        return (
            "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>[Security Report] Caza #{esc(scan_id)}</title>\n"
            f"<style>{css}</style>\n</head>\n<body>{body}</body>\n</html>\n"
        )

    # ------------------------------------------------------------------
    def build_scan_json(
        self, scan: dict[str, Any], findings: list[dict[str, Any]]
    ) -> str:
        scan_payload = dict(scan)
        raw_duplicates = scan_payload.pop("duplicadas_json", None)
        duplicates: list[dict[str, Any]] = []
        if raw_duplicates:
            try:
                parsed = json.loads(str(raw_duplicates))
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, list):
                duplicates = parsed
        payload = {
            "tool": APP_NAME,
            "version": APP_VERSION,
            "generated_at": now_iso(),
            "scan": scan_payload,
            "duplicates": duplicates,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "posibles_vuln": sum(
                    1 for f in findings if f.get("estado") == ESTADO_VULN
                ),
                "duplicadas": int(scan.get("duplicadas") or 0),
            },
            "disclaimer": DISCLAIMER_NOTE,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)

    # ------------------------------------------------------------------
    def build_html(self, finding: dict[str, Any]) -> str:
        url = str(finding.get("url") or "")
        param = str(finding.get("parametro") or "No identificado")
        evidence = str(finding.get("evidencia") or "").strip()
        if not evidence:
            evidence = "No se capturó evidencia textual. Repetir la prueba de forma autorizada."
        evidence = truncate(evidence, MAX_EVIDENCE_CHARS)

        contact = str(finding.get("contacto") or "No disponible")
        organization = str(finding.get("organizacion") or "No disponible")
        security_txt = str(finding.get("security_txt") or "No encontrado")
        error = str(finding.get("error_detectado") or "Firma de error SQL")
        status = finding.get("http_status") or "N/D"
        dbms = str(finding.get("dbms") or "No determinado")
        confidence = str(finding.get("confianza") or "No determinada")
        waf = str(finding.get("waf") or "No detectado")
        registrar = str(finding.get("registrar") or "No disponible")
        whois_country = str(finding.get("whois_country") or "No disponible")
        enrichment_source = str(finding.get("enrichment_source") or "No disponible")
        found_at = str(finding.get("created_at") or now_iso())

        def esc(value: Any) -> str:
            return html.escape(str(value), quote=True)

        css = """
        :root { color-scheme: dark; }
        * { box-sizing: border-box; }
        body {
            margin: 0; padding: 40px 20px;
            background: #0d1117; color: #e6edf3;
            font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.65;
        }
        main { max-width: 900px; margin: 0 auto; }
        .card {
            background: #151b23; border: 1px solid #26303d;
            border-radius: 14px; padding: 36px 40px;
        }
        .badge {
            display: inline-block; padding: 4px 12px; border-radius: 999px;
            background: #3b1d1d; color: #f87171; font-size: 12px;
            font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
        }
        h1 { font-size: 26px; line-height: 1.3; margin: 18px 0 8px; }
        h2 {
            font-size: 17px; margin: 34px 0 10px; padding-bottom: 6px;
            border-bottom: 1px solid #26303d; color: #22d3ee;
        }
        .meta { color: #8b98a9; font-size: 13px; }
        .meta strong { color: #e6edf3; }
        table { width: 100%; border-collapse: collapse; margin: 12px 0; }
        th, td {
            text-align: left; padding: 9px 12px; font-size: 14px;
            border-bottom: 1px solid #26303d; vertical-align: top;
        }
        th { color: #8b98a9; font-weight: 600; width: 190px; }
        code, pre { font-family: "SFMono-Regular", Consolas, monospace; }
        code { color: #7dd3fc; word-break: break-all; }
        pre {
            background: #0b0f14; border: 1px solid #26303d; border-radius: 10px;
            padding: 16px; overflow-x: auto; white-space: pre-wrap;
            word-break: break-word; color: #fca5a5; font-size: 13px;
        }
        .note {
            background: #1c222b; border-left: 4px solid #fbbf24;
            padding: 14px 18px; border-radius: 8px; color: #d6dee8;
            font-size: 14px; margin: 18px 0;
        }
        ul { padding-left: 22px; }
        li { margin: 6px 0; }
        footer { color: #8b98a9; font-size: 12px; margin-top: 28px; }
        a { color: #22d3ee; }
        """

        body = f"""
<main>
  <div class="card">
    <span class="badge">Hallazgo no confirmado</span>
    <h1>[Security Report] Posible SQL Injection en {esc(url)}</h1>
    <p class="meta">
      <strong>Fecha del hallazgo:</strong> {esc(found_at)}<br>
      <strong>Herramienta:</strong> {esc(APP_NAME)} v{esc(APP_VERSION)}<br>
      <strong>Clasificación:</strong> Divulgación responsable — pendiente de validación
    </p>

    <h2>1. Resumen</h2>
    <p>Durante una revisión pasiva de superficie de exposición se identificó que
    el parámetro <code>{esc(param)}</code> devuelve un mensaje de error asociado
    al motor de base de datos cuando se envía una comilla simple
    (<code>'</code>).</p>

    <h2>2. Tipo de Vulnerabilidad</h2>
    <p>Tipo de Vulnerabilidad: SQL Injection (Error-Based)</p>

    <h2>3. URL Afectada y Parámetro</h2>
    <table>
      <tr><th>URL</th><td><code>{esc(url)}</code></td></tr>
      <tr><th>Parámetro</th><td><code>{esc(param)}</code></td></tr>
      <tr><th>Método</th><td>GET</td></tr>
      <tr><th>Código HTTP</th><td>{esc(status)}</td></tr>
      <tr><th>Motor de base de datos</th><td>{esc(dbms)}</td></tr>
      <tr><th>WAF detectado</th><td>{esc(waf)}</td></tr>
      <tr><th>Confianza del triaje</th><td>{esc(confidence)}</td></tr>
      <tr><th>Firma detectada</th><td>{esc(error)}</td></tr>
    </table>

    <h2>4. Evidencia</h2>
    <pre>{esc(evidence)}</pre>
    <div class="note">
      La evidencia se limita al mensaje de error. No se extrajeron datos, no se
      ejecutaron técnicas de Blind SQLi ni Time-Based y no se intentó explotar
      la vulnerabilidad.
    </div>

    <h2>5. Impacto Potencial</h2>
    <p>{esc(IMPACT)}</p>

    <h2>6. Contacto Sugerido</h2>
    <table>
      <tr><th>Organización</th><td>{esc(organization)}</td></tr>
      <tr><th>Registrador</th><td>{esc(registrar)}</td></tr>
      <tr><th>País WHOIS</th><td>{esc(whois_country)}</td></tr>
      <tr><th>Contacto</th><td>{esc(contact)}</td></tr>
      <tr><th>security.txt</th><td>{esc(security_txt)}</td></tr>
      <tr><th>Fuente de enriquecimiento</th><td>{esc(enrichment_source)}</td></tr>
    </table>
    <p>Si el contacto no es válido, se recomienda localizar el canal oficial de
    seguridad o el buzón de la oficina de TI/CSIRT del organismo.</p>

    <h2>7. Recomendación</h2>
    <ul>
      <li>Validar y sanear todas las entradas en el servidor (lista blanca de
      tipos, longitudes y formatos). No confiar en validaciones del cliente.</li>
      <li>Usar consultas parametrizadas (<em>prepared statements</em>) o un ORM
      que las genere. Nunca concatenar entrada del usuario en la sentencia SQL.</li>
      <li>Aplicar mínimo privilegio al usuario de base de datos de la aplicación
      (sin DDL, sin acceso a otras bases).</li>
      <li>Devolver mensajes de error genéricos y registrar el detalle en logs
      internos, sin exponer rutas, versiones ni estructura de tablas.</li>
      <li>Revisar los logs del servidor web y de la base de datos para descartar
      intentos previos sobre el mismo parámetro.</li>
      <li>Considerar un WAF como control compensatorio, nunca como sustituto del
      saneamiento de código.</li>
    </ul>

    <h2>8. Aviso</h2>
    <div class="note">{esc(DISCLAIMER_NOTE)}</div>

    <footer>
      Reporte generado automáticamente por {esc(APP_NAME)} v{esc(APP_VERSION)}.
      Este documento no constituye una prueba de penetración ni una confirmación
      de explotabilidad.
    </footer>
  </div>
</main>
"""
        return (
            "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>[Security Report] Posible SQL Injection en {esc(url)}</title>\n"
            f"<style>{css}</style>\n</head>\n<body>{body}</body>\n</html>\n"
        )
