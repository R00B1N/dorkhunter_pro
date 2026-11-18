"""Gestión de SQLite con acceso seguro desde varios hilos.

La GUI y los hilos de trabajo comparten una única conexión protegida por un
``RLock``. SQLite en modo WAL tolera bien este patrón y evita el clásico
``database is locked``.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from utils.helpers import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    finished_at   TEXT,
    dork_used     TEXT NOT NULL,
    country       TEXT,
    domain_type   TEXT,
    keywords      TEXT,
    status        TEXT NOT NULL DEFAULT 'running',
    urls_found    INTEGER NOT NULL DEFAULT 0,
    duplicadas    INTEGER NOT NULL DEFAULT 0,
    duplicadas_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    url             TEXT NOT NULL,
    domain          TEXT,
    parametro       TEXT,
    estado          TEXT NOT NULL DEFAULT 'pendiente',
    error_detectado TEXT,
    evidencia       TEXT,
    http_status     INTEGER,
    dbms            TEXT,
    confianza       TEXT,
    contacto        TEXT,
    organizacion    TEXT,
    registrar       TEXT,
    whois_country   TEXT,
    security_txt    TEXT,
    enrichment_source TEXT,
    reporte_path    TEXT,
    estado_reporte  TEXT NOT NULL DEFAULT 'sin_reporte',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    sqlmap_estado   TEXT,
    sqlmap_output   TEXT,
    waf             TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique
    ON findings(scan_id, url, COALESCE(parametro, ''));

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_estado ON findings(estado);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

_FINDING_FIELDS = {
    "domain",
    "parametro",
    "estado",
    "error_detectado",
    "evidencia",
    "http_status",
    "dbms",
    "confianza",
    "contacto",
    "organizacion",
    "registrar",
    "whois_country",
    "security_txt",
    "enrichment_source",
    "reporte_path",
    "estado_reporte",
    "sqlmap_estado",
    "sqlmap_output",
    "waf",
}

# Columnas añadidas después de la primera versión del esquema. SQLite no
# modifica una tabla existente con CREATE TABLE IF NOT EXISTS, así que las
# añadimos de forma idempotente al abrir la base de datos.
_FINDING_COLUMN_MIGRATIONS: dict[str, str] = {
    "dbms": "TEXT",
    "confianza": "TEXT",
    "registrar": "TEXT",
    "whois_country": "TEXT",
    "enrichment_source": "TEXT",
    "sqlmap_estado": "TEXT",
    "sqlmap_output": "TEXT",
    "waf": "TEXT",
}

# Columnas añadidas a ``scans`` para el resumen de URLs duplicadas.
_SCAN_COLUMN_MIGRATIONS: dict[str, str] = {
    "duplicadas": "INTEGER NOT NULL DEFAULT 0",
    "duplicadas_json": "TEXT",
}


class DatabaseManager:
    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), timeout=30, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._ensure_columns()
            self._conn.commit()

    def _ensure_columns(self) -> None:
        """Migra bases de datos creadas por versiones anteriores."""
        self._ensure_table_columns("findings", _FINDING_COLUMN_MIGRATIONS)
        self._ensure_table_columns("scans", _SCAN_COLUMN_MIGRATIONS)

    def _ensure_table_columns(
        self, table: str, migrations: dict[str, str]
    ) -> None:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {str(row["name"]) for row in rows}
        for name, column_type in migrations.items():
            if name not in existing:
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {column_type}"
                )

    # ------------------------------------------------------------------
    # Escaneos
    # ------------------------------------------------------------------
    def create_scan(
        self,
        dork_used: str,
        country: str = "",
        domain_type: str = "",
        keywords: str = "",
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO scans (created_at, dork_used, country, domain_type, keywords, status)
                VALUES (?, ?, ?, ?, ?, 'running')
                """,
                (now_iso(), dork_used, country, domain_type, keywords),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: str, urls_found: int) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE scans
                   SET finished_at = ?, status = ?, urls_found = ?
                 WHERE id = ?
                """,
                (now_iso(), status, int(urls_found), scan_id),
            )
            self._conn.commit()

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return dict(row) if row else None

    def save_scan_duplicates(
        self, scan_id: int, duplicates: list[dict[str, Any]]
    ) -> None:
        """Guarda el resumen de URLs encontradas por varios dorks."""
        payload = json.dumps(duplicates, ensure_ascii=False)
        with self._lock:
            self._conn.execute(
                """
                UPDATE scans
                   SET duplicadas = ?, duplicadas_json = ?
                 WHERE id = ?
                """,
                (len(duplicates), payload, scan_id),
            )
            self._conn.commit()

    def get_scan_duplicates(self, scan_id: int) -> list[dict[str, Any]]:
        """Recupera las URLs duplicadas guardadas para una caza."""
        with self._lock:
            row = self._conn.execute(
                "SELECT duplicadas_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if not row or not row["duplicadas_json"]:
            return []
        try:
            data = json.loads(str(row["duplicadas_json"]))
        except (TypeError, ValueError):
            return []
        return data if isinstance(data, list) else []

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def list_scans_with_counts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Historial enriquecido con número de hallazgos y posibles SQLi."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT s.*,
                       COUNT(f.id) AS findings_count,
                       COALESCE(SUM(
                           CASE WHEN f.estado = 'posible_vuln' THEN 1 ELSE 0 END
                       ), 0) AS vulns_count
                  FROM scans AS s
                  LEFT JOIN findings AS f ON f.scan_id = s.id
                 GROUP BY s.id
                 ORDER BY s.id DESC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Hallazgos
    # ------------------------------------------------------------------
    def add_finding(
        self,
        scan_id: int,
        url: str,
        domain: str = "",
        parametro: str = "",
        estado: str = "pendiente",
        **fields: Any,
    ) -> int:
        """Inserta o actualiza un hallazgo identificado por (scan, url, parámetro)."""
        ts = now_iso()
        extra = {k: v for k, v in fields.items() if k in _FINDING_FIELDS}
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO findings
                    (scan_id, url, domain, parametro, estado, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, url, domain, parametro, estado, ts, ts),
            )
            row = self._conn.execute(
                """
                SELECT id FROM findings
                 WHERE scan_id = ? AND url = ? AND COALESCE(parametro, '') = ?
                """,
                (scan_id, url, parametro or ""),
            ).fetchone()
            finding_id = int(row["id"])
            if extra:
                assignments = ", ".join(f"{key} = ?" for key in extra)
                values = list(extra.values()) + [ts, finding_id]
                self._conn.execute(
                    f"UPDATE findings SET {assignments}, updated_at = ? WHERE id = ?",
                    values,
                )
            self._conn.commit()
            return finding_id

    def update_finding(self, finding_id: int, **fields: Any) -> None:
        allowed = {k: v for k, v in fields.items() if k in _FINDING_FIELDS}
        if not allowed:
            return
        assignments = ", ".join(f"{key} = ?" for key in allowed)
        values = list(allowed.values()) + [now_iso(), finding_id]
        with self._lock:
            self._conn.execute(
                f"UPDATE findings SET {assignments}, updated_at = ? WHERE id = ?",
                values,
            )
            self._conn.commit()

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
        return dict(row) if row else None

    def set_finding_sqlmap(
        self, finding_id: int, estado: str, output_path: str = ""
    ) -> None:
        """Guarda el veredicto de SQLMap para un hallazgo."""
        self.update_finding(
            finding_id,
            sqlmap_estado=estado,
            sqlmap_output=output_path or "",
        )

    def list_findings(
        self, scan_id: int | None = None, only_vulns: bool = False
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM findings"
        clauses: list[str] = []
        params: list[Any] = []
        if scan_id is not None:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if only_vulns:
            clauses.append("estado = 'posible_vuln'")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id ASC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def summary(self, scan_id: int) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT estado, COUNT(*) AS total FROM findings WHERE scan_id = ? GROUP BY estado",
                (scan_id,),
            ).fetchall()
        return {str(r["estado"]): int(r["total"]) for r in rows}

    # ------------------------------------------------------------------
    # Configuración persistente (disclaimer, preferencias)
    # ------------------------------------------------------------------
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
            finally:
                self._conn.close()
