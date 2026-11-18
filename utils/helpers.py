"""Utilidades pequeñas y sin dependencias pesadas."""
from __future__ import annotations

import html
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")


def now_iso() -> str:
    """Fecha local en ISO-8601 con zona horaria."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def strip_html(text: str) -> str:
    """Convierte HTML en texto plano legible (sin dependencias)."""
    if not text:
        return ""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def redact_sensitive(text: str) -> str:
    """Elimina correos, hashes y tokens largos de la evidencia almacenada."""
    if not text:
        return ""
    text = _EMAIL_RE.sub("[correo redactado]", text)
    text = _HEX_RE.sub("[hash redactado]", text)
    text = _B64_RE.sub("[token redactado]", text)
    return text


def sanitize_filename(value: str, max_len: int = 60) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return (value[:max_len] or "sin_nombre")


def open_path(path: str | Path) -> bool:
    """Abre un archivo o carpeta con la aplicación predeterminada del sistema."""
    target = str(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(target)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
        return True
    except Exception:
        return False
