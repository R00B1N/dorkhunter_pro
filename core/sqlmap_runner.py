"""Verificación activa con SQLMap (opcional, separada del triaje pasivo).

DorkHunter Pro es pasivo por diseño: una comilla y observación de errores.
Esta fase es un EXTRA explícito que el usuario debe activar. Ejecuta el
binario ``sqlmap`` como subproceso (en un pool de hilos) sobre un conjunto
reducido de URLs, transmite su salida estándar en vivo (eventos
``sqlmap_started``/``sqlmap_line`` por worker) y guarda el veredicto por
hallazgo.

REGLAS:
  • Solo sobre sistemas con autorización escrita y vigente.
  • ``--dbs`` extrae bases de datos: solo si el alcance lo permite.
  • El comando se construye como lista de argumentos (sin shell), de modo
    que la URL no puede inyectar comandos.
  • Si pides proxychains4 y el binario no existe, la fase se aborta: nunca
    se ejecuta "sin proxy" por accidente.
"""
from __future__ import annotations

import queue
import re
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from config import (
    PROXYCHAINS_BIN,
    SQLMAP_BIN,
    SQLMAP_TIMEOUT,
    SQLMAP_WORKERS,
)

SQLMAP_VULNERABLE = "sqlmap_vulnerable"
SQLMAP_CLEAN = "sqlmap_limpio"
SQLMAP_ERROR = "sqlmap_error"

SQLMAP_LABELS: dict[str, str] = {
    SQLMAP_VULNERABLE: "Vulnerable",
    SQLMAP_CLEAN: "No vulnerable",
    SQLMAP_ERROR: "Error",
}

# Frases con las que SQLMap confirma una inyección en su salida estándar.
_VULN_MARKERS = re.compile(
    r"is vulnerable|is prone to|injection\(s\) found|"
    r"identified the following injection",
    re.IGNORECASE,
)

# Máximo de líneas que se transmiten en vivo por proceso; la salida completa
# siempre se escribe en el archivo de reporte.
MAX_STREAM_LINES = 4000

TARGET_VULNS = "vulns"
TARGET_ALL = "all"
TARGET_AUTO = "auto"  # vulns primero; si no hay, todas las URLs con parámetros

# Presets de intensidad: flags extra que acompañan al comando base.
SQLMAP_PRESET_FLAGS: dict[str, tuple[str, ...]] = {
    "seguro": (),  # Por defecto: batch, sin subir nivel ni riesgo.
    "estandar": ("--level", "2", "--risk", "1"),
    "profundo": ("--level", "3", "--risk", "2"),
}


def preset_extra_flags(name: str) -> tuple[str, ...]:
    """Flags del preset indicado (seguro/estandar/profundo)."""
    key = str(name or "seguro").strip().lower()
    if key == "estándar":
        key = "estandar"
    return SQLMAP_PRESET_FLAGS.get(key, ())


def parse_extra_flags(text: str) -> tuple[str, ...]:
    """Tokeniza flags libres escritos por el usuario con ``shlex.split``.

    Solo se separan tokens; no se ejecuta ningún shell. Los tokens vacíos
    se descartan.
    """
    try:
        tokens = shlex.split(str(text or ""))
    except ValueError:
        tokens = str(text or "").split()
    return tuple(token for token in tokens if token)


@dataclass
class SqlmapConfig:
    """Configuración de la fase de verificación activa."""

    enabled: bool = False
    sqlmap_bin: str = SQLMAP_BIN
    proxychains_bin: str = PROXYCHAINS_BIN
    use_proxychains: bool = False
    random_agent: bool = True
    enumerate_dbs: bool = False
    targets: str = TARGET_AUTO          # "auto" | "vulns" | "all"
    extra_flags: tuple[str, ...] = field(default_factory=tuple)
    timeout: int = SQLMAP_TIMEOUT
    workers: int = SQLMAP_WORKERS        # procesos sqlmap simultáneos
    sqlmap_threads: int = 1              # --threads de sqlmap (por proceso)
    output_dir: Path | None = None

    def __post_init__(self) -> None:
        if int(self.workers) < 1:
            self.workers = 1
        if int(self.workers) > 8:
            self.workers = 8
        if int(self.sqlmap_threads) < 1:
            self.sqlmap_threads = 1
        if int(self.sqlmap_threads) > 16:
            self.sqlmap_threads = 16
        if int(self.timeout) < 30:
            self.timeout = 30
        if self.targets not in {TARGET_VULNS, TARGET_ALL, TARGET_AUTO}:
            self.targets = TARGET_AUTO


def build_sqlmap_command(url: str, config: SqlmapConfig) -> list[str]:
    """Construye el comando como lista de argumentos (sin shell).

    Equivale a ``[proxychains4] sqlmap -u URL --batch --random-agent [--dbs]
    [--threads=N] --output-dir DIR`` más las banderas extra configuradas.
    """
    command: list[str] = []
    if config.use_proxychains and config.proxychains_bin:
        command.append(config.proxychains_bin)
    command.append(config.sqlmap_bin)
    command.extend(["-u", url])
    command.append("--batch")
    if config.random_agent:
        command.append("--random-agent")
    if config.enumerate_dbs:
        command.append("--dbs")
    if int(config.sqlmap_threads) > 1:
        command.append(f"--threads={int(config.sqlmap_threads)}")
    if config.output_dir is not None:
        command.extend(["--output-dir", str(config.output_dir)])
    command.extend(str(flag) for flag in config.extra_flags if str(flag))
    return command


def validate_sqlmap_config(config: SqlmapConfig) -> list[str]:
    """Devuelve los problemas que deben impedir ejecutar SQLMap."""
    problems: list[str] = []
    if not shutil.which(config.sqlmap_bin) and not Path(config.sqlmap_bin).is_file():
        problems.append(
            f"El binario de SQLMap no se encontró: {config.sqlmap_bin}"
        )
    if config.use_proxychains:
        if not config.proxychains_bin:
            problems.append("proxychains está activado pero sin binario configurado.")
        elif not shutil.which(config.proxychains_bin) and not Path(
            config.proxychains_bin
        ).is_file():
            problems.append(
                f"El binario de proxychains no se encontró: {config.proxychains_bin}"
            )
    return problems


class SqlmapRunner:
    """Ejecuta SQLMap en paralelo, transmite su salida y guarda el veredicto."""

    def __init__(
        self,
        config: SqlmapConfig,
        db,
        emit: Callable[[dict[str, Any]], None],
        cancel_event: threading.Event,
    ) -> None:
        self.config = config
        self.db = db
        self.emit = emit
        self.cancel = cancel_event
        self.output_dir = (
            Path(config.output_dir)
            if config.output_dir is not None
            else None
        )

    # ------------------------------------------------------------------
    def run(
        self,
        items: list[dict[str, Any]],
        on_progress: Callable[[int, int], None] | None = None,
    ) -> dict[str, int]:
        """Ejecuta SQLMap sobre ``items`` (dicts con ``finding_id`` y ``url``).

        Devuelve un resumen ``{"sqlmap_vulnerable": n, ...}``. Cada proceso
        recibe un ID de worker (1..N) para que la GUI pueda mostrar N
        consolas en vivo.
        """
        counts = {SQLMAP_VULNERABLE: 0, SQLMAP_CLEAN: 0, SQLMAP_ERROR: 0}
        if not items:
            return counts
        if self.output_dir is not None:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        workers = max(1, int(self.config.workers))
        free_worker_ids: "queue.Queue[int]" = queue.Queue()
        for worker_id in range(1, workers + 1):
            free_worker_ids.put(worker_id)

        def job(item: dict[str, Any]) -> tuple[str, str] | None:
            if self.cancel.is_set():
                return None  # omitido: la caza fue cancelada antes de lanzar
            worker_id = free_worker_ids.get()
            try:
                return self.run_one(item, worker_id)
            finally:
                free_worker_ids.put(worker_id)

        total = len(items)
        done = 0
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="sqlmap"
        ) as pool:
            futures = {pool.submit(job, item): item for item in items}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    outcome = future.result()
                except CancelledError:
                    continue
                except Exception as exc:  # pragma: no cover - salvaguarda
                    outcome = (SQLMAP_ERROR, "")
                    self._log(
                        "error",
                        f"SQLMap falló para {item.get('url')}: {exc}",
                    )
                if outcome is None:
                    continue
                estado, output_path = outcome
                counts[estado] = counts.get(estado, 0) + 1
                self._store(item, estado, output_path)
                done += 1
                if on_progress is not None:
                    on_progress(done, total)
                if self.cancel.is_set():
                    # Los pendientes se cancelan; los en curso llegan a este
                    # mismo bucle cuando run_one corta y los registra.
                    for pending in futures:
                        pending.cancel()
        return counts

    # ------------------------------------------------------------------
    def run_one(self, item: dict[str, Any], worker_id: int = 0) -> tuple[str, str]:
        """Lanza un proceso sqlmap y transmite su salida línea a línea.

        La lectura usa un hilo lector + una cola con timeout, de modo que la
        cancelación funciona incluso cuando el proceso no imprime nada.
        """
        url = str(item.get("url") or "")
        command = build_sqlmap_command(url, self.config)
        self.emit(
            {
                "type": "sqlmap_started",
                "url": url,
                "worker": int(worker_id),
            }
        )
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            self._log("error", f"No se pudo ejecutar {command[0]}: {exc}")
            return SQLMAP_ERROR, ""

        incoming: "queue.Queue[str | None]" = queue.Queue()

        def pump() -> None:
            try:
                assert proc.stdout is not None
                for raw in proc.stdout:
                    incoming.put(raw.rstrip("\r\n"))
            except Exception:  # pragma: no cover - pipe cerrado
                pass
            finally:
                incoming.put(None)  # marcador de fin de flujo

        reader = threading.Thread(
            target=pump, daemon=True, name=f"sqlmap-read-{worker_id}"
        )
        reader.start()

        # Watchdog: si sqlmap se cuelga, el kill libera el hilo de lectura.
        watchdog = threading.Timer(int(self.config.timeout), proc.kill)
        watchdog.daemon = True
        watchdog.start()

        lines: list[str] = []
        try:
            while True:
                try:
                    line = incoming.get(timeout=0.2)
                except queue.Empty:
                    if self.cancel.is_set():
                        proc.terminate()
                        break
                    if not watchdog.is_alive():
                        # El watchdog ejecutó kill: proceso colgado, timeout.
                        break
                    continue
                if line is None:
                    break
                lines.append(line)
                if len(lines) <= MAX_STREAM_LINES:
                    self.emit(
                        {
                            "type": "sqlmap_line",
                            "url": url,
                            "worker": int(worker_id),
                            "line": line,
                        }
                    )
        finally:
            watchdog.cancel()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover - salvaguarda
                proc.kill()
                proc.wait(timeout=15)
            reader.join(timeout=5)

        output = "\n".join(lines)
        output_path = self._dump_output(item, url, output)
        if proc.returncode != 0:
            reason = (
                "agotó el tiempo"
                if proc.returncode is not None and proc.returncode < 0
                else f"terminó con código {proc.returncode}"
            )
            self._log("warn", f"SQLMap {reason} para {url}.")
            return SQLMAP_ERROR, output_path
        if _VULN_MARKERS.search(output):
            return SQLMAP_VULNERABLE, output_path
        return SQLMAP_CLEAN, output_path

    # ------------------------------------------------------------------
    def _dump_output(self, item: dict[str, Any], url: str, text: Any) -> str:
        """Guarda la salida cruda de SQLMap junto al resto de reportes."""
        if self.output_dir is None:
            return ""
        try:
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", url)[:120].strip("_") or "url"
            suffix = str(item.get("finding_id") or "x")
            path = self.output_dir / f"finding_{suffix}_{safe}.txt"
            body = text if isinstance(text, str) else str(text)
            path.write_text(body or "", encoding="utf-8", errors="replace")
            return str(path)
        except OSError:
            return ""

    # ------------------------------------------------------------------
    def _store(self, item: dict[str, Any], estado: str, output_path: str) -> None:
        finding_id = item.get("finding_id")
        url = str(item.get("url") or "")
        if finding_id is not None:
            try:
                self.db.set_finding_sqlmap(int(finding_id), estado, output_path)
            except Exception:  # pragma: no cover - salvaguarda de la GUI
                pass
        self.emit(
            {
                "type": "sqlmap",
                "finding_id": finding_id,
                "url": url,
                "estado": estado,
                "estado_label": SQLMAP_LABELS.get(estado, estado),
                "output": output_path,
            }
        )
        level = "ok" if estado == SQLMAP_VULNERABLE else "muted"
        message = f"SQLMap · {url}: {SQLMAP_LABELS.get(estado, estado)}"
        if estado == SQLMAP_ERROR and output_path:
            message += f" (salida: {output_path})"
        self._log(level, message)

    def _log(self, level: str, message: str) -> None:
        self.emit({"type": "log", "level": level, "message": message})
