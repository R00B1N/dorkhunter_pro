# DorkHunter Pro

Herramienta de escritorio para **auditoría de superficie de exposición**
mediante Google Dorks, con un núcleo de **detección pasiva de errores SQL** y
una fase opcional de verificación activa con SQLMap. Está pensada para
investigadores de seguridad, equipos de TI y programas de divulgación
responsable.

> **Aviso:** úsala únicamente en sistemas propios o sobre los que tengas
> autorización escrita. Escanear o atacar terceros sin permiso puede ser
> delito. Por defecto, DorkHunter Pro **no explota** vulnerabilidades: el
> triaje pasivo solo envía una comilla simple y busca mensajes de error. La
> verificación con **SQLMap es opcional, está desactivada por defecto** y, si
> la activas, envía payloads reales (y con `--dbs` extrae bases de datos):
> úsala solo dentro de un engagement autorizado.

---

## Características

- **Generación de dorks** por país y tipo de dominio (`edu`, `gov`, `gob`,
  `mil`, `org`, `com`, `net`), con palabras clave y dorks manuales.
- **75 países en 5 regiones + Internacional** (Latinoamérica, Norteamérica y
  Caribe, Europa, Asia y Oceanía, África y Oriente Medio), con el prefijo
  gubernamental real de cada país (`gob.mx`, `gub.uy`, `gouv.fr`, `gc.ca`...).
- **Sugerencias de palabras clave** mientras escribes, insensibles a acentos.
- **Profundidad configurable**: 6, 10, 16, 24 o 32 dorks por caza.
- **Búsqueda en varios motores públicos**: DuckDuckGo, Brave, Bing, Mojeek y,
  opcionalmente, Yahoo o Yandex. Google no se usa. En la GUI puedes elegir el
  motor; en el CLI se usa `--engines`.
- **Rotación de motores**: la opción «Rotación (todos)» de la GUI (o
  `--rotate` en CLI) reparte los motores entre los dorks de una misma caza.
  En la GUI rota los seis motores disponibles; en CLI rota los elegidos con
  `--engines`.
- **URLs duplicadas**: botón para ver las URLs que devolvieron dos o más
  dorks, con el detalle de las fuentes; se guardan en SQLite.
- **Copiar URLs**: botón y `Ctrl+C` para copiar la selección o todas las URLs
  visibles al portapapeles.
- **Detección pasiva de SQLi error-based**: una petición de línea base y una
  petición GET con `'` sobre el parámetro auditable de mayor prioridad.
- **Triaje enriquecido**: prioriza parámetros clásicamente vulnerables, omite
  parámetros de analítica (`utm_*`, `fbclid`, etc.), identifica el motor SQL
  (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2, Firebird, Sybase, Access) y
  asigna un nivel de confianza (`alta`, `media`, `baja`) sin explotar nada.
- **Enriquecimiento**: WHOIS (python-whois con fallback por socket),
  registrador, país y `security.txt`.
- **Detección de WAF**: heurística informativa por cabeceras, cookies y cuerpo
  (Cloudflare, AWS WAF, Sucuri, Imperva, Akamai, F5 BIG-IP, ModSecurity,
  Wordfence, dotDefender). Se guarda por hallazgo, se muestra en la tabla
  (columna **WAF**), en el detalle, en los reportes y en el CSV; si un bloqueo
  403/429 coincide con un WAF conocido, el mensaje lo nombra.
- **Alcance por dominios (allowlist/denylist)**: campos «Solo dominios» y
  «Excluir dominios» (o `--allow-domains` / `--deny-domains` en CLI). Si hay
  allowlist, solo se auditan hosts de esos dominios o subdominios; la
  denylist siempre gana. Se aplica a resultados de búsqueda y a URLs
  manuales/importadas.
- **Fuentes pasivas** (botón «FUENTES PASIVAS» / `--domain-sources`): para un
  dominio concreto consulta **Wayback Machine (CDX)** y **OTX AlienVault** y
  lista subdominios por **crt.sh** (Certificate Transparency). Todo pasivo,
  sin tocar el objetivo; las URLs con parámetros encontradas se convierten en
  objetivos de la caza.
- **Importar .txt de URLs** (botón «IMPORTAR .TXT» / `--url-file`): carga
  listas de waybackurls, gau, Burp o exports propios (una URL por línea,
  `#` para comentarios), filtra las que tienen parámetros y las usa como
  objetivos.
- **Cola manual de SQLMap** (botón «COLA SQLMAP»): pega una lista de URLs y
  ejecuta SQLMap directamente sobre ellas (máx. 50), creando una caza
  «Cola SQLMap» en el historial con monitoreo en vivo incluido.
- **Enviar a SQLMap por hallazgo**: clic derecho en la tabla → «Enviar a
  SQLMap» verifica esa URL concreta con la configuración activa; el menú
  contextual también permite copiar la URL, ver el detalle o abrirla en el
  navegador. Además, la tabla se **ordena por columna** al hacer clic en su
  encabezado.
- **Presets y flags de SQLMap**: menú «Intensidad» (Seguro, Estándar
  `--level=2 --risk=1`, Profundo `--level=3 --risk=2`) más un campo de
  **flags extra** libre (tokenizado con `shlex`, sin shell). En CLI:
  `--sqlmap-preset` y `--sqlmap-flags`.
- **Verificación activa opcional con SQLMap** (desactivada por defecto): tras
  el triaje pasivo, envía URLs a procesos `sqlmap` en segundo plano, con un
  pool configurable de **procesos simultáneos** (1–8) e **hilos internos por
  proceso** (`--threads`). El menú «Objetivos» decide qué se verifica:
  **Vulns + respaldo (todas)** (por defecto: los `posible_vuln` y, si no hubo
  ninguno, todas las URLs con parámetros), **Solo posibles vulns** o **Todas
  las URLs**. El comando equivalente es `proxychains4 sqlmap -u URL --batch
  --random-agent [--threads=N] [--dbs] --output-dir DIR`, donde `proxychains4`
  y `--dbs` son opcionales y están apagados por defecto. Si pides proxychains4
  y el binario no existe, la fase se aborta (nunca corre "sin proxy" por
  accidente). El veredicto (Vulnerable / No vulnerable / Error) se guarda en
  SQLite, se muestra en una columna de la tabla y la salida cruda queda en
  `reports/sqlmap/`.
- **Monitoreo de SQLMap en vivo**: ventana con un panel `[W1]..[Wn]` por URL
  que muestra la salida estándar de cada proceso en tiempo real, con su
  estado (EN CURSO / LIMPIO / VULNERABLE / ERROR) y contadores. Se abre sola
  al arrancar la fase (o desde el botón «Ver SQLMap en vivo»). «Detener»
  termina los procesos en curso y cancela la cola.
- **Reportes** por hallazgo y **reporte agregado de toda la caza** en Markdown,
  HTML o JSON, con evidencia, impacto, contacto y recomendaciones.
- **SQLite** para historial de escaneos, hallazgos, metadatos de triaje y
  estado del reporte. Las bases antiguas se migran automáticamente.
- **Historial de cazas** y **filtros** por URL, dominio, parámetro, motor,
  confianza, contacto o estado.
- **Prueba de URL directa** desde la GUI, sin depender de un dork.
- **Exportación CSV** compatible con Excel y **exportación JSON**.
- **Modo CLI** sin Tkinter para automatización y servidores sin escritorio.
- **GUI oscura** con CustomTkinter, tabla en tiempo real, progreso y logs.
- **Aviso legal** obligatorio en la primera ejecución.

## Requisitos

- Python 3.11 o superior (probado con 3.14).
- Tkinter (incluido en el instalador oficial de Python en Windows/macOS; en
  Linux suele venir en un paquete aparte). **Solo es necesario para la GUI**;
  el modo CLI funciona sin Tkinter.
- Las dependencias de `requirements.txt`.

### Instalación de Tkinter en Linux

```bash
# Debian / Ubuntu
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

## Instalación y ejecución

```bash
cd dorkhunter_pro
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

La base de datos se crea en `data/dorkhunter.db` y los reportes en `reports/`.
Ambas carpetas se crean automáticamente.

> En la primera ejecución aparece el aviso legal. Si lo rechazas, la aplicación
> se cierra. La aceptación se guarda en SQLite (`settings`).

### Modo CLI (sin Tkinter)

```bash
# Caza normal por país/tipo (requiere confirmar autorización con --yes)
python cli.py --country Colombia --type "Educativo (edu)" --yes

# Probar una URL concreta y exportar todos los formatos
python cli.py \
  --url "https://dominio.com/item.php?id=1" \
  --yes --no-enrich \
  --json salida.json --csv salida.csv --report caza.md

# Dork manual, sin escaneo (solo recolección)
python cli.py --dork "site:edu.co inurl:id=" --no-scan --yes

# Ordenar motores de búsqueda (Brave primero, luego Bing y Mojeek)
python cli.py --dork "site:edu.co inurl:id=" --engines "brave,bing,mojeek" --yes

# Rotar motores entre dorks (usa todos en una misma caza)
python cli.py --dork "site:edu.co inurl:id=" --rotate --yes

# Ver países agrupados por región y tipos de dominio disponibles
python cli.py --list-countries
python cli.py --list-types

# Verificación ACTIVA opcional con SQLMap (solo con autorización escrita)
python cli.py --url "https://dominio.com/item.php?id=1" --yes --sqlmap

# SQLMap sobre todas las URLs, con --dbs (EXTRAE datos) y proxychains4
python cli.py --dork "site:edu.co inurl:id=" --yes \
    --sqlmap --sqlmap-all --sqlmap-dbs --proxychains --sqlmap-workers 2

# SQLMap con salida en vivo por consola (verbose imprime cada línea)
python cli.py --url "https://dominio.com/item.php?id=1" --yes --sqlmap \
    --sqlmap-workers 2 --sqlmap-threads 3 --verbose

# Preset de intensidad + flags extra (tokenizados sin shell)
python cli.py --url "https://dominio.com/item.php?id=1" --yes --sqlmap \
    --sqlmap-preset estandar --sqlmap-flags "--forms --titles"

# Importar URLs desde un archivo (.txt, una por línea)
python cli.py --url-file urls_wayback.txt --yes --no-enrich

# Fuentes pasivas para un dominio (Wayback CDX + OTX + crt.sh)
python cli.py --domain-sources "uni.edu.co" --yes

# Restringir el alcance por dominios (denylist gana sobre allowlist)
python cli.py --dork "site:edu.co inurl:id=" --yes \
    --allow-domains "uni.edu.co,gov.co" --deny-domains "lab.uni.edu.co"

# También se puede invocar desde main.py
python main.py --cli --country Colombia --type "Educativo (edu)" --yes
```

El CLI mantiene el mismo alcance pasivo y los mismos límites de red. `--yes`
confirma que tienes autorización escrita; sin ese flag, en un entorno no
interactivo el programa se niega a ejecutar. Los flags de SQLMap
(`--sqlmap`, `--sqlmap-all`, `--sqlmap-dbs`, `--proxychains`,
`--sqlmap-workers`, `--sqlmap-bin`, `--sqlmap-timeout`, `--sqlmap-preset`,
`--sqlmap-flags`) activan la fase activa; las entradas de objetivos admiten
`--url`, `--url-file` y `--domain-sources`, y el alcance se acota con
`--allow-domains` / `--deny-domains`. `--help` muestra todas las opciones
(`--depth`, `--max-results`, `--max-urls`, `--db`, `--quiet`, etc.).

## Estructura

```
dorkhunter_pro/
├── main.py                     # Punto de entrada (CTk + disclaimer + --cli)
├── cli.py                      # Modo CLI sin Tkinter
├── config.py                   # Límites, rutas, User-Agent
├── requirements.txt
├── README.md
├── gui/
│   ├── theme.py                # Paleta y estilos ttk (Treeview)
│   ├── disclaimer.py           # Aviso legal modal
│   ├── dashboard.py            # Panel principal, filtros, tabla, logs
│   ├── duplicates.py           # Ventana de URLs duplicadas
│   ├── sqlmap_monitor.py       # Consolas en vivo [W1..Wn] de SQLMap
│   ├── sqlmap_queue.py         # Cola manual de SQLMap (pegar y ejecutar)
│   ├── history.py              # Historial de cazas
│   └── finding_detail.py       # Detalle + generación de reportes
├── core/
│   ├── dork_engine.py          # site:, inurl:, intext:
│   ├── search_engine.py        # DuckDuckGo, Brave, Bing, Mojeek
│   ├── sqli_scanner.py         # Una comilla, firmas, motor, confianza y WAF
│   ├── passive_sources.py      # Wayback CDX, OTX y crt.sh (pasivo)
│   ├── sqlmap_runner.py        # Fase ACTIVA opcional con SQLMap
│   ├── whois_lookup.py         # WHOIS + security.txt
│   ├── report_generator.py     # Markdown / HTML / JSON (hallazgo y caza)
│   └── orchestrator.py         # Pipeline en hilo + cola de eventos
├── database/
│   └── db_manager.py           # SQLite (WAL, RLock, migraciones)
├── utils/
│   └── helpers.py              # Fechas, sanitización, redacción
├── tests/
│   ├── test_core.py            # Pruebas base
│   ├── test_enhancements.py    # Triaje, migración, reportes y CLI
│   ├── test_search_engines.py  # Motores de búsqueda y respaldo
│   ├── test_sqlmap.py          # Fase opcional SQLMap
│   └── test_power_features.py  # WAF, dominios, fuentes pasivas, presets
├── data/                       # Base de datos (generada)
└── reports/                    # Reportes y salida de SQLMap (generados)
```

## Cómo funciona

1. **Dorks**: `DorkEngine` combina `site:{sufijo}` con `inurl:{parametro}=` y,
   si hay palabras clave, una o varias cláusulas `intext:"..."` (las palabras
   separadas por comas se convierten en cláusulas independientes). El sufijo se
   deriva del país y del tipo de dominio (`Colombia + edu` → `edu.co`;
   `México + gov` → `gob.mx`).
2. **Búsqueda**: `SearchEngine` traduce `intext:` a frases entre comillas y
   consulta los motores configurados. La consulta se adapta por motor: en
   Bing, Brave, Yahoo y Yandex (que no soportan `inurl:`) el parámetro se
   convierte en frase entre comillas; DuckDuckGo y Mojeek lo conservan. La
   librería `ddgs` intenta un backend concreto; si no devuelve nada, se usa
   el HTML público de Bing, Brave o Mojeek. Yahoo y Yandex son opcionales vía
   `--engines`. Google no se usa. En modo rotación, cada dork empieza por un
   motor distinto y usa el resto como respaldo, de modo que una caza reparte
   la carga entre todos los motores.
3. **Filtro de alcance**: solo se aceptan URLs cuyo host pertenece al `site:`
   del dork y que tengan cadena de consulta. Si definiste allowlist/denylist
   de dominios («Solo dominios» / «Excluir dominios»), esos filtros también se
   aplican aquí y a las URLs manuales; la denylist siempre gana. Se limita a
   40 URLs por caza.
4. **Escaneo**: para cada URL se elige el parámetro auditable con mayor
   prioridad (`id`, `cat`, `page`...); los parámetros de analítica (`utm_*`,
   `fbclid`, etc.) se omiten. Se descartan `login`, `logout`, `delete`, `pay`,
   `token`, etc. Se hace una petición base y otra con `'` (URL-encoded como
   `%27`). Si aparece una firma de error nueva (MySQL, PostgreSQL, MSSQL,
   Oracle, SQLite, DB2, Firebird, Sybase, Access), se marca `posible_vuln`,
   se identifica el motor y se asigna confianza (`alta` si la línea base estaba
   limpia y el estado HTTP no cambió; `media` si la base falló o hubo 5xx;
   `baja` para firmas SQL genéricas sin base). Hay un mínimo de 1,5 s entre
   peticiones al mismo host y un máximo de 512 KB por respuesta. En cada
   respuesta se busca además la huella de un **WAF** (cabeceras, cookies y
   cuerpo) y se guarda por hallazgo; un bloqueo 403/429 con WAF conocido
   queda etiquetado con su nombre.
5. **Enriquecimiento**: para cada `posible_vuln` se extrae el dominio raíz, se
   consulta WHOIS (organización, registrador, país y correo) y se busca
   `/.well-known/security.txt` y `/security.txt`.
6. **Reporte**: desde el detalle (doble clic) se genera Markdown, HTML o JSON
   por hallazgo; desde la barra superior se genera un reporte agregado de la
   caza. La evidencia se redacta para eliminar correos, hashes y tokens largos.
7. **Verificación activa (opcional)**: solo si activaste SQLMap, se seleccionan
   los objetivos según el modo elegido — «Vulns + respaldo (todas)» (por
   defecto: los `posible_vuln` y, si no hubo ninguno, todas las URLs con
   parámetros), «Solo posibles vulns» o «Todas las URLs» —, se validan los
   binarios y `SqlmapRunner` lanza procesos `sqlmap` en paralelo (2 por
   defecto, configurable de 1 a 8) con `--threads` interno opcional. Cada
   proceso transmite su salida línea a línea (`sqlmap_started`/`sqlmap_line`
   con el ID de worker) hacia la ventana de monitoreo. Cada veredicto se
   guarda en SQLite (`findings.sqlmap_estado` / `sqlmap_output`), se emite a
   la GUI y la salida cruda se escribe en `reports/sqlmap/scan_<id>/`. Si el
   binario de `proxychains4` falta, la fase se aborta; si falta `sqlmap`, la
   fase se omite con un aviso y el triaje pasivo se conserva. «Detener»
   termina los procesos activos con SIGTERM y cancela los pendientes.

### Historial, filtros, duplicadas y URL directa

- **Historial** abre las cazas guardadas en SQLite y permite recargarlas sin
  volver a hacer peticiones de red.
- Los **filtros** de la tabla buscan por URL, dominio, parámetro, motor,
  confianza o contacto, y permiten aislar un estado (`Posible Vuln`, `Error`,
  `Bloqueado`, etc.).
- **Probar URL directa** permite auditar un enlace concreto con parámetros,
  útil cuando ya se conoce el objetivo y no se quiere depender de un dork.
- **Duplicadas** muestra las URLs que aparecieron en más de un dork, con el
  número de repeticiones y los dorks que las devolvieron. El resumen se guarda
  en SQLite y sigue disponible al recargar la caza desde el historial.
- **Copiar URLs** copia la selección de la tabla o, si no hay selección, todas
  las filas visibles; `Ctrl+C` hace lo mismo. La ventana de duplicadas también
  permite copiar las URLs seleccionadas o todas.
- La tabla muestra **Motor**, **WAF**, **Confianza** y **SQLMap** para
  priorizar la revisión manual; la columna SQLMap muestra el veredicto de la
  verificación activa cuando está activada («Vulnerable», «No vulnerable»,
  «Error» o «—»). Cada columna se ordena al hacer clic en su encabezado
  (clic de nuevo invierte el orden).
- **Clic derecho** sobre una fila abre un menú contextual: copiar la URL, ver
  el detalle, **Enviar a SQLMap** (verificación activa de esa URL concreta,
  con confirmación propia) y abrir en el navegador.
- **Importar .txt** carga listas de URLs (waybackurls, gau, Burp), **Fuentes
  pasivas** consulta Wayback/OTX/crt.sh para un dominio concreto y **Cola
  SQLMap** pega URLs y las verifica directamente (crea una caza «Cola SQLMap»
  en el historial, con monitoreo en vivo).

### Hilos

`HuntOrchestrator.run()` se ejecuta en un `threading.Thread` daemon. Toda la
comunicación con la GUI pasa por `queue.Queue`; `Dashboard._poll_events()` la
vacía cada 120 ms desde el hilo de Tk. Ningún widget se toca desde un hilo de
trabajo. El escaneo usa un `ThreadPoolExecutor` de 3 workers y el botón
**Detener** activa un `threading.Event` que se comprueba en cada petición.

La fase de SQLMap tiene dos niveles de concurrencia: **procesos
simultáneos** (`workers`, 1–8; un worker = un panel `[Wn]` del monitoreo) e
**hilos internos de sqlmap** (`--threads`, por defecto 1). La salida de cada
proceso se lee con un hilo lector + cola con timeout, de modo que la
cancelación funciona aunque el proceso esté en silencio: **Detener** envía
SIGTERM a los procesos en curso, cancela los pendientes y sus resultados
parciales se registran como `Error`.

## Configuración

Edita `config.py`:

| Constante | Por defecto | Descripción |
|---|---:|---|
| `CONTACT_EMAIL` | `security@example.org` | **Cámbialo**: va en el User-Agent |
| `MAX_URLS_PER_HUNT` | 40 | Tope de URLs por caza |
| `MAX_RESULTS_PER_DORK` | 25 | Resultados por consulta |
| `DEFAULT_DORK_COUNT` | 10 | Dorks por defecto (CLI y opción «Normal») |
| `SCAN_DELAY_PER_HOST` | 1.5 s | Espaciado por host |
| `SCAN_WORKERS` | 3 | Peticiones simultáneas |
| `HTTP_TIMEOUT` | 10 s | Timeout por petición |
| `MAX_BODY_BYTES` | 512 KB | Tamaño máximo leído por respuesta |
| `MAX_REDIRECTS` | 3 | Redirecciones máximas por petición |
| `SEARCH_DELAY` | 2 s | Espaciado entre consultas a un motor |
| `SEARCH_RETRIES` | 3 | Reintentos del fallback HTML |
| `SEARCH_ENGINES` | DDG, Brave, Bing, Mojeek | Motores usados por defecto |
| `WHOIS_DELAY` | 2 s | Espaciado entre WHOIS |
| `SQLMAP_BIN` | `sqlmap` | Binario de SQLMap (fase activa opcional) |
| `PROXYCHAINS_BIN` | `proxychains4` | Binario del wrapper proxychains |
| `SQLMAP_TIMEOUT` | 600 s | Segundos máximos por URL de SQLMap |
| `SQLMAP_WORKERS` | 2 | Procesos sqlmap simultáneos |

El CLI permite sobrescribir `--max-urls`, `--max-results`, `--depth`, `--engines`,
`--rotate`, `--db` y las opciones de SQLMap (`--sqlmap-*`, `--proxychains`) sin
editar `config.py`.

## Pruebas

```bash
python -m unittest discover -s tests -v
```

Actualmente son **102 pruebas**. Cubren el motor de dorks (países por región,
sufijos gubernamentales, sugerencias de palabras clave y profundidad), el
dominio raíz, SQLite (incluida la migración de esquemas antiguos, el resumen
de URLs duplicadas, las columnas/roundtrip de SQLMap y la columna de WAF),
los reportes por hallazgo y agregados, el escáner (con un servidor HTTP local
que simula errores SQL y cabeceras de WAF), la detección de WAF, la
priorización de parámetros, los metadatos de motor/confianza, la
normalización de URLs directas, el alcance por dominios (allowlist/denylist),
los parsers de fuentes pasivas (Wayback/OTX/crt.sh), los presets y flags de
SQLMap, la rotación de motores, los motores de búsqueda y sus respaldos, los
helpers del CLI (incluido `--url-file`) y la fase opcional de SQLMap
(construcción del comando sin shell, validación de binarios, runner con un
binario falso, streaming en vivo con ID de worker, timeout, cancelación con
terminación del proceso y selección de objetivos).
No requieren Tkinter ni red externa.

## Limitaciones conocidas

- **Motores públicos**: DuckDuckGo, Brave, Bing y Mojeek no son Google.
  `inurl:` e `intext:` son aproximados y los resultados varían; en Bing,
  Brave, Yahoo y Yandex el `inurl:` se convierte en frase entre comillas y los
  resultados fuera del dominio del `site:` se descartan, por lo que a veces se
  obtienen menos URLs (precisión sobre ruido). Para dorks muy específicos usa
  el campo **Dork manual**.
- **Falsos positivos**: un mensaje de error puede provenir de una página de
  error genérica, de un WAF o de la línea base. El escáner compara con la línea
  base, pero la confirmación siempre requiere una prueba autorizada. La
  confianza (`alta`/`media`/`baja`) es una heurística de triaje, no una
  confirmación.
- **Un parámetro por URL**: se prueba el parámetro con mayor prioridad. Si el
  hallazgo está en otro parámetro, usa una URL directa con ese parámetro o
  revisa manualmente.
- **WHOIS redactado**: muchos registros ocultan el correo por GDPR. En ese caso
  el contacto será `No disponible`; usa `security.txt` o el CSIRT del país.
- **WAF/rate limit**: si un sitio responde 403/429, se marca `Bloqueado` y no se
  insiste.
- **Solo GET**: no se prueban formularios POST, cabeceras ni cookies.
- **Veredicto de SQLMap heurístico**: la fase activa clasifica por código de
  salida y frases en la salida estándar («is vulnerable», etc.). Un timeout o
  un error se marcan como `Error`, no como «no vulnerable»; revisa la salida
  cruda en `reports/sqlmap/` antes de descartar una URL.
- **SQLMap requiere el binario**: la fase activa necesita `sqlmap` (y
  `proxychains4`, si lo activas) instalado y accesible en el PATH o vía
  `--sqlmap-bin`. Sin binario, la fase se omite y la caza sigue siendo pasiva.

## Ética y legal

- La herramienta muestra un aviso legal en la primera ejecución (la versión
  1.1 del aviso incluye la fase activa y pide re-aceptación) y pide una
  confirmación de alcance antes del primer escaneo. En CLI, el flag `--yes`
  cumple la misma función; sin él, un entorno no interactivo no ejecuta la
  caza.
- El triaje pasivo se limita a una comilla y a la observación de errores. La
  verificación con SQLMap es la excepción explícita: está desactivada por
  defecto, exige una confirmación propia (checkbox + diálogo en GUI; `--sqlmap`
  + `--yes` en CLI) y solo debe ejecutarse sobre sistemas con autorización
  escrita. `--dbs` extrae datos: actívalo únicamente si tu autorización lo
  permite. `proxychains4` solo cambia el origen del tráfico; no legaliza nada.
- El comando de SQLMap se construye como lista de argumentos (sin shell), de
  modo que la URL no puede inyectar comandos al proceso.
- Los reportes incluyen esta nota:

  > Este hallazgo fue detectado mediante análisis pasivo de OSINT. Se
  > recomienda al equipo de TI realizar una prueba de penetración autorizada
  > para confirmar la vulnerabilidad.

- Si encuentras un hallazgo, contacta por el canal de `security.txt`, el
  correo de abuso del WHOIS o el CSIRT del país. No publiques la URL antes de
  que el responsable haya tenido un plazo razonable para corregir.
