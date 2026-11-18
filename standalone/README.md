# DorkHunter Pro — edición mono-script (standalone)

`dorkhunter_pro_mono.py` es una **copia autocontenida en un solo archivo** de
toda la lógica no-GUI del proyecto. El proyecto original (con su GUI y sus
módulos) **sigue siendo la referencia** y no se modifica.

## Qué incluye

Exactamente lo mismo que el modo CLI del proyecto: dorks por país/tipo,
búsqueda en motores públicos (sin Google), triaje pasivo de SQLi con una
comilla por URL (motor + confianza + detección de WAF), enriquecimiento
WHOIS/security.txt, fuentes pasivas (Wayback/OTX/crt.sh), importación de
`.txt`, allowlist/denylist de dominios, verificación ACTIVA opcional con
SQLMap (apagada por defecto, presets y flags, hasta 8 procesos), historial en
SQLite, CSV/JSON y reportes MD/HTML/JSON. **No incluye la GUI.**

## Uso

```bash
# Con el intérprete del proyecto (tiene las dependencias instaladas):
../.env/bin/python dorkhunter_pro_mono.py --country Colombia --type "Educativo (edu)" --yes
../.env/bin/python dorkhunter_pro_mono.py --url "https://dominio.com/item.php?id=1" --yes
../.env/bin/python dorkhunter_pro_mono.py --help
```

También funciona con cualquier Python 3.11+ que tenga `requests`, `ddgs`,
`bs4` y (opcional) `python-whois`: copia el archivo a donde quieras y sus
carpetas `data/` y `reports/` se crean junto a él (aisladas del proyecto
original).

Nota: si mueves el archivo a otra carpeta, regenera la copia para que las
rutas internas apunten allí (ver abajo); la ruta se fija al generar.

## Regenerar la copia

La copia se genera mecánicamente desde el código fuente (sin tocarlo):

```bash
python /tmp/opencode/build_mono.py   # o donde viva el generador
```

Tras regenerar, corre las pruebas: `python -m unittest discover -s tests`
incluye `test_standalone.py`, que verifica que la copia compila, tiene una
sola guardia `__main__` y expone la misma API que los módulos originales.

## Etica y legal

Idéntico al proyecto principal: solo sistemas propios o con autorización
escrita; el triaje pasivo no explota nada, y la fase de SQLMap exige
confirmación explícita (`--yes` en no interactivo) y extrae datos solo con
`--dbs`.
