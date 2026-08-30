# keylogger-detector

Detecta **comportamiento** típico de keyloggers y de malware que roba
contraseñas, analizando los procesos en ejecución — no por nombre de
archivo (trivial de evadir: basta con renombrar el ejecutable), sino
por lo que el proceso hace y dónde se ancla al sistema.

## Las cuatro familias de señales

| # | Señal | Cómo se detecta | Plataforma |
|---|---|---|---|
| 1 | Captura de teclado | Se inspeccionan los **imports** del ejecutable en busca de `SetWindowsHookEx`, `GetAsyncKeyState`/`GetKeyState`/`GetKeyboardState`, o `RegisterRawInputDevices` (las tres únicas formas de leer el teclado en Windows) | Windows (requiere `pefile`) |
| 2 | Acceso a almacén de credenciales | Un proceso que **no es el navegador** tiene abierto el archivo donde Chrome/Edge/Brave/Firefox guardan las contraseñas (`Login Data`, `logins.json`, `key4.db`) | Windows, Linux, macOS |
| 3 | Persistencia | El ejecutable del proceso coincide con una entrada de auto-inicio (registro `Run`, tarea programada, `cron`, autostart XDG, `LaunchAgent`) | Windows, Linux, macOS |
| 4 | Red externa | *Solo como agravante* — si ya hay otra señal, y además el proceso mantiene una conexión activa a una IP pública | Todas |

Cada señal suma puntos (`SIGNAL_POINTS` en el código) y el total decide
un nivel: **bajo** (no se reporta) / **medio** / **alto**. Ninguna
señal aislada llega a "alto" — hace falta corroboración entre al
menos dos familias distintas. Esto está garantizado por un test
(`test_no_single_signal_reaches_alto_alone`), no solo documentado.

## Por qué NO es una lista de nombres de proceso

Un detector que compara `"si el nombre contiene 'keylog'"` se evade
renombrando un archivo. Por eso el 95% del peso está en **comportamiento**
verificable (qué APIs importa, qué archivos tiene abiertos, dónde se
auto-inicia) y solo un 5% (`nombre_sospechoso`, la señal más débil de
la tabla) mira el nombre — y nunca alcanza "alto" por sí sola.

## Uso

```bash
pip install -r requirements.txt
# En Windows, además:
pip install pefile

python keylogger_detector.py                    # un escaneo, tabla en consola
python keylogger_detector.py --threshold 30     # solo mostrar score >= 30
python keylogger_detector.py --list-persistence # solo listar auto-inicios
python keylogger_detector.py --watch            # monitoreo continuo (Ctrl+C corta)
python keylogger_detector.py --watch --interval 10
```

Con `just`:

```bash
just setup
just scan
just watch 15        # cada 15 segundos
just persistence
```

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Nada por encima del umbral, o solo riesgo "bajo" |
| `1` | Algún proceso llegó a riesgo "medio" |
| `2` | Algún proceso llegó a riesgo "alto" |

## Ejecutarlo realmente "en segundo plano"

`--watch` corre en un bucle continuo, pero sigue atado a la terminal
que lo lanzó. Para que sobreviva al cierre de sesión o al reinicio,
elegí según tu sistema:

**Linux (systemd, usuario):**
```ini
# ~/.config/systemd/user/keylog-detect.service
[Unit]
Description=Keylogger behavior detector

[Service]
ExecStart=/ruta/a/.venv/bin/python /ruta/a/keylogger_detector.py --watch --interval 60
Restart=on-failure

[Install]
WantedBy=default.target
```
```bash
systemctl --user daemon-reload
systemctl --user enable --now keylog-detect.service
journalctl --user -u keylog-detect -f   # ver las alertas
```

**Windows:** Programador de tareas → "Crear tarea básica" → desencadenador
"Al iniciar sesión" → acción `python.exe` con argumentos
`keylogger_detector.py --watch`.

**Cualquier Unix, rápido y sucio:**
```bash
nohup python keylogger_detector.py --watch > keylog-detect.log 2>&1 &
disown
```

## Limitaciones (leelas antes de confiar en esto)

- **No es un antivirus.** No tiene firmas, no analiza memoria, no
  desempaqueta binarios ofuscados. Un keylogger empaquetado o con
  componente en modo kernel puede evadirlo sin esfuerzo.
- **No lee ni registra teclas en ningún momento.** Solo observa
  metadatos de *otros* procesos (nombre, ejecutable, imports, archivos
  abiertos, conexiones) — la propia herramienta nunca toca el teclado.
- El chequeo de imports de Windows requiere `pefile` y solo aplica a
  `.exe`. Sin esa librería, esa señal (la más fuerte de la tabla) queda
  deshabilitada y el programa te avisa al arrancar.
- **Hay falsos positivos posibles**: un gestor de contraseñas legítimo,
  o una utilidad de accesibilidad, pueden disparar alguna señal. Por
  eso el resultado siempre es "candidatos con nivel de riesgo", nunca
  un veredicto binario.
- Algunos chequeos (archivos abiertos de otros usuarios, ciertas claves
  de registro) requieren permisos elevados. Sin ellos, esos procesos
  simplemente se saltan — no se reportan como falso "todo limpio".

## Un bug real que encontré armando esto (y por qué importa)

Al probar el escáner de persistencia contra un sistema Linux real, el
primer intento reportaba `/dev/null` y `/run/systemd/system` como si
fueran ejecutables programados. La causa: `/etc/cron.daily` y
`/etc/cron.hourly` **no tienen formato crontab** — cada archivo ahí
adentro es un script completo que `run-parts` ejecuta tal cual, a
diferencia de `/etc/cron.d` (que sí es formato horario+comando). El
parser original trataba ambos igual y terminaba extrayendo rutas
sueltas de *adentro* de los scripts (como un `if [ -d /run/systemd/system ]`).

Se corrigió tratando cada directorio de cron según su formato real, y
se agregó un test de regresión (`test_persistence_cron_daily_targets_the_script_itself_not_its_content`)
para que no vuelva a pasar. Lo dejamos documentado a propósito: en una
herramienta de seguridad, los falsos positivos silenciosos son casi
tan malos como los falsos negativos — erosionan la confianza en la
próxima alerta real.

## Extender el detector

Las tablas `SIGNAL_POINTS` y `SIGNAL_DESCRIPTIONS` en
`keylogger_detector.py` son la única fuente de verdad. Agregar una
señal nueva es: definir su constante `SIG_*`, agregarla a ambas tablas,
y hacer que algún `check_*()` la agregue a la lista de señales de un
proceso. El test `test_no_single_signal_reaches_alto_alone` te va a
avisar si le pusiste demasiado peso sin querer.

## Tests

```bash
pip install pytest
pytest -v
```

51 casos en cuatro capas: núcleo de scoring (puro, sin mocks),
utilidades de parseo de rutas/comandos, escaneo de persistencia en
Linux (real, contra archivos temporales — no mockeado), y los chequeos
que dependen de `psutil`/`pefile` (con `unittest.mock`, porque no
podemos depender de que la máquina que corre los tests tenga un
proceso sospechoso de verdad).

## Licencia

MIT
