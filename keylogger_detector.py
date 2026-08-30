"""
©AngelaMos | 2026
keylogger_detector.py

Escanea los procesos en ejecución en busca de señales de COMPORTAMIENTO
típicas de keyloggers y malware que roba contraseñas — no por nombre de
archivo (trivial de evadir: basta con renombrar el .exe), sino por lo
que el proceso hace o dónde se ancla al sistema.

────────────────────────────────────────────────────────────────────
Las cuatro familias de señales
────────────────────────────────────────────────────────────────────
  1. Captura de teclado (solo Windows, requiere `pefile`)
     Se inspeccionan las funciones que el ejecutable IMPORTA de
     user32.dll. Un keylogger necesita, sí o sí, usar una de estas
     tres técnicas para leer el teclado:
       - SetWindowsHookEx(A/W)      -> hook global de teclado
       - GetAsyncKeyState / GetKeyState / GetKeyboardState
                                    -> sondeo (polling) del teclado
       - RegisterRawInputDevices    -> captura de entrada cruda
     Que un ejecutable IMPORTE estas funciones no prueba nada por sí
     solo (un juego, un mapeador de teclas, o AutoHotkey también las
     usan) — es un indicio, no un veredicto. Por eso es apenas una de
     varias señales, nunca la única

  2. Acceso a almacenes de credenciales
     Los "infostealers" (familia de malware más amplia que los
     keyloggers, y hoy más común) casi siempre van directo a robar
     el archivo donde el navegador guarda las contraseñas guardadas
     (Login Data de Chrome/Edge/Brave, logins.json/key4.db de
     Firefox). Si un proceso que NO es el propio navegador tiene ese
     archivo abierto, es una señal fuerte

  3. Persistencia
     Casi ningún malware quiere ejecutarse una sola vez: se instala
     para arrancar con el sistema (registro Run de Windows, tareas
     programadas, crontab, autostart de XDG, LaunchAgents de macOS).
     Si el ejecutable de un proceso en ejecución coincide con una de
     estas rutas de auto-inicio, sube la sospecha

  4. Red externa (factor agravante, nunca señal única)
     Un proceso que ya mostró una de las señales anteriores Y además
     mantiene una conexión activa hacia una IP pública es más
     sospechoso de estar exfiltrando datos. Tener acceso a internet
     por sí solo NO es sospechoso — casi todo lo tiene — así que esta
     señal solo se evalúa si ya hay otra

Cada señal suma puntos (ver `SIGNAL_POINTS`) y el total decide un
nivel de riesgo: "bajo" (no se reporta), "medio" o "alto". Ninguna
señal por sí sola alcanza "alto": la herramienta está diseñada para
necesitar corroboración entre familias antes de gritar alarma

────────────────────────────────────────────────────────────────────
Qué NO hace esta herramienta (léelo antes de confiar en ella)
────────────────────────────────────────────────────────────────────
  - No es un antivirus. No tiene firmas, no hace análisis de memoria,
    no desempaqueta binarios ofuscados. Un keylogger medianamente
    sofisticado (empaquetado, o que usa un driver en modo kernel)
    puede evadirla sin esfuerzo
  - No lee, transmite ni registra pulsaciones de teclado en ningún
    momento — solo observa metadatos de OTROS procesos (nombre,
    ejecutable, imports, archivos abiertos, conexiones)
  - Las señales de Windows (imports de user32.dll) requieren la
    librería opcional `pefile` y solo aplican a ejecutables .exe
  - Los falsos positivos existen: un gestor de contraseñas legítimo
    importando esas mismas rutas, o una utilidad de accesibilidad,
    pueden disparar señales. Por eso el resultado es una lista de
    candidatos con nivel de confianza, no una sentencia

────────────────────────────────────────────────────────────────────
Qué expone este archivo
────────────────────────────────────────────────────────────────────
  ProcessFinding          — resultado de evaluar un proceso
  SIGNAL_POINTS           — tabla de pesos de cada señal
  SIGNAL_DESCRIPTIONS     — explicación en español de cada señal
  score_signals()         — función pura: señales -> puntaje
  risk_level_for_score()  — función pura: puntaje -> "bajo"/"medio"/"alto"
  evaluate_process()      — combina todos los chequeos para UN proceso
  scan_once()             — escanea TODOS los procesos, una vez
  find_persistence_targets() — ubicaciones de auto-inicio del sistema
  main()                  — punto de entrada de la CLI (`keylog-detect`)
"""

from __future__ import annotations

# --- Librería estándar -------------------------------------------------
import argparse
import csv
import fnmatch
import ipaddress
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

# plistlib es multiplataforma en la librería estándar, pero solo tiene
# sentido usarlo para leer LaunchAgents en macOS
import plistlib

# winreg SOLO existe en Windows. Lo importamos de forma defensiva para
# que el resto del programa siga funcionando (con esa señal deshabilitada)
# en Linux/macOS
try:
    import winreg  # type: ignore[import-not-found]
except ImportError:
    winreg = None  # type: ignore[assignment]

# --- Terceros ------------------------------------------------------------
import psutil
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# pefile es OPCIONAL: sin él, simplemente se omite el chequeo de imports
# de Windows (con un aviso), en vez de romper todo el programa
try:
    import pefile  # type: ignore[import-not-found]
except ImportError:
    pefile = None  # type: ignore[assignment]


PLATFORM = platform.system()  # "Windows" | "Linux" | "Darwin"


# =============================================================================
# Nombres de señales — strings, no un Enum, para que sumar puntos con un
# dict sea trivial y los tests puedan comparar contra literales simples
# =============================================================================

SIG_HOOK_IMPORT = "importa_hook_teclado"
SIG_KEYSTATE_IMPORT = "importa_sondeo_teclado"
SIG_RAWINPUT_IMPORT = "importa_raw_input"
SIG_CRED_STORE = "acceso_almacen_credenciales"
SIG_REG_RUN = "persistencia_registro_run"
SIG_STARTUP_FOLDER = "persistencia_carpeta_inicio"
SIG_SCHEDULED_TASK = "persistencia_tarea_programada"
SIG_CRON = "persistencia_cron"
SIG_SYSTEMD_USER = "persistencia_systemd_usuario"
SIG_AUTOSTART_XDG = "persistencia_autostart_xdg"
SIG_LAUNCH_AGENT = "persistencia_launch_agent_macos"
SIG_EXTERNAL_NETWORK = "conexion_red_externa"
SIG_SUSPICIOUS_NAME = "nombre_sospechoso"

# Cuánto suma cada señal. Ajustar estos números es la forma más simple
# de "afinar" la sensibilidad del detector sin tocar ninguna lógica
SIGNAL_POINTS: dict[str, int] = {
    SIG_HOOK_IMPORT: 35,
    SIG_KEYSTATE_IMPORT: 20,
    SIG_RAWINPUT_IMPORT: 15,
    SIG_CRED_STORE: 40,
    SIG_REG_RUN: 15,
    SIG_STARTUP_FOLDER: 15,
    SIG_SCHEDULED_TASK: 15,
    SIG_CRON: 15,
    SIG_SYSTEMD_USER: 10,
    SIG_AUTOSTART_XDG: 10,
    SIG_LAUNCH_AGENT: 15,
    SIG_EXTERNAL_NETWORK: 10,
    SIG_SUSPICIOUS_NAME: 5,
}

SIGNAL_DESCRIPTIONS: dict[str, str] = {
    SIG_HOOK_IMPORT: "Importa SetWindowsHookEx (hook global de teclado) — técnica clásica de keylogger",
    SIG_KEYSTATE_IMPORT: "Importa GetAsyncKeyState/GetKeyState/GetKeyboardState — sondeo de teclado sin hook",
    SIG_RAWINPUT_IMPORT: "Importa RegisterRawInputDevices — captura de entrada a bajo nivel",
    SIG_CRED_STORE: "Tiene abierto un almacén de credenciales de un navegador sin ser el navegador",
    SIG_REG_RUN: "Entrada de auto-inicio en el registro de Windows (Run)",
    SIG_STARTUP_FOLDER: "Acceso directo en la carpeta de inicio de Windows",
    SIG_SCHEDULED_TASK: "Programado como tarea programada de Windows",
    SIG_CRON: "Programado vía cron (crontab o /etc/cron.d)",
    SIG_SYSTEMD_USER: "Habilitado como unidad de systemd de usuario",
    SIG_AUTOSTART_XDG: "Entrada de autoarranque XDG (~/.config/autostart)",
    SIG_LAUNCH_AGENT: "LaunchAgent/LaunchDaemon de macOS",
    SIG_EXTERNAL_NETWORK: "Conexión activa hacia una IP pública (factor agravante, no se evalúa solo)",
    SIG_SUSPICIOUS_NAME: "El nombre del proceso contiene una palabra clave típica de este malware (señal débil)",
}

# Funciones de user32.dll que un proceso Windows necesita importar para
# poder leer el teclado por alguna de las tres vías conocidas. pefile
# devuelve los nombres como bytes, por eso los literales son b"..."
_HOOK_APIS = {b"SetWindowsHookExA", b"SetWindowsHookExW"}
_KEYSTATE_APIS = {b"GetAsyncKeyState", b"GetKeyState", b"GetKeyboardState"}
_RAWINPUT_APIS = {b"RegisterRawInputDevices"}

# Palabras clave débiles en el nombre del proceso. Trivial de evadir
# (basta renombrar el ejecutable) — por eso pesa solo 5 puntos
_SUSPICIOUS_NAME_KEYWORDS = ("keylog", "keycap", "stealer", "logger", "spyware")

# Ubicaciones de cron en Linux, como constantes de módulo (no hardcodeadas
# dentro de la función) para poder sustituirlas fácilmente en los tests
# por un directorio temporal, sin tener que mockear pathlib.Path entero
_CRON_D_DIR = "/etc/cron.d"
_CRON_PERIODIC_DIRS = ("/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly")

# Procesos que SÍ tienen legítimamente abiertos sus propios archivos de
# credenciales — se excluyen del chequeo de acceso a almacén de credenciales
_KNOWN_BROWSER_NAMES = {
    "chrome.exe", "chrome", "msedge.exe", "msedge", "firefox.exe", "firefox",
    "brave.exe", "brave", "opera.exe", "opera", "vivaldi.exe", "vivaldi",
    "safari", "chromium", "chromium-browser",
}

# Patrones (con comodines) hacia los almacenes de credenciales más comunes
# de cada navegador, por sistema operativo. Se expanden variables de
# entorno / "~" en tiempo de ejecución, nunca están hardcodeados a un
# usuario en particular
_CREDENTIAL_STORE_GLOBS: dict[str, list[str]] = {
    "Windows": [
        r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Login Data",
        r"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Login Data",
        r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\*\Login Data",
        r"%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json",
        r"%APPDATA%\Mozilla\Firefox\Profiles\*\key4.db",
    ],
    "Linux": [
        "~/.config/google-chrome/*/Login Data",
        "~/.config/chromium/*/Login Data",
        "~/.config/BraveSoftware/Brave-Browser/*/Login Data",
        "~/.mozilla/firefox/*/logins.json",
        "~/.mozilla/firefox/*/key4.db",
    ],
    "Darwin": [
        "~/Library/Application Support/Google/Chrome/*/Login Data",
        "~/Library/Application Support/BraveSoftware/Brave-Browser/*/Login Data",
        "~/Library/Application Support/Firefox/Profiles/*/logins.json",
        "~/Library/Application Support/Firefox/Profiles/*/key4.db",
    ],
}

RiskLevel = Literal["alto", "medio", "bajo"]

_RISK_COLORS: dict[RiskLevel, str] = {
    "alto": "bright_red",
    "medio": "yellow",
    "bajo": "cyan",
}


# =============================================================================
# Núcleo puro — sin E/S, sin psutil, 100% testeable sin mocks
# =============================================================================


def score_signals(signals: tuple[str, ...] | list[str]) -> int:
    """Suma los puntos de cada señal presente. Señales desconocidas
    (typos, versiones futuras) simplemente no suman nada en vez de
    lanzar una excepción."""
    return sum(SIGNAL_POINTS.get(sig, 0) for sig in signals)


def risk_level_for_score(score: int) -> RiskLevel:
    """
    Umbrales pensados para que NINGUNA señal aislada llegue a 'alto':
    la más pesada (acceso a almacén de credenciales, 40 pts) por sí
    sola cae en 'medio'. Se necesita corroboración entre familias de
    señales para escalar a 'alto'
    """
    if score >= 50:
        return "alto"
    if score >= 20:
        return "medio"
    return "bajo"


@dataclass(frozen=True, slots=True)
class ProcessFinding:
    """Resultado de evaluar un proceso: qué señales disparó y qué tan
    grave es la combinación."""

    pid: int
    name: str
    exe: str
    signals: tuple[str, ...]

    @property
    def score(self) -> int:
        return score_signals(self.signals)

    @property
    def risk_level(self) -> RiskLevel:
        return risk_level_for_score(self.score)


def build_finding(pid: int, name: str, exe: str, signals: list[str]) -> ProcessFinding:
    """Constructor de conveniencia: ordena y deduplica las señales para
    que dos finding con las mismas señales sean siempre comparables."""
    return ProcessFinding(pid=pid, name=name, exe=exe, signals=tuple(sorted(set(signals))))


# =============================================================================
# Utilidades puras de parseo de rutas — testeables sin tocar el sistema
# =============================================================================


def _normalize_path(path: str | None) -> str:
    """Normaliza una ruta para poder comparar 'el ejecutable de un
    proceso en RAM' contra 'el target de una entrada de persistencia
    en disco' sin que barras invertidas, mayúsculas o variables de
    entorno sin expandir generen falsos negativos."""
    if not path:
        return ""
    expanded = os.path.expandvars(os.path.expanduser(path.strip().strip('"')))
    normalized = os.path.normpath(expanded)
    return normalized.lower() if PLATFORM == "Windows" else normalized


_TEST_CONDITION_RE = re.compile(r"\btest\s+-\w+\s+\S+\s*(\|\||&&)")


def _strip_test_conditions(line: str) -> str:
    """
    Muchísimos cron.d de sistema (Debian/Ubuntu en particular) usan el
    patrón `test -e /run/systemd/system || COMANDO_REAL`. Sin esto, la
    extracción ingenua agarra la ruta de la CONDICIÓN en vez del
    comando real, generando falsos positivos con cada scan (se pudo
    comprobar corriendo esto contra un sistema real: aparecía
    /run/systemd/system como si fuera un ejecutable programado)
    """
    return _TEST_CONDITION_RE.sub("", line)


def _extract_first_executable_token(line: str | None) -> str | None:
    """De una línea de crontab, un 'Exec=' de un .desktop, o un
    'Task To Run' de schtasks, extrae el primer token que parece una
    ruta absoluta. Es deliberadamente simple: prefiere no encontrar
    nada a inventar una ruta incorrecta."""
    if not line:
        return None
    line = _strip_test_conditions(line)
    for token in line.split():
        token = token.strip('"')
        if token.startswith("/") or (len(token) > 2 and token[1:3] == ":\\"):
            return token
    return None


def _extract_execstart_path(show_output: str) -> str | None:
    """Extrae la ruta del ejecutable de la salida de
    `systemctl show <unit> -p ExecStart`, que en systemd moderno tiene
    forma '{ path=/usr/bin/foo ; argv[]=... }' y en versiones viejas
    es simplemente 'ExecStart=/usr/bin/foo args'."""
    line = show_output.strip()
    if not line.startswith("ExecStart="):
        return None
    value = line[len("ExecStart="):]
    match = re.search(r"path=([^\s;]+)", value)
    if match:
        return match.group(1)
    return _extract_first_executable_token(value)


def _has_suspicious_name(name: str | None) -> bool:
    lowered = (name or "").lower()
    return any(keyword in lowered for keyword in _SUSPICIOUS_NAME_KEYWORDS)


def _expand_credential_patterns() -> list[str]:
    """Expande '%VAR%'/'~' en los patrones de la plataforma actual,
    normalizando separadores para poder comparar con fnmatch."""
    patterns = _CREDENTIAL_STORE_GLOBS.get(PLATFORM, [])
    expanded = []
    for pattern in patterns:
        value = os.path.expandvars(os.path.expanduser(pattern))
        value = value.replace("\\", "/")
        expanded.append(value.lower() if PLATFORM == "Windows" else value)
    return expanded


# =============================================================================
# Chequeos que SÍ tocan el sistema operativo — cada uno atrapa sus
# propias excepciones para que un fallo puntual no tumbe todo el escaneo
# =============================================================================


def check_pe_imports(exe_path: str) -> list[str]:
    """
    Inspecciona la tabla de imports de un ejecutable Windows en busca
    de las APIs de user32.dll que un keylogger necesita usar. Requiere
    la librería opcional `pefile`; si no está instalada, o si el
    archivo no es un PE válido, o si no hay permisos para leerlo,
    simplemente no aporta señales (no es un chequeo crítico)
    """
    if pefile is None or PLATFORM != "Windows" or not exe_path:
        return []

    signals: list[str] = []
    try:
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imported: set[bytes] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    imported.add(imp.name)
        if imported & _HOOK_APIS:
            signals.append(SIG_HOOK_IMPORT)
        if imported & _KEYSTATE_APIS:
            signals.append(SIG_KEYSTATE_IMPORT)
        if imported & _RAWINPUT_APIS:
            signals.append(SIG_RAWINPUT_IMPORT)
    except Exception:
        # PE corrupto, sin permisos, archivo no-PE, etc. — se omite
        pass
    return signals


def check_credential_store_access(proc: "psutil.Process", patterns: list[str]) -> bool:
    """True si `proc` (que NO es un navegador conocido) tiene abierto
    un archivo que calza con alguno de los patrones de almacén de
    credenciales de la plataforma actual."""
    try:
        name = (proc.name() or "").lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return False
    if name in _KNOWN_BROWSER_NAMES:
        return False
    try:
        open_files = proc.open_files()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return False
    for f in open_files:
        candidate = f.path.replace("\\", "/")
        candidate = candidate.lower() if PLATFORM == "Windows" else candidate
        if any(fnmatch.fnmatch(candidate, pattern) for pattern in patterns):
            return True
    return False


def check_external_network(proc: "psutil.Process") -> bool:
    """True si `proc` mantiene una conexión ESTABLISHED hacia una IP
    pública (ni privada, ni loopback, ni link-local). Se usa solo
    como factor agravante — nunca como señal única, ver `evaluate_process`."""
    getter = getattr(proc, "net_connections", None) or getattr(proc, "connections", None)
    if getter is None:
        return False
    try:
        conns = getter(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return False
    for conn in conns:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        ip = conn.raddr[0] if isinstance(conn.raddr, tuple) else conn.raddr.ip
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast):
            return True
    return False


# --- Persistencia: dónde busca cada sistema operativo -----------------------


def find_persistence_targets() -> dict[str, list[str]]:
    """
    Devuelve {ruta_normalizada_del_ejecutable: [señales]} recorriendo
    las ubicaciones de auto-inicio típicas del sistema operativo
    actual. Nunca lanza excepciones: cada fuente que falla se omite
    silenciosamente y el resto sigue intentándose
    """
    if PLATFORM == "Windows":
        return _find_persistence_windows()
    if PLATFORM == "Linux":
        return _find_persistence_linux()
    if PLATFORM == "Darwin":
        return _find_persistence_macos()
    return {}


def _add_target(targets: dict[str, list[str]], path: str | None, signal: str) -> None:
    if not path:
        return
    key = _normalize_path(path)
    if not key:
        return
    bucket = targets.setdefault(key, [])
    if signal not in bucket:
        bucket.append(signal)


def _find_persistence_linux() -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}

    # crontab del usuario actual
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5, check=False
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                _add_target(targets, _extract_first_executable_token(line), SIG_CRON)
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass

    # /etc/cron.d/*  — SÍ tiene formato crontab (horario + usuario + comando),
    # una línea por tarea, exactamente como el crontab del usuario
    try:
        for entry in Path(_CRON_D_DIR).iterdir():
            if not entry.is_file():
                continue
            for line in entry.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    _add_target(targets, _extract_first_executable_token(line), SIG_CRON)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    # /etc/cron.{daily,hourly,weekly,monthly}/* — NO tienen formato crontab.
    # run-parts ejecuta cada ARCHIVO completo como si fuera un script, así
    # que el objetivo de persistencia es el archivo mismo, no algo dentro
    # de su contenido (parsear el contenido línea por línea, como si fuera
    # crontab, produce falsos positivos: agarra cualquier ruta absoluta
    # mencionada dentro del script, como un `if [ -d /run/systemd/system ]`)
    for cron_dir in _CRON_PERIODIC_DIRS:
        try:
            for entry in Path(cron_dir).iterdir():
                if entry.is_file() and os.access(entry, os.X_OK):
                    _add_target(targets, str(entry), SIG_CRON)
        except (FileNotFoundError, PermissionError, OSError):
            continue

    # autostart de XDG (~/.config/autostart/*.desktop)
    try:
        autostart_dir = Path.home() / ".config" / "autostart"
        for entry in autostart_dir.glob("*.desktop"):
            for line in entry.read_text(errors="ignore").splitlines():
                if line.startswith("Exec="):
                    exe = _extract_first_executable_token(line[len("Exec="):])
                    _add_target(targets, exe, SIG_AUTOSTART_XDG)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    # unidades de systemd --user habilitadas
    try:
        result = subprocess.run(
            ["systemctl", "--user", "list-unit-files", "--state=enabled", "--no-legend"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            try:
                show = subprocess.run(
                    ["systemctl", "--user", "show", unit, "-p", "ExecStart"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                exe = _extract_execstart_path(show.stdout)
                _add_target(targets, exe, SIG_SYSTEMD_USER)
            except (subprocess.SubprocessError, OSError):
                continue
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass

    return targets


def _find_persistence_windows() -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}

    if winreg is not None:
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, subkey in run_keys:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    index = 0
                    while True:
                        try:
                            _, value, _ = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        exe = _extract_first_executable_token(value) or value
                        _add_target(targets, exe, SIG_REG_RUN)
                        index += 1
            except OSError:
                continue

    appdata = os.environ.get("APPDATA")
    if appdata:
        startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        try:
            for entry in startup_dir.iterdir():
                _add_target(targets, str(entry), SIG_STARTUP_FOLDER)
        except (FileNotFoundError, PermissionError, OSError):
            pass

    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        reader = csv.DictReader(result.stdout.splitlines())
        for row in reader:
            cmd = row.get("Task To Run")
            if cmd:
                exe = _extract_first_executable_token(cmd) or cmd.strip('"')
                _add_target(targets, exe, SIG_SCHEDULED_TASK)
    except (FileNotFoundError, subprocess.SubprocessError, OSError, csv.Error):
        pass

    return targets


def _find_persistence_macos() -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}
    plist_dirs = [
        Path.home() / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    for directory in plist_dirs:
        try:
            for entry in directory.glob("*.plist"):
                try:
                    with entry.open("rb") as fh:
                        data = plistlib.load(fh)
                except Exception:
                    continue
                args = data.get("ProgramArguments") or []
                exe = args[0] if args else data.get("Program")
                _add_target(targets, exe, SIG_LAUNCH_AGENT)
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return targets


# =============================================================================
# Orquestación — combina todos los chequeos para un proceso, y para todos
# =============================================================================


def gather_processes():
    """Generador delgado sobre psutil.process_iter(). Separado en su
    propia función solo para poder sustituirlo fácilmente en los tests."""
    yield from psutil.process_iter()


def evaluate_process(
    proc: "psutil.Process",
    persistence_targets: dict[str, list[str]],
    credential_patterns: list[str],
) -> ProcessFinding | None:
    """
    Corre todos los chequeos disponibles sobre UN proceso y devuelve
    un ProcessFinding si disparó al menos una señal, o None si el
    proceso no dio motivo de sospecha (o ya no existe / no hay permisos
    para inspeccionarlo, lo cual NO es en sí mismo una señal)
    """
    try:
        name = proc.name()
        exe = proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return None

    signals: list[str] = []
    signals.extend(check_pe_imports(exe))

    if check_credential_store_access(proc, credential_patterns):
        signals.append(SIG_CRED_STORE)

    normalized_exe = _normalize_path(exe)
    signals.extend(persistence_targets.get(normalized_exe, []))

    # La conexión de red es un AGRAVANTE: solo se evalúa si ya hay
    # alguna otra señal de comportamiento sospechoso (ver docstring
    # del módulo — tener internet no es sospechoso por sí solo)
    keylog_or_cred_signals = {
        SIG_HOOK_IMPORT, SIG_KEYSTATE_IMPORT, SIG_RAWINPUT_IMPORT, SIG_CRED_STORE,
    }
    if signals and (set(signals) & keylog_or_cred_signals):
        if check_external_network(proc):
            signals.append(SIG_EXTERNAL_NETWORK)

    if _has_suspicious_name(name):
        signals.append(SIG_SUSPICIOUS_NAME)

    if not signals:
        return None
    return build_finding(proc.pid, name, exe, signals)


def scan_once(min_score: int = 0) -> list[ProcessFinding]:
    """
    Escanea todos los procesos actuales una sola vez y devuelve los
    hallazgos con puntaje >= min_score, ordenados de mayor a menor
    riesgo. Es la función que tanto el modo de escaneo único como el
    modo --watch llaman en cada iteración
    """
    persistence_targets = find_persistence_targets()
    credential_patterns = _expand_credential_patterns()

    findings: list[ProcessFinding] = []
    for proc in gather_processes():
        finding = evaluate_process(proc, persistence_targets, credential_patterns)
        if finding is not None and finding.score >= min_score:
            findings.append(finding)

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


# =============================================================================
# Presentación — separada de la lógica de arriba
# =============================================================================


def _render_findings(findings: list[ProcessFinding], console: Console) -> None:
    if not findings:
        console.print(
            "[green]Sin hallazgos.[/green] Ningún proceso superó el umbral "
            "configurado. Recordá que esto no es una garantía: ver las "
            "limitaciones en el docstring del módulo / el README."
        )
        return

    table = Table(title=f"Hallazgos ({len(findings)})")
    table.add_column("pid", justify="right")
    table.add_column("proceso", style="bold white")
    table.add_column("riesgo", no_wrap=True)
    table.add_column("puntaje", justify="right")
    table.add_column("señales", style="dim")

    for finding in findings:
        color = _RISK_COLORS[finding.risk_level]
        table.add_row(
            str(finding.pid),
            finding.name,
            f"[{color}]{finding.risk_level}[/{color}]",
            str(finding.score),
            ", ".join(finding.signals),
        )
    console.print(table)

    if any(f.risk_level == "alto" for f in findings):
        console.print(
            "\n[bright_red]Al menos un proceso alcanzó riesgo 'alto'.[/bright_red] "
            "Investigalo manualmente antes de tomar cualquier acción: cerrá el "
            "proceso, revisá qué archivo lo inició, y considerá escanear con un "
            "antivirus real si la sospecha se confirma."
        )


def _render_alert(finding: ProcessFinding, console: Console) -> None:
    color = _RISK_COLORS[finding.risk_level]
    timestamp = datetime.now().strftime("%H:%M:%S")
    details = "\n".join(
        f"  • {SIGNAL_DESCRIPTIONS.get(sig, sig)}" for sig in finding.signals
    )
    console.print(
        Panel(
            f"[bold]PID:[/bold] {finding.pid}   "
            f"[bold]Proceso:[/bold] {finding.name}\n"
            f"[bold]Ejecutable:[/bold] {finding.exe}\n"
            f"[bold]Puntaje:[/bold] {finding.score}\n\n"
            f"{details}",
            title=f"[{color}]⚠ Riesgo {finding.risk_level} · {timestamp}[/{color}]",
            border_style=color,
        )
    )


def _render_persistence(console: Console) -> None:
    targets = find_persistence_targets()
    if not targets:
        console.print(
            "[green]No se encontraron entradas de auto-inicio[/green] en las "
            "ubicaciones revisadas para esta plataforma "
            f"({PLATFORM})."
        )
        return
    table = Table(title=f"Entradas de auto-inicio encontradas ({len(targets)})")
    table.add_column("ejecutable", style="bold white")
    table.add_column("origen")
    for path, signals in sorted(targets.items()):
        origins = ", ".join(SIGNAL_DESCRIPTIONS.get(s, s) for s in signals)
        table.add_row(path, origins)
    console.print(table)


# =============================================================================
# CLI
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keylog-detect",
        description=(
            "Detecta comportamiento típico de keyloggers y de malware que "
            "roba contraseñas, analizando los procesos en ejecución "
            "(no por nombre de archivo, sino por comportamiento)."
        ),
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Monitorea en un bucle continuo en vez de hacer un solo escaneo.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Segundos entre cada escaneo en modo --watch (default: 30).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=15,
        help="Puntaje mínimo para mostrar/alertar un proceso (default: 15).",
    )
    parser.add_argument(
        "--list-persistence",
        action="store_true",
        help="Solo lista las entradas de auto-inicio encontradas y termina.",
    )
    return parser


def _exit_code_for(findings: list[ProcessFinding]) -> int:
    if any(f.risk_level == "alto" for f in findings):
        return 2
    if any(f.risk_level == "medio" for f in findings):
        return 1
    return 0


def _run_watch_loop(console: Console, interval: int, threshold: int) -> int:
    console.print(
        Panel(
            f"Escaneando cada {interval}s. Presioná Ctrl+C para detener.",
            title="Modo watch",
            border_style="blue",
        )
    )
    last_alerted_score: dict[int, int] = {}
    worst_seen = 0
    try:
        while True:
            findings = scan_once(min_score=threshold)
            for finding in findings:
                previous = last_alerted_score.get(finding.pid)
                if previous is None or finding.score > previous:
                    _render_alert(finding, console)
                    last_alerted_score[finding.pid] = finding.score
                    worst_seen = max(worst_seen, finding.score)
            active_pids = {f.pid for f in findings}
            for pid in list(last_alerted_score):
                if pid not in active_pids:
                    del last_alerted_score[pid]
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Monitoreo detenido por el usuario.[/dim]")
    return risk_level_for_score(worst_seen) == "alto" and 2 or (
        1 if risk_level_for_score(worst_seen) == "medio" else 0
    )


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    if pefile is None and PLATFORM == "Windows":
        console.print(
            "[yellow]Aviso:[/yellow] `pefile` no está instalado — el chequeo "
            "de imports de teclado (la señal más fuerte en Windows) está "
            "deshabilitado. Instalalo con: pip install pefile\n"
        )

    if args.list_persistence:
        _render_persistence(console)
        return 0

    if args.watch:
        return _run_watch_loop(console, interval=args.interval, threshold=args.threshold)

    findings = scan_once(min_score=args.threshold)
    _render_findings(findings, console)
    return _exit_code_for(findings)


if __name__ == "__main__":
    sys.exit(main())
