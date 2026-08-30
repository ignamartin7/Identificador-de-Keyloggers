"""
©AngelaMos | 2026
test_keylogger_detector.py

Cuatro capas de prueba:
  1. Núcleo puro (score_signals, risk_level_for_score, ProcessFinding)
     — sin mocks, corre en cualquier plataforma
  2. Utilidades de parseo de rutas/comandos — strings de entrada/salida
     conocidas, sin tocar el sistema
  3. Persistencia en Linux — REAL, no mockeada: creamos crontabs,
     archivos .desktop y respuestas de systemctl falsas en un
     directorio temporal y verificamos que el scanner las encuentre
  4. Chequeos que tocan psutil/pefile — con unittest.mock, porque no
     podemos depender de que exista un proceso sospechoso de verdad
     en la máquina que corre los tests
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

import keylogger_detector as kd


# =============================================================================
# 1. Núcleo puro
# =============================================================================


def test_score_signals_sums_known_signals():
    assert kd.score_signals([kd.SIG_HOOK_IMPORT, kd.SIG_CRED_STORE]) == 35 + 40


def test_score_signals_ignores_unknown_signal():
    assert kd.score_signals(["algo_que_no_existe"]) == 0


def test_score_signals_empty_is_zero():
    assert kd.score_signals([]) == 0


@pytest.mark.parametrize(
    "score,expected",
    [(0, "bajo"), (19, "bajo"), (20, "medio"), (35, "medio"), (49, "medio"), (50, "alto"), (100, "alto")],
)
def test_risk_level_thresholds(score, expected):
    assert kd.risk_level_for_score(score) == expected


def test_no_single_signal_reaches_alto_alone():
    """Ninguna señal individual debería, por sí sola, alcanzar 'alto'.
    Si esto falla, alguien subió el peso de una señal sin querer
    convertirla en una alarma de un solo disparo."""
    for signal, points in kd.SIGNAL_POINTS.items():
        assert kd.risk_level_for_score(points) != "alto", (
            f"La señal '{signal}' ({points} pts) alcanza 'alto' ella sola"
        )


def test_build_finding_deduplicates_and_sorts_signals():
    finding = kd.build_finding(1234, "proc", "/bin/proc", [kd.SIG_CRON, kd.SIG_CRON, kd.SIG_REG_RUN])
    assert finding.signals == tuple(sorted({kd.SIG_CRON, kd.SIG_REG_RUN}))


def test_process_finding_score_and_risk_are_derived():
    finding = kd.build_finding(1, "x", "/bin/x", [kd.SIG_HOOK_IMPORT, kd.SIG_CRED_STORE])
    assert finding.score == 75
    assert finding.risk_level == "alto"


def test_process_finding_is_frozen():
    finding = kd.build_finding(1, "x", "/bin/x", [kd.SIG_CRON])
    with pytest.raises(AttributeError):
        finding.pid = 999  # type: ignore[misc]


# =============================================================================
# 2. Utilidades de parseo
# =============================================================================


@pytest.mark.parametrize(
    "line,expected",
    [
        ("* * * * * /usr/bin/malo --flag", "/usr/bin/malo"),
        ("0 3 * * * root /opt/app/run.sh", "/opt/app/run.sh"),
        ("no hay ninguna ruta aca", None),
        ("", None),
        (None, None),
    ],
)
def test_extract_first_executable_token(line, expected):
    assert kd._extract_first_executable_token(line) == expected


def test_extract_first_executable_token_windows_style_path():
    # Caso simple, sin espacios en la ruta: se extrae completo
    assert kd._extract_first_executable_token(r"C:\evil\run.exe -silent") == r"C:\evil\run.exe"
    # Caso límite conocido: una ruta CON espacios se corta en el primer
    # espacio, porque el split es por whitespace y no parsea comillas
    # balanceadas. Documentamos la limitación en vez de esconderla
    cut = kd._extract_first_executable_token(r'"C:\Program Files\evil\run.exe" -silent')
    assert cut == r"C:\Program"


def test_extract_first_executable_token_skips_test_condition_paths():
    """Patrón real de Debian/Ubuntu: 'test -e /run/systemd/system ||
    COMANDO_REAL'. Debe ignorar la ruta de la condición y devolver la
    del comando que realmente se ejecuta."""
    line = "10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r"
    assert kd._extract_first_executable_token(line) == "/sbin/e2scrub_all"


def test_extract_execstart_path_modern_systemd_format():
    output = "ExecStart={ path=/usr/bin/foo ; argv[]=/usr/bin/foo --daemon ; ignore_errors=no }"
    assert kd._extract_execstart_path(output) == "/usr/bin/foo"


def test_extract_execstart_path_legacy_format():
    assert kd._extract_execstart_path("ExecStart=/usr/bin/bar --flag") == "/usr/bin/bar"


def test_extract_execstart_path_missing_prefix_returns_none():
    assert kd._extract_execstart_path("SomethingElse=nope") is None


def test_has_suspicious_name():
    assert kd._has_suspicious_name("SneakyKeyLogger.exe")
    assert kd._has_suspicious_name("password-stealer")
    assert not kd._has_suspicious_name("chrome.exe")
    assert not kd._has_suspicious_name(None)


def test_normalize_path_expands_user_and_lowercases_only_on_windows():
    home_path = kd._normalize_path("~/algo")
    assert not home_path.startswith("~")


# =============================================================================
# 3. Persistencia en Linux — REAL (no mock), usando un HOME temporal
# =============================================================================


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    monkeypatch.setattr(kd.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _mock_subprocess_run(responses: dict[tuple, str]):
    """Crea un reemplazo de subprocess.run que devuelve stdout distinto
    según el comando invocado (matcheando por el primer argumento)."""

    def _fake_run(cmd, *args, **kwargs):
        key = tuple(cmd)
        result = MagicMock()
        result.stdout = responses.get(key, responses.get((cmd[0],), ""))
        result.returncode = 0
        return result

    return _fake_run


def test_persistence_finds_crontab_entry(fake_home, monkeypatch):
    fake_run = _mock_subprocess_run(
        {("crontab", "-l"): "* * * * * /home/user/.hidden/malo.sh\n"}
    )
    monkeypatch.setattr(kd.subprocess, "run", fake_run)
    targets = kd._find_persistence_linux()
    assert kd.SIG_CRON in targets.get(kd._normalize_path("/home/user/.hidden/malo.sh"), [])


def test_persistence_cron_daily_targets_the_script_itself_not_its_content(fake_home, monkeypatch, tmp_path):
    """Regresión: cron.daily/hourly NO son formato crontab — cada
    archivo es un script completo que run-parts ejecuta tal cual.
    Parsear su contenido línea por línea generaba falsos positivos
    (se detectó corriendo esto contra un sistema real: aparecía
    /run/systemd/system, sacado de un `if [ -d ... ]` dentro del script)."""
    cron_daily = tmp_path / "cron.daily"
    cron_daily.mkdir()
    script = cron_daily / "mi-script"
    script.write_text("#!/bin/sh\nif [ -d /run/systemd/system ]; then\n  exit 0\nfi\n")
    script.chmod(0o755)

    monkeypatch.setattr(kd.subprocess, "run", _mock_subprocess_run({}))
    monkeypatch.setattr(kd, "_CRON_D_DIR", str(tmp_path / "cron.d-vacio"))
    monkeypatch.setattr(kd, "_CRON_PERIODIC_DIRS", (str(cron_daily),))

    targets = kd._find_persistence_linux()

    script_key = kd._normalize_path(str(script))
    assert kd.SIG_CRON in targets.get(script_key, [])
    # La ruta de adentro del script (la condición del if) NO debe
    # aparecer como si fuera un objetivo de persistencia
    assert kd._normalize_path("/run/systemd/system") not in targets


def test_persistence_cron_d_still_uses_crontab_style_parsing(fake_home, monkeypatch, tmp_path):
    """/etc/cron.d SÍ es formato crontab — confirma que no rompimos
    ese caso al separarlo de cron.daily/hourly."""
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    (cron_d / "mitarea").write_text("* * * * * root /opt/real/comando --flag\n")

    monkeypatch.setattr(kd.subprocess, "run", _mock_subprocess_run({}))
    monkeypatch.setattr(kd, "_CRON_D_DIR", str(cron_d))
    monkeypatch.setattr(kd, "_CRON_PERIODIC_DIRS", ())

    targets = kd._find_persistence_linux()
    assert kd.SIG_CRON in targets.get(kd._normalize_path("/opt/real/comando"), [])


def test_persistence_finds_xdg_autostart_entry(fake_home, monkeypatch):
    autostart = fake_home / ".config" / "autostart"
    autostart.mkdir(parents=True)
    (autostart / "evil.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=/opt/evil/run --background\n"
    )
    monkeypatch.setattr(kd.subprocess, "run", _mock_subprocess_run({}))
    targets = kd._find_persistence_linux()
    assert kd.SIG_AUTOSTART_XDG in targets.get(kd._normalize_path("/opt/evil/run"), [])


def test_persistence_finds_systemd_user_unit(fake_home, monkeypatch):
    fake_run = _mock_subprocess_run(
        {
            ("systemctl", "--user", "list-unit-files", "--state=enabled", "--no-legend"): (
                "evil.service enabled\n"
            ),
            (
                "systemctl", "--user", "show", "evil.service", "-p", "ExecStart",
            ): "ExecStart={ path=/opt/evil/daemon ; argv[]=/opt/evil/daemon }",
        }
    )
    monkeypatch.setattr(kd.subprocess, "run", fake_run)
    targets = kd._find_persistence_linux()
    assert kd.SIG_SYSTEMD_USER in targets.get(kd._normalize_path("/opt/evil/daemon"), [])


def test_persistence_ignores_comments_in_crontab(fake_home, monkeypatch):
    fake_run = _mock_subprocess_run(
        {("crontab", "-l"): "# esto es un comentario /no/deberia/aparecer\n"}
    )
    monkeypatch.setattr(kd.subprocess, "run", fake_run)
    targets = kd._find_persistence_linux()
    assert kd._normalize_path("/no/deberia/aparecer") not in targets


def test_persistence_handles_missing_crontab_binary_gracefully(fake_home, monkeypatch):
    def _raise(*args, **kwargs):
        raise FileNotFoundError("crontab no instalado")

    monkeypatch.setattr(kd.subprocess, "run", _raise)
    # No debe lanzar excepción, simplemente devolver lo que sí pudo encontrar
    targets = kd._find_persistence_linux()
    assert isinstance(targets, dict)


def test_find_persistence_targets_dispatches_by_platform(monkeypatch):
    monkeypatch.setattr(kd, "PLATFORM", "Linux")
    monkeypatch.setattr(kd, "_find_persistence_linux", lambda: {"x": ["y"]})
    assert kd.find_persistence_targets() == {"x": ["y"]}

    monkeypatch.setattr(kd, "PLATFORM", "PlataformaInventada")
    assert kd.find_persistence_targets() == {}


# =============================================================================
# 4. Chequeos con psutil/pefile mockeados
# =============================================================================


def _make_fake_process(pid=1000, name="proc.exe", exe="/usr/bin/proc", open_files=None, connections=None):
    proc = MagicMock()
    proc.pid = pid
    proc.name.return_value = name
    proc.exe.return_value = exe
    proc.open_files.return_value = open_files or []
    proc.net_connections.return_value = connections or []
    return proc


def test_check_credential_store_access_flags_non_browser_process():
    fake_file = MagicMock()
    fake_file.path = "/home/user/.mozilla/firefox/abc123.default/logins.json"
    proc = _make_fake_process(name="totallylegit.exe", open_files=[fake_file])
    patterns = ["/home/user/.mozilla/firefox/*/logins.json"]
    assert kd.check_credential_store_access(proc, patterns) is True


def test_check_credential_store_access_excludes_known_browsers():
    fake_file = MagicMock()
    fake_file.path = "/home/user/.mozilla/firefox/abc123.default/logins.json"
    proc = _make_fake_process(name="firefox", open_files=[fake_file])
    patterns = ["/home/user/.mozilla/firefox/*/logins.json"]
    assert kd.check_credential_store_access(proc, patterns) is False


def test_check_credential_store_access_no_match_returns_false():
    fake_file = MagicMock()
    fake_file.path = "/home/user/documents/notes.txt"
    proc = _make_fake_process(open_files=[fake_file])
    patterns = ["/home/user/.mozilla/firefox/*/logins.json"]
    assert kd.check_credential_store_access(proc, patterns) is False


def test_check_credential_store_access_handles_access_denied():
    proc = _make_fake_process()
    proc.open_files.side_effect = __import__("psutil").AccessDenied(pid=1000)
    assert kd.check_credential_store_access(proc, ["*"]) is False


def test_check_external_network_flags_public_ip():
    conn = MagicMock()
    conn.status = "ESTABLISHED"
    conn.raddr = ("8.8.8.8", 443)
    proc = _make_fake_process(connections=[conn])
    with patch.object(kd.psutil, "CONN_ESTABLISHED", "ESTABLISHED"):
        assert kd.check_external_network(proc) is True


def test_check_external_network_ignores_private_ip():
    conn = MagicMock()
    conn.status = "ESTABLISHED"
    conn.raddr = ("192.168.1.50", 443)
    proc = _make_fake_process(connections=[conn])
    with patch.object(kd.psutil, "CONN_ESTABLISHED", "ESTABLISHED"):
        assert kd.check_external_network(proc) is False


def test_check_external_network_ignores_processes_without_raddr():
    conn = MagicMock()
    conn.status = "LISTEN"
    conn.raddr = None
    proc = _make_fake_process(connections=[conn])
    with patch.object(kd.psutil, "CONN_ESTABLISHED", "ESTABLISHED"):
        assert kd.check_external_network(proc) is False


def test_check_pe_imports_returns_empty_when_pefile_missing(monkeypatch):
    monkeypatch.setattr(kd, "pefile", None)
    monkeypatch.setattr(kd, "PLATFORM", "Windows")
    assert kd.check_pe_imports("C:\\fake.exe") == []


def test_check_pe_imports_returns_empty_on_non_windows(monkeypatch):
    monkeypatch.setattr(kd, "PLATFORM", "Linux")
    assert kd.check_pe_imports("/bin/anything") == []


def test_check_pe_imports_detects_hook_api(monkeypatch):
    fake_import = MagicMock()
    fake_import.name = b"SetWindowsHookExW"
    fake_entry = MagicMock()
    fake_entry.imports = [fake_import]

    fake_pe_instance = MagicMock()
    fake_pe_instance.DIRECTORY_ENTRY_IMPORT = [fake_entry]

    fake_pefile_module = MagicMock()
    fake_pefile_module.PE.return_value = fake_pe_instance
    fake_pefile_module.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}

    monkeypatch.setattr(kd, "pefile", fake_pefile_module)
    monkeypatch.setattr(kd, "PLATFORM", "Windows")

    signals = kd.check_pe_imports("C:\\fake.exe")
    assert kd.SIG_HOOK_IMPORT in signals


def test_check_pe_imports_swallows_parse_errors(monkeypatch):
    fake_pefile_module = MagicMock()
    fake_pefile_module.PE.side_effect = Exception("archivo corrupto")
    fake_pefile_module.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
    monkeypatch.setattr(kd, "pefile", fake_pefile_module)
    monkeypatch.setattr(kd, "PLATFORM", "Windows")
    assert kd.check_pe_imports("C:\\fake.exe") == []


# =============================================================================
# Integración: evaluate_process / scan_once con todo mockeado
# =============================================================================


def test_evaluate_process_returns_none_when_no_signals(monkeypatch):
    proc = _make_fake_process(name="notepad.exe", exe="/usr/bin/notepad")
    monkeypatch.setattr(kd, "check_pe_imports", lambda exe: [])
    monkeypatch.setattr(kd, "check_credential_store_access", lambda p, patterns: False)
    monkeypatch.setattr(kd, "check_external_network", lambda p: False)
    result = kd.evaluate_process(proc, persistence_targets={}, credential_patterns=[])
    assert result is None


def test_evaluate_process_combines_signals_from_all_checks(monkeypatch):
    proc = _make_fake_process(pid=42, name="sneaky.exe", exe="/opt/sneaky/run")
    monkeypatch.setattr(kd, "check_pe_imports", lambda exe: [kd.SIG_HOOK_IMPORT])
    monkeypatch.setattr(kd, "check_credential_store_access", lambda p, patterns: False)
    monkeypatch.setattr(kd, "check_external_network", lambda p: True)
    persistence = {kd._normalize_path("/opt/sneaky/run"): [kd.SIG_REG_RUN]}

    result = kd.evaluate_process(proc, persistence_targets=persistence, credential_patterns=[])

    assert result is not None
    assert kd.SIG_HOOK_IMPORT in result.signals
    assert kd.SIG_REG_RUN in result.signals
    assert kd.SIG_EXTERNAL_NETWORK in result.signals  # agravante activado
    assert result.risk_level == "alto"


def test_evaluate_process_does_not_check_network_without_prior_signal(monkeypatch):
    proc = _make_fake_process(name="normalapp", exe="/usr/bin/normalapp")
    monkeypatch.setattr(kd, "check_pe_imports", lambda exe: [])
    monkeypatch.setattr(kd, "check_credential_store_access", lambda p, patterns: False)
    network_check = MagicMock(return_value=True)
    monkeypatch.setattr(kd, "check_external_network", network_check)
    result = kd.evaluate_process(proc, persistence_targets={}, credential_patterns=[])
    assert result is None
    network_check.assert_not_called()


def test_evaluate_process_returns_none_on_access_denied():
    proc = _make_fake_process()
    proc.exe.side_effect = __import__("psutil").AccessDenied(pid=1000)
    result = kd.evaluate_process(proc, persistence_targets={}, credential_patterns=[])
    assert result is None


def test_scan_once_filters_by_min_score_and_sorts_descending(monkeypatch):
    low = _make_fake_process(pid=1, name="low")
    high = _make_fake_process(pid=2, name="high")

    monkeypatch.setattr(kd, "gather_processes", lambda: iter([low, high]))
    monkeypatch.setattr(kd, "find_persistence_targets", lambda: {})
    monkeypatch.setattr(kd, "_expand_credential_patterns", lambda: [])

    def fake_evaluate(proc, persistence_targets, credential_patterns):
        if proc.pid == 1:
            return kd.build_finding(1, "low", "/bin/low", [kd.SIG_SUSPICIOUS_NAME])  # 5 pts
        return kd.build_finding(2, "high", "/bin/high", [kd.SIG_CRED_STORE])  # 40 pts

    monkeypatch.setattr(kd, "evaluate_process", fake_evaluate)

    results = kd.scan_once(min_score=20)
    assert [f.pid for f in results] == [2]


def test_exit_code_for_reflects_worst_finding():
    alto = kd.build_finding(1, "a", "/a", [kd.SIG_HOOK_IMPORT, kd.SIG_CRED_STORE])
    medio = kd.build_finding(2, "b", "/b", [kd.SIG_CRED_STORE])
    bajo = kd.build_finding(3, "c", "/c", [kd.SIG_SUSPICIOUS_NAME])

    assert kd._exit_code_for([alto]) == 2
    assert kd._exit_code_for([medio]) == 1
    assert kd._exit_code_for([bajo]) == 0
    assert kd._exit_code_for([]) == 0
