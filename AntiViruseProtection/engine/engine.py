"""Stasivyn Security scanning engine foundation.

This module is deliberately separate from the Tkinter interface.

IMPORTANT:
- A file not found in the local hash database is UNKNOWN, not CLEAN.
- The local TXT database is supplied by the updater; unmatched hashes remain unknown.
- This module does not provide real-time protection or secure quarantine yet.
"""

from __future__ import annotations

import hashlib
import os
import re
import string
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Callable, Iterator


APP_NAME = "Stasivyn Security"
ENGINE_VERSION = "0.1.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "Updater" / "data"
HASH_DATABASE_PATH = DATA_DIR / "threat_hashes.txt"
_HASH_DATABASE_CACHE: dict[str, str] | None = None
_HASH_DATABASE_CACHE_KEY: tuple[int, int] | None = None


# ---------------------------------------------------------------------------
# 1. Result types and basic status
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Result for one inspected file."""

    path: str
    status: str  # known_threat, unknown, or error
    sha256: str | None = None
    threat_name: str | None = None
    message: str = ""
    category: str = "Files"


@dataclass
class ScanSummary:
    """Summary returned after a quick or full scan."""

    scan_type: str
    scanned: int
    known_threats: int
    errors: int
    cancelled: bool
    results: list[ScanResult]
    category_counts: dict[str, int] = field(default_factory=dict)
    category_errors: dict[str, int] = field(default_factory=dict)
    processes_found: int = 0
    registry_entries_checked: int = 0
    warnings: list[str] = field(default_factory=list)


def get_engine_status() -> dict[str, str | bool | int]:
    """Report engine readiness without claiming the computer is protected."""
    database_exists = HASH_DATABASE_PATH.is_file()
    database_size = 0

    if database_exists:
        try:
            database = _load_hash_database()
            database_size = len(database)
        except (OSError, ValueError, UnicodeError):
            return {
                "engine_version": ENGINE_VERSION,
                "scanner_available": True,
                "hash_database": "invalid",
                "definitions": False,
                "definition_count": 0,
                "realtime_protection": False,
                "message": "The hash database could not be read.",
            }

    return {
        "engine_version": ENGINE_VERSION,
        "scanner_available": True,
        "hash_database": "loaded" if database_size else "empty",
        "definitions": database_size > 0,
        "definition_count": database_size,
        "realtime_protection": False,
        "message": (
            f"Loaded {database_size} hash definition(s)."
            if database_size
            else "No threat definitions are installed. Files can be hashed, but cannot be declared safe."
        ),
    }


# ---------------------------------------------------------------------------
# 2. Input validation and hash database
# ---------------------------------------------------------------------------

def _normalise_sha256(file_hash: str) -> str:
    value = file_hash.strip().lower()
    if len(value) != 64 or any(char not in string.hexdigits.lower() for char in value):
        raise ValueError("A SHA-256 hash must contain exactly 64 hexadecimal characters.")
    return value


def _load_hash_database() -> dict[str, str]:
    """Load SHA-256 definitions from the updater's newline-delimited TXT file.

    Supported lines:
        <64-character-sha256>
        <64-character-sha256>|<optional threat label>

    The updater currently writes one bare SHA-256 hash per line, so those
    entries receive a generic label. A hash match means a known signature was
    found; no match means UNKNOWN, not proven safe.
    """
    global _HASH_DATABASE_CACHE, _HASH_DATABASE_CACHE_KEY

    if not HASH_DATABASE_PATH.is_file():
        _HASH_DATABASE_CACHE = {}
        _HASH_DATABASE_CACHE_KEY = None
        return {}

    stat = HASH_DATABASE_PATH.stat()
    cache_key = (stat.st_mtime_ns, stat.st_size)
    if _HASH_DATABASE_CACHE is not None and _HASH_DATABASE_CACHE_KEY == cache_key:
        return _HASH_DATABASE_CACHE

    definitions: dict[str, str] = {}
    with HASH_DATABASE_PATH.open("r", encoding="utf-8") as database_file:
        for line_number, raw_line in enumerate(database_file, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if "|" in line:
                raw_hash, threat_name = line.split("|", 1)
                threat_name = threat_name.strip() or "Known threat (SHA-256 match)"
            else:
                raw_hash = line
                threat_name = "Known threat (SHA-256 match)"

            try:
                checked_hash = _normalise_sha256(raw_hash)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid SHA-256 entry on line {line_number} of {HASH_DATABASE_PATH.name}."
                ) from exc

            definitions[checked_hash] = threat_name

    _HASH_DATABASE_CACHE = definitions
    _HASH_DATABASE_CACHE_KEY = cache_key
    return definitions


def check_hash_database(file_hash: str) -> str | None:
    """Return a known threat name, or None when no definition matches.

    None means UNKNOWN. It must never be displayed as proof that a file is safe.
    """
    checked_hash = _normalise_sha256(file_hash)
    return _load_hash_database().get(checked_hash)


# ---------------------------------------------------------------------------
# 3. File hashing and individual-file inspection
# ---------------------------------------------------------------------------

def calculate_sha256(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate a file's SHA-256 hash without loading the whole file into RAM."""
    file_path = Path(path).expanduser()

    if file_path.is_symlink():
        raise ValueError("Symbolic links are not scanned by this engine.")
    if not file_path.exists():
        raise FileNotFoundError(file_path)
    if not file_path.is_file():
        raise IsADirectoryError(file_path)
    if chunk_size < 4096:
        raise ValueError("chunk_size must be at least 4096 bytes.")

    digest = hashlib.sha256()
    with file_path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def detect_threat(path: str | Path) -> dict[str, str | None]:
    """Check one file against the local hash definitions."""
    file_hash = calculate_sha256(path)
    threat_name = check_hash_database(file_hash)
    return {
        "path": str(Path(path).expanduser().resolve()),
        "sha256": file_hash,
        "status": "known_threat" if threat_name else "unknown",
        "threat_name": threat_name,
    }


def scan_file(path: str | Path) -> ScanResult:
    """Inspect a single file and return a structured result."""
    file_path = Path(path).expanduser()
    try:
        detection = detect_threat(file_path)
        if detection["status"] == "known_threat":
            return ScanResult(
                path=detection["path"] or str(file_path),
                status="known_threat",
                sha256=detection["sha256"],
                threat_name=detection["threat_name"],
                message="File hash matched a local threat definition.",
            )

        return ScanResult(
            path=detection["path"] or str(file_path),
            status="unknown",
            sha256=detection["sha256"],
            message="No matching hash definition. This does not prove the file is safe.",
        )
    except (OSError, ValueError) as error:
        return ScanResult(
            path=str(file_path),
            status="error",
            message=f"Could not inspect file: {error}",
        )


# ---------------------------------------------------------------------------
# 4. File discovery and scan orchestration
# ---------------------------------------------------------------------------

ProgressCallback = Callable[[int, ScanResult], None]


def _is_link_or_junction(path: Path) -> bool:
    """Avoid symbolic links and Windows junctions during recursive scans."""
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction()) if callable(is_junction) else False


def _iter_files(
    roots: list[str | Path],
    on_error: Callable[[OSError], None] | None = None,
) -> Iterator[Path]:
    """Yield regular files beneath roots, skipping symbolic links.

    Directory traversal errors are reported to on_error instead of silently
    disappearing from the scan summary.
    """
    for root_value in roots:
        root = Path(root_value).expanduser()
        try:
            if not root.exists() or _is_link_or_junction(root):
                continue
            if root.is_file():
                yield root
                continue
        except OSError as error:
            if on_error is not None:
                on_error(error)
            continue

        def report_walk_error(error: OSError) -> None:
            if on_error is not None:
                on_error(error)

        for current_dir, dir_names, file_names in os.walk(
            root, followlinks=False, onerror=report_walk_error
        ):
            current_path = Path(current_dir)
            kept_dirs = []
            for name in dir_names:
                candidate_dir = current_path / name
                try:
                    if not _is_link_or_junction(candidate_dir):
                        kept_dirs.append(name)
                except OSError as error:
                    report_walk_error(error)
            dir_names[:] = kept_dirs

            for file_name in file_names:
                candidate = current_path / file_name
                try:
                    if candidate.is_file() and not _is_link_or_junction(candidate):
                        yield candidate
                except OSError as error:
                    report_walk_error(error)


def _unique_existing_paths(paths: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            if not path.exists() or _is_link_or_junction(path):
                continue
            identity = os.path.normcase(str(path.resolve()))
        except OSError:
            continue
        if identity not in seen:
            unique.append(path)
            seen.add(identity)
    return unique


def _temporary_scan_roots() -> list[Path]:
    candidates = [Path(tempfile.gettempdir())]
    for variable in ("TEMP", "TMP"):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value))
    windows_dir = os.environ.get("WINDIR")
    if windows_dir:
        candidates.append(Path(windows_dir) / "Temp")
    return _unique_existing_paths(candidates)


def get_quick_scan_targets() -> dict[str, list[Path]]:
    """Return the small set of common user folders included in Quick Scan."""
    home = Path.home()
    return {
        "Downloads": _unique_existing_paths([home / "Downloads"]),
        "Desktop": _unique_existing_paths([home / "Desktop"]),
        "Temporary files": _temporary_scan_roots(),
    }


def get_full_scan_targets() -> dict[str, list[Path]]:
    """Return automatic folder targets for Full Scan.

    This scans common user locations and AppData, not every file on every drive.
    Running process executables and selected registry references are gathered
    separately by full_scan().
    """
    home = Path.home()
    appdata_root = home / "AppData"
    if appdata_root.is_dir():
        appdata_candidates = [appdata_root]
    else:
        appdata_candidates = []
        appdata_roaming = os.environ.get("APPDATA")
        appdata_local = os.environ.get("LOCALAPPDATA")
        if appdata_roaming:
            appdata_candidates.append(Path(appdata_roaming))
        if appdata_local:
            appdata_candidates.append(Path(appdata_local))

    return {
        "Downloads": _unique_existing_paths([home / "Downloads"]),
        "Desktop": _unique_existing_paths([home / "Desktop"]),
        "Temporary files": _temporary_scan_roots(),
        "AppData": _unique_existing_paths(appdata_candidates),
    }


def get_running_process_executables() -> tuple[list[Path], int, list[str]]:
    """Return executable paths for running Windows processes.

    This inspects process image paths only. It does not inspect process memory,
    inject code, terminate processes, or change process state.
    """
    if os.name != "nt":
        return [], 0, ["Running-process inspection is only available on Windows."]

    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot == invalid_handle:
        error_code = ctypes.get_last_error()
        return [], 0, [f"Could not list running processes (Windows error {error_code})."]

    paths: list[Path] = []
    process_count = 0
    inaccessible = 0
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        has_entry = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while has_entry:
            process_count += 1
            process_handle = kernel32.OpenProcess(
                0x1000,  # PROCESS_QUERY_LIMITED_INFORMATION
                False,
                entry.th32ProcessID,
            )
            if process_handle:
                try:
                    buffer = ctypes.create_unicode_buffer(32768)
                    buffer_size = wintypes.DWORD(len(buffer))
                    if kernel32.QueryFullProcessImageNameW(
                        process_handle, 0, buffer, ctypes.byref(buffer_size)
                    ):
                        paths.append(Path(buffer.value))
                    else:
                        inaccessible += 1
                finally:
                    kernel32.CloseHandle(process_handle)
            else:
                inaccessible += 1

            has_entry = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    paths = _unique_existing_paths(paths)
    warnings = []
    if inaccessible:
        warnings.append(
            f"Executable paths were unavailable for {inaccessible} running process(es)."
        )
    return paths, process_count, warnings


_REGISTRY_FILE_PATTERN = re.compile(
    r'"([^"\r\n]+?\.(?:exe|dll|sys|com|bat|cmd|ps1|vbs|js))"'
    r'|([A-Za-z]:\\[^"\r\n,;]*?\.(?:exe|dll|sys|com|bat|cmd|ps1|vbs|js))',
    re.IGNORECASE,
)


def _paths_from_registry_command(command: str) -> list[Path]:
    """Extract likely executable/script/module file paths from a registry value."""
    expanded = os.path.expandvars(command.strip())
    for variable in ("SystemRoot", "WINDIR"):
        value = os.environ.get(variable)
        if value:
            expanded = re.sub(
                rf"%{variable}%", lambda _match, value=value: value,
                expanded, flags=re.IGNORECASE,
            )
    windows_dir = os.environ.get("WINDIR")
    if windows_dir:
        expanded = re.sub(
            r"\\SystemRoot(?=\\)", lambda _match: windows_dir,
            expanded, flags=re.IGNORECASE,
        )
    expanded = expanded.replace("\\??\\", "")

    found: list[Path] = []
    for match in _REGISTRY_FILE_PATTERN.finditer(expanded):
        value = match.group(1) or match.group(2)
        candidate = Path(value.strip())
        try:
            if candidate.is_file() and not _is_link_or_junction(candidate):
                found.append(candidate)
        except OSError:
            continue
    return _unique_existing_paths(found)


def get_registry_autostart_targets() -> tuple[list[Path], int, list[str]]:
    """Read common Windows auto-start and service ImagePath registry values.

    Registry access is strictly read-only. This is not a scan of every registry
    hive or key; it checks common persistence locations and service image paths.
    """
    if os.name != "nt":
        return [], 0, ["Windows Registry inspection is only available on Windows."]

    import winreg

    targets: list[Path] = []
    entries_checked = 0
    warnings: list[str] = []

    value_locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    ]

    for hive, subkey_path in value_locations:
        try:
            with winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        _name, data, _value_type = winreg.EnumValue(key, index)
                    except OSError as error:
                        error_code = getattr(error, "winerror", None) or getattr(error, "errno", None)
                        if error_code != 259:
                            warnings.append(f"Could not enumerate registry key {subkey_path}: {error}")
                        break
                    index += 1
                    entries_checked += 1
                    if isinstance(data, str):
                        targets.extend(_paths_from_registry_command(data))
        except FileNotFoundError:
            continue
        except OSError as error:
            warnings.append(f"Could not read registry key {subkey_path}: {error}")

    services_path = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, services_path, 0, winreg.KEY_READ
        ) as services_key:
            index = 0
            while True:
                try:
                    service_name = winreg.EnumKey(services_key, index)
                except OSError as error:
                    error_code = getattr(error, "winerror", None) or getattr(error, "errno", None)
                    if error_code != 259:
                        warnings.append(f"Could not enumerate Windows service keys: {error}")
                    break
                index += 1
                try:
                    with winreg.OpenKey(
                        services_key, service_name, 0, winreg.KEY_READ
                    ) as service_key:
                        data, _value_type = winreg.QueryValueEx(service_key, "ImagePath")
                        entries_checked += 1
                        if isinstance(data, str):
                            targets.extend(_paths_from_registry_command(data))
                except FileNotFoundError:
                    continue
                except OSError as error:
                    warnings.append(
                        f"Could not read service registry entry {service_name}: {error}"
                    )
    except FileNotFoundError:
        warnings.append("The Windows Services registry key was not found.")
    except OSError as error:
        warnings.append(f"Could not read Windows Services registry entries: {error}")

    return _unique_existing_paths(targets), entries_checked, warnings


def _run_categorized_scan(
    scan_type: str,
    targets: dict[str, list[Path]],
    progress_callback: ProgressCallback | None = None,
    cancel_event: Event | None = None,
    processes_found: int = 0,
    registry_entries_checked: int = 0,
    initial_warnings: list[str] | None = None,
) -> ScanSummary:
    results: list[ScanResult] = []
    category_counts: dict[str, int] = {name: 0 for name in targets}
    category_errors: dict[str, int] = {name: 0 for name in targets}
    warnings = list(initial_warnings or [])
    visited: dict[str, ScanResult] = {}
    scanned = 0
    known_threats = 0
    errors = 0
    cancelled = False

    for category, category_roots in targets.items():
        def report_walk_error(error: OSError, category_name: str = category) -> None:
            nonlocal errors
            errors += 1
            category_errors[category_name] = category_errors.get(category_name, 0) + 1
            warnings.append(f"{category_name}: {error}")

        for root in category_roots:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
            try:
                if not root.exists():
                    warnings.append(f"{category}: location not present: {root}")
                    continue
            except OSError as error:
                report_walk_error(error)
                continue

            for file_path in _iter_files([root], on_error=report_walk_error):
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
                try:
                    identity = os.path.normcase(str(file_path.resolve()))
                except OSError as error:
                    report_walk_error(error)
                    continue

                category_counts[category] = category_counts.get(category, 0) + 1
                cached_result = visited.get(identity)
                if cached_result is not None:
                    continue

                result = scan_file(file_path)
                result.category = category
                visited[identity] = result
                results.append(result)
                scanned += 1
                if result.status == "known_threat":
                    known_threats += 1
                elif result.status == "error":
                    errors += 1
                    category_errors[category] = category_errors.get(category, 0) + 1

                if progress_callback is not None:
                    progress_callback(scanned, result)

            if cancelled:
                break
        if cancelled:
            break

    return ScanSummary(
        scan_type=scan_type,
        scanned=scanned,
        known_threats=known_threats,
        errors=errors,
        cancelled=cancelled,
        results=results,
        category_counts=category_counts,
        category_errors=category_errors,
        processes_found=processes_found,
        registry_entries_checked=registry_entries_checked,
        warnings=warnings,
    )


def quick_scan(
    progress_callback: ProgressCallback | None = None,
    cancel_event: Event | None = None,
) -> ScanSummary:
    """Scan Downloads, Desktop, and temporary folders."""
    return _run_categorized_scan(
        "Quick Scan",
        get_quick_scan_targets(),
        progress_callback=progress_callback,
        cancel_event=cancel_event,
    )


def full_scan(
    roots: list[str | Path] | None = None,
    progress_callback: ProgressCallback | None = None,
    cancel_event: Event | None = None,
) -> ScanSummary:
    """Automatically scan user folders, AppData, process images and registry targets.

    Optional roots are retained for callers that explicitly want a custom
    folder scan. The normal application Full Scan passes no roots and uses the
    automatic Windows coverage.
    """
    if roots:
        custom_targets = {"Selected folders": [Path(root) for root in roots]}
        return _run_categorized_scan(
            "Full Scan",
            custom_targets,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )

    targets = get_full_scan_targets()
    warnings: list[str] = []

    process_paths, processes_found, process_warnings = get_running_process_executables()
    targets["Running processes"] = process_paths
    warnings.extend(process_warnings)

    registry_paths, registry_entries_checked, registry_warnings = (
        get_registry_autostart_targets()
    )
    targets["Windows Registry"] = registry_paths
    warnings.extend(registry_warnings)

    return _run_categorized_scan(
        "Full Scan",
        targets,
        progress_callback=progress_callback,
        cancel_event=cancel_event,
        processes_found=processes_found,
        registry_entries_checked=registry_entries_checked,
        initial_warnings=warnings,
    )


# ---------------------------------------------------------------------------
# 5. Quarantine (intentionally not implemented yet)
# ---------------------------------------------------------------------------

def quarantine_file(path: str | Path) -> None:
    """TODO: implement secure, reversible quarantine after review and testing."""
    raise NotImplementedError(
        "Quarantine is not implemented. Do not delete or move files automatically."
    )


def get_quarantine_items() -> list[dict[str, str]]:
    """TODO: return verified quarantine records after quarantine is implemented."""
    raise NotImplementedError("Quarantine storage is not implemented yet.")


def restore_quarantined_file(file_id: str) -> None:
    """TODO: safely restore a selected quarantined file after user confirmation."""
    raise NotImplementedError("Quarantine restoration is not implemented yet.")


# ---------------------------------------------------------------------------
# 6. Real-time protection (intentionally not implemented yet)
# ---------------------------------------------------------------------------

def start_realtime_protection() -> None:
    """TODO: add a tested Windows file-monitoring service; not active yet."""
    raise NotImplementedError("Real-time protection is not implemented yet.")


def stop_realtime_protection() -> None:
    """TODO: stop the Windows monitoring service after it is implemented."""
    raise NotImplementedError("Real-time protection is not implemented yet.")
