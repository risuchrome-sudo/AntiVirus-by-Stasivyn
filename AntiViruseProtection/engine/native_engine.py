"""Optional ctypes bridge for the native stasivyn.dll ABI."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
from ctypes import wintypes


class NativeScanError(RuntimeError):
    pass


class NativeEngine:
    def __init__(self, dll: Path) -> None:
        self.dll = dll
        self.library = ctypes.WinDLL(str(dll))
        self.library.stasivyn_initialize.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        self.library.stasivyn_initialize.restype = ctypes.c_int
        self.library.stasivyn_scan_file.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int), wintypes.LPWSTR, ctypes.c_size_t]
        self.library.stasivyn_scan_file.restype = ctypes.c_int
        self.library.stasivyn_cleanup.argtypes = []
        self.library.stasivyn_cleanup.restype = None
        hash_file = Path(__file__).resolve().parent / "Updater" / "data" / "threat_hashes.txt"
        rules_dir = Path(__file__).resolve().parent / "YARA" / "rules"
        code = self.library.stasivyn_initialize(str(hash_file), str(rules_dir))
        if code != 0:
            raise NativeScanError(f"stasivyn.dll initialization failed ({code})")

    def scan(self, path: Path) -> tuple[str, str]:
        status = ctypes.c_int(-1)
        message = ctypes.create_unicode_buffer(512)
        code = self.library.stasivyn_scan_file(str(path), ctypes.byref(status), message, len(message))
        if code != 0:
            raise NativeScanError(message.value or f"stasivyn.dll scan failed ({code})")
        return {0: "unknown", 1: "known_threat", 2: "suspicious"}.get(status.value, "error"), message.value

    def close(self) -> None:
        self.library.stasivyn_cleanup()


def load_native_engine() -> NativeEngine | None:
    if os.name != "nt" or os.environ.get("STASIVYN_DISABLE_DLL", "").lower() in {"1", "true", "yes"}:
        return None
    candidates = [Path(__file__).resolve().parent.parent / "stasivyn.dll", Path.cwd() / "stasivyn.dll"]
    for candidate in candidates:
        if candidate.is_file():
            return NativeEngine(candidate)
    return None
