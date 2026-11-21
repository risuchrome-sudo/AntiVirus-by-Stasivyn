"""Crash-safe scan baseline used as a performance cache, never as a whitelist."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


BASELINE_PATH = Path(__file__).resolve().parent.parent / "data" / "safing.json"
BASELINE_VERSION = 1


def _definition_fingerprint(hash_path: Path, rules_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in [hash_path, *sorted(rules_dir.rglob("*.yar")), *sorted(rules_dir.rglob("*.yara"))]:
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(str(path).encode("utf-8", "surrogatepass"))
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        digest.update(str(stat.st_size).encode("ascii"))
    return digest.hexdigest()


class ScanBaseline:
    def __init__(self, path: Path = BASELINE_PATH) -> None:
        self.path = path
        self.data: dict[str, Any] = {"version": BASELINE_VERSION, "definition_fingerprint": "", "files": {}}
        self.load()

    def load(self) -> None:
        try:
            candidate = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(candidate, dict) or not isinstance(candidate.get("files", {}), dict):
                raise ValueError("baseline root/files must be objects")
            self.data = candidate
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            # A corrupt cache must cost performance, not stop protection.
            self.data = {"version": BASELINE_VERSION, "definition_fingerprint": "", "files": {}}

    def set_definition(self, hash_path: Path, rules_dir: Path) -> None:
        fingerprint = _definition_fingerprint(hash_path, rules_dir)
        if self.data.get("definition_fingerprint") != fingerprint:
            self.data = {"version": BASELINE_VERSION, "definition_fingerprint": fingerprint, "files": {}}
        self.data["definition_fingerprint"] = fingerprint

    def get(self, path: Path, size: int, mtime_ns: int) -> dict[str, Any] | None:
        entry = self.data.get("files", {}).get(str(path))
        if not isinstance(entry, dict) or entry.get("size") != size or entry.get("mtime_ns") != mtime_ns:
            return None
        if entry.get("status") == "error" or not entry.get("last_scanned"):
            return None
        return entry

    def record(self, path: Path, size: int, mtime_ns: int, result: Any) -> None:
        if result.status == "error" or not result.sha256:
            return
        self.data.setdefault("files", {})[str(path)] = {
            "path": str(path),
            "size": size,
            "mtime": mtime_ns / 1_000_000_000,
            "mtime_ns": mtime_ns,
            "sha256": result.sha256,
            "status": result.status,
            "threat_name": result.threat_name,
            "yara_matches": list(result.yara_matches),
            "last_scanned": time.time(),
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent,
                                            prefix=f".{self.path.name}.", suffix=".tmp", delete=False) as handle:
                temp_name = handle.name
                json.dump(self.data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            temp_name = None
        finally:
            if temp_name:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
