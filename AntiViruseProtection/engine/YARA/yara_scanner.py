"""Compile and apply local YARA rules without executing scanned files."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any

try:
    import yara  # type: ignore
except ImportError:  # YARA is optional; hash scanning still works without it.
    yara = None

RULES_DIR = Path(__file__).resolve().parent / "rules"
MATCH_TIMEOUT_SECONDS = 8
_CACHE_LOCK = RLock()
_CACHE_SIGNATURE: tuple[tuple[str, int, int], ...] | None = None
_CACHE_RULES: Any = None
_CACHE_WARNINGS: tuple[str, ...] = ()
_CACHE_FILE_COUNT = 0


@dataclass(frozen=True)
class YaraStatus:
    available: bool
    compiled: bool
    rule_files: int
    warnings: tuple[str, ...]


def _rule_files() -> list[Path]:
    if not RULES_DIR.is_dir():
        return []
    return sorted(
        path for path in RULES_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yar", ".yara"}
    )


def _get_compiled_rules() -> tuple[Any, tuple[str, ...], int]:
    """Return cached compiled rules, compiling again when any rule changes."""
    global _CACHE_SIGNATURE, _CACHE_RULES, _CACHE_WARNINGS, _CACHE_FILE_COUNT

    if yara is None:
        return None, ("yara-python is not installed; YARA scanning is disabled.",), 0

    files = _rule_files()
    signature_parts: list[tuple[str, int, int]] = []
    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        signature_parts.append((str(path), stat.st_mtime_ns, stat.st_size))
    signature = tuple(signature_parts)

    with _CACHE_LOCK:
        if signature == _CACHE_SIGNATURE:
            return _CACHE_RULES, _CACHE_WARNINGS, _CACHE_FILE_COUNT

        warnings: list[str] = []
        valid_files: list[Path] = []
        for path in files:
            try:
                if path.stat().st_size == 0:
                    continue
                # Compile each file on its own first so a bad community rule
                # cannot invalidate all the other rules.
                yara.compile(filepath=str(path), includes=False)
                valid_files.append(path)
            except Exception as exc:
                warnings.append(f"Could not compile {path.relative_to(RULES_DIR)}: {exc}")

        compiled_rules = None
        if valid_files:
            namespaces = {
                f"rule_{index}_{path.stem}": str(path)
                for index, path in enumerate(valid_files)
            }
            try:
                compiled_rules = yara.compile(filepaths=namespaces, includes=False)
            except Exception as exc:
                warnings.append(f"Could not combine YARA rules; using separate files: {exc}")
                # Keep only individually validated rules as a safe fallback.
                fallback = []
                for path in valid_files:
                    try:
                        fallback.append(yara.compile(filepath=str(path), includes=False))
                    except Exception as fallback_exc:
                        warnings.append(
                            f"Could not load {path.relative_to(RULES_DIR)}: {fallback_exc}"
                        )
                compiled_rules = fallback or None

        if not valid_files:
            warnings.append("No non-empty, valid .yar or .yara files were found.")

        _CACHE_SIGNATURE = signature
        _CACHE_RULES = compiled_rules
        _CACHE_WARNINGS = tuple(dict.fromkeys(warnings))
        _CACHE_FILE_COUNT = len(valid_files)
        return _CACHE_RULES, _CACHE_WARNINGS, _CACHE_FILE_COUNT


def get_yara_status() -> YaraStatus:
    """Compile/check rules and return YARA readiness information."""
    if yara is None:
        return YaraStatus(
            available=False,
            compiled=False,
            rule_files=0,
            warnings=("Install the requirements.txt dependencies to enable YARA.",),
        )
    compiled_rules, warnings, count = _get_compiled_rules()
    return YaraStatus(
        available=True,
        compiled=compiled_rules is not None,
        rule_files=count,
        warnings=warnings,
    )


def scan_file_with_yara(path: str | Path) -> tuple[list[str], list[str]]:
    """Return heuristic YARA matches and diagnostics for one file."""
    compiled_rules, warnings, _count = _get_compiled_rules()
    if compiled_rules is None:
        return [], list(warnings)

    matches: list[str] = []
    rule_sets = compiled_rules if isinstance(compiled_rules, list) else [compiled_rules]
    scan_warnings = list(warnings)
    for rules in rule_sets:
        try:
            found = rules.match(filepath=str(path), timeout=MATCH_TIMEOUT_SECONDS)
            for match in found:
                namespace = getattr(match, "namespace", "")
                rule_name = getattr(match, "rule", "UnknownRule")
                label = f"{namespace}::{rule_name}" if namespace else rule_name
                if label not in matches:
                    matches.append(label)
        except Exception as exc:
            scan_warnings.append(f"YARA scan issue for {Path(path).name}: {exc}")
    return matches, list(dict.fromkeys(scan_warnings))


def main() -> int:
    status = get_yara_status()
    print(f"YARA available: {status.available}")
    print(f"Valid rule files: {status.rule_files}")
    print(f"Compiled: {status.compiled}")
    for warning in status.warnings:
        print(f"WARNING: {warning}")
    return 0 if status.compiled else 1


if __name__ == "__main__":
    raise SystemExit(main())
