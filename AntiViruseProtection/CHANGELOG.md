# Changelog

## [Unreleased]

### Added

- Persistent scan baseline at `data/safing.json`.
- Baseline invalidation when the SHA-256 database or YARA rules change.
- Atomic baseline writes to protect against interrupted updates.
- SHA-256 detection followed by YARA heuristic scanning.
- Optional native Windows `stasivyn.dll` integration through `ctypes.WinDLL()`.
- Native libyara C++ implementation using `yr_initialize()` and `yr_rules_scan_file()`.
- Five-hour scheduled full rechecks using the exact `18,000` second interval.
- Read-only live protection polling for new and modified files.
- Reversible quarantine with SHA-256 integrity verification.
- Safe restoration that refuses to overwrite an existing destination.
- Inspection-copy workflow that leaves the original file untouched.
- `tools/check_quarantine.py` for checking quarantine storage and creating inspection copies.
- Cryptographically verified GitHub commit checks before installing community YARA rules.

### Changed

- The interface now starts an initial full scan and live protection when the engine is available.
- Detection results can be copied for inspection or explicitly moved to quarantine after confirmation.
- Quarantine and protection status are displayed in the existing Tkinter interface.
- Documentation now describes the baseline, native engine, quarantine, and inspection workflows.

### Validation

- Python syntax compilation passed.
- YARA validation passed: 2 valid rule files compiled successfully.
- Engine status smoke test passed with 4,149 SHA-256 definitions loaded.
- Baseline cache reuse test passed.
- Quarantine move/restore round-trip test passed.
- Inspection-copy integrity test passed.

### Known limitations

- The native DLL must be built on Windows with libyara and a compatible C++ toolchain.
- Live monitoring currently uses polling rather than `ReadDirectoryChangesW`.
- Quarantine is explicit and user-confirmed; scans do not automatically move files.
- The project is defensive scanning software and does not replace Windows Security or commercial antivirus protection.
