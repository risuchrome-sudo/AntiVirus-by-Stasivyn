# Stasivyn Security integration notes

## Current scanning layers

- SHA-256 exact-match detection reads `engine/Updater/data/threat_hashes.txt`. A no-match result is UNKNOWN, not proof of safety.
- YARA scans files using the rules under `engine/YARA/rules/`, including nested community-rule folders. YARA findings are heuristic indicators and must be reviewed manually; they are not automatically treated as confirmed malware.
- Full Scan checks Downloads, Desktop, temporary folders, AppData, running process executable paths, and selected Windows Registry startup/service entries. It does not scan every drive, process memory, or every registry key.
- Scanning does not move, delete, or quarantine files.

## Install and run

From the project root in PowerShell:

```powershell
uv venv --python 3.13
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
.venv\Scripts\python.exe interface\interface.py
```

To validate the YARA rules without starting the GUI:

```powershell
.venv\Scripts\python.exe -m engine.YARA.yara_scanner
```

To prepare the Windows executable build tools (only needed when building the `.exe`):

```powershell
uv pip install --python .venv\Scripts\python.exe -r requirements-build.txt
```

To build the Windows folder application after installing the build requirements:

```powershell
.venv\Scripts\pyinstaller.exe AntiViruseProtection.spec
```

To download the Trellix ATR community rules (requires internet):

```powershell
.venv\Scripts\python.exe .\engine\YARA\yara_updater.py
```

The updater stores third-party rules in `engine/YARA/rules/community/trellix/`, preserves the two project rules, validates each rule before saving, and stores the upstream license. Review community-rule matches because false positives are possible.

To update the SHA-256 feed, set `MALWAREBAZAAR_API_KEY` in the current PowerShell session and run:

```powershell
uv run --python 3.13 .\engine\Updater\database_updater.py
```

## Remaining work

Quarantine is implemented as an explicit, reversible action through `quarantine_file`, `get_quarantine_items`, and `restore_quarantined_file`. It verifies SHA-256 before moving a file, writes an atomic index, refuses to overwrite an existing restore destination, and verifies content again before restoration. Scans and live protection never quarantine automatically. Live protection uses a read-only polling monitor and a five-hour scheduled full recheck. The quarantine index starts as valid empty JSON.

Scan metadata is stored atomically in `data/safing.json`. A cache entry is reused only when path, size, modification timestamp, and the combined hash/rule-definition fingerprint match. Errors are not cached as clean, and detection results remain detection results when reused.

`tools/check_quarantine.py` checks that quarantine storage exists and can create a verified inspection copy without changing the original file. Inspection-copy failures return the original path for manual review.

The optional native ABI is in `native/stasivyn_api.h` and `native/stasivyn.cpp`. It performs SHA-256, known-hash lookup, then libyara scanning. This checkout does not include a DLL or libyara binaries, so native build prerequisites must be installed separately.
