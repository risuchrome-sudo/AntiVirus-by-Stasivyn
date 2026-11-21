# Stasivyn Security scan notes

## Quick Scan

Checks Downloads, Desktop, and available temporary folders.

## Full Scan

Checks Downloads, Desktop, temporary folders, the current user's AppData folders, running process executable paths, and selected Windows Registry startup/service entries. It does not scan every drive, process memory, or every registry key.

## Detection results

- **Known hash match:** the file's SHA-256 exactly matches an entry in the local MalwareBazaar-derived hash database.
- **YARA heuristic match:** one or more rules matched. This is suspicious and needs manual review; it is not proof that the file is malware.
- **Unknown:** no local hash or YARA rule matched. This does not prove the file is safe.
- **Error:** the file could not be inspected.

YARA rules are compiled by `engine/YARA/yara_scanner.py` when first needed and recompiled when rule files change. The scanner includes `.yar` and `.yara` files recursively under `engine/YARA/rules/`.

## Safety and remaining features

Scans are read-only. They do not move, delete, terminate, or quarantine files. Quarantine and real-time protection are not implemented yet. Process inspection reads executable file paths only; it does not inspect process memory. Registry inspection is read-only and limited to selected startup and service entries.

## Run

```powershell
.venv\Scripts\python.exe interface\interface.py
```
