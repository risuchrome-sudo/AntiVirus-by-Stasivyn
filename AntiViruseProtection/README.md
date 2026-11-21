# Stasivyn Security

A local defensive scanning project with SHA-256 matching and YARA heuristic scanning.

Start with `INTEGRATION_NOTES.md` for install, update, validation, and current limitations.

**Important:** this is a learning project, not a replacement for Windows Security or a commercial antivirus. Unknown files are not automatically safe. YARA matches are heuristic and require review. Scan metadata is cached in `data/safing.json`; the cache is invalidated when definitions change and is never an unconditional whitelist.

The Python engine remains the fallback. An optional native Windows engine is provided under `native/`; build it with CMake against libyara and place the resulting `stasivyn.dll` beside the application. It loads automatically when present; set `STASIVYN_DISABLE_DLL=1` to force the Python fallback.

To check quarantine storage or make a non-destructive inspection copy of a flagged file:

```powershell
uv run --python 3.13 .\tools\check_quarantine.py
uv run --python 3.13 .\tools\check_quarantine.py C:\path\to\flagged-file.exe
```

Inspection copies are stored under `engine/quarantine/files/inspection/`; the original file is never moved or deleted. If copying fails, the command reports the original path.
