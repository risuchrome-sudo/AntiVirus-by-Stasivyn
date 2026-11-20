# Stasivyn Security scan notes

## Quick Scan

Quick Scan checks Downloads, Desktop, and available temporary folders.

## Full Scan

Full Scan starts automatically and checks Downloads, Desktop, temporary folders, the current user's AppData folders, running process executable files, and files referenced by selected Windows Registry startup and service entries.

Process inspection reads executable paths only. It does not inspect process memory or stop processes. Registry inspection is read-only and limited to common Run, RunOnce, Winlogon, and service ImagePath entries. This is not a complete scan of every drive, every registry key, or every process's memory.

## Results

The scan summary lists unique files inspected, known SHA-256 matches, errors, process count, registry entries checked, per-category file candidates, and warnings. Inaccessible paths may be skipped and appear in warnings. Run with appropriate Windows permissions to improve coverage; the application does not silently claim inaccessible locations are clean.

A hash that does not match the local database is unknown, not proven safe. The scanner does not move, delete, or quarantine detected files.

## Run

From the project folder on Windows:

```powershell
py interface\interface.py
```
