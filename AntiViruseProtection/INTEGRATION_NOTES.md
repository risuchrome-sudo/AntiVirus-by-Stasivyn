# Stasivyn Security integration notes

Run the application from the project folder with `py interface\interface.py`.

The interface imports the scanner from `engine/engine.py`. Quick Scan checks Downloads, Desktop, and available temporary folders. Full Scan runs automatically and also checks the user's AppData folders, running process executable paths, and selected Windows Registry startup and service ImagePath entries.

The engine reads `engine/Updater/data/threat_hashes.txt`, the same file used by the database updater. Lines may contain a SHA-256 hash alone or `sha256|Threat.Name`.

Process inspection reads executable paths only. Registry inspection is read-only and limited to common startup and service entries. Neither feature inspects process memory or scans every registry key. Some protected files, process paths, and registry entries may be inaccessible; these are reported as warnings. Running with appropriate Windows permissions can improve coverage.

Detection currently uses exact SHA-256 matches only. A file with no matching hash is UNKNOWN, not proven safe. Scans do not move, delete, or quarantine files. Quarantine and real-time protection are not implemented.
