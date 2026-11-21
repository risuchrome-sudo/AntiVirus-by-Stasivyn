"""Check quarantine storage and optionally copy a flagged file for inspection."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine import engine


def main() -> int:
    parser = argparse.ArgumentParser(description="Copy a flagged file without modifying the original.")
    parser.add_argument("path", nargs="?", help="flagged file to copy for inspection")
    args = parser.parse_args()
    print(f"Quarantine folder: {engine.QUARANTINE_DIR}")
    print(f"Exists: {engine.QUARANTINE_DIR.is_dir()}")
    print(f"Stored quarantine items: {len(engine.get_quarantine_items())}")
    if not args.path:
        return 0
    result = engine.copy_flagged_for_inspection(args.path)
    if result.get("copied"):
        print(f"Inspection copy: {result['inspection_path']}")
        print(f"Original left untouched: {result['source_path']}")
        return 0
    print(f"Could not copy the file: {result.get('error', 'unknown error')}", file=sys.stderr)
    print(f"Inspect the original path manually: {result['source_path']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
