"""Download and validate public YARA rules from the Trellix ATR repository.

This updater downloads rule text only. It does not download or execute malware.
Existing personal rules are left untouched.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import yara
except ImportError:
    print("Error: yara-python is not installed in this Python environment.")
    print("Install it with: uv pip install yara-python==4.5.4")
    raise SystemExit(1)

REPOSITORY = "advanced-threat-research/Yara-Rules"
BRANCH = "master"
COMMIT_API_URL = f"https://api.github.com/repos/{REPOSITORY}/commits/{BRANCH}"
TREE_API_URL = f"https://api.github.com/repos/{REPOSITORY}/git/trees"
RAW_BASE_URL = f"https://raw.githubusercontent.com/{REPOSITORY}/{BRANCH}"

# yara_updater.py is stored in engine/YARA/.
RULES_DIR = Path(__file__).resolve().parent / "rules"
DESTINATION = RULES_DIR / "community" / "trellix"
USER_AGENT = "LocalAntivirus-YARA-Updater/1.0"
TIMEOUT_SECONDS = 30


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read()


def main() -> int:
    print(f"Source: {REPOSITORY} ({BRANCH})")
    print(f"Destination: {DESTINATION}")

    try:
        commit_data = json.loads(fetch_bytes(COMMIT_API_URL).decode("utf-8"))
        verification = commit_data.get("commit", {}).get("verification", {})
        commit_sha = commit_data.get("sha")
        tree_sha = commit_data.get("commit", {}).get("tree", {}).get("sha")
        if not commit_sha or not tree_sha or verification.get("verified") is not True:
            print("Error: upstream rule commit is not cryptographically verified; no files were changed.")
            return 1
        tree_data = json.loads(fetch_bytes(f"{TREE_API_URL}/{tree_sha}?recursive=1").decode("utf-8"))
        raw_base_url = f"https://raw.githubusercontent.com/{REPOSITORY}/{commit_sha}"
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Error: could not retrieve the GitHub file list: {exc}")
        return 1

    if tree_data.get("truncated"):
        print("Error: GitHub returned an incomplete file list; no files were changed.")
        return 1

    rule_paths = [
        item["path"]
        for item in tree_data.get("tree", [])
        if item.get("type") == "blob"
        and Path(item.get("path", "")).suffix.lower() in {".yar", ".yara"}
    ]

    if not rule_paths:
        print("No .yar or .yara files were found; no files were changed.")
        return 1

    DESTINATION.mkdir(parents=True, exist_ok=True)
    added_or_updated = 0
    skipped = 0

    for relative_path in rule_paths:
        url = f"{raw_base_url}/{relative_path}"
        try:
            raw_rule = fetch_bytes(url)
            rule_text = raw_rule.decode("utf-8-sig")
            # Compile before saving so invalid or incompatible rules are not installed.
            yara.compile(source=rule_text, includes=False)
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, yara.Error) as exc:
            print(f"SKIP {relative_path}: {exc}")
            skipped += 1
            continue

        # Keep repository paths inside the dedicated community-rules folder.
        output_path = (DESTINATION / Path(*relative_path.split("/"))).resolve()
        destination_root = DESTINATION.resolve()
        if not output_path.is_relative_to(destination_root):
            print(f"SKIP {relative_path}: unsafe repository path")
            skipped += 1
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
        try:
            temporary_path.write_text(rule_text, encoding="utf-8", newline="\n")
            temporary_path.replace(output_path)
            added_or_updated += 1
        except OSError as exc:
            temporary_path.unlink(missing_ok=True)
            print(f"SKIP {relative_path}: could not save file: {exc}")
            skipped += 1

    # Keep the upstream license beside the downloaded rules.
    try:
        license_text = fetch_bytes(f"{raw_base_url}/LICENSE").decode("utf-8-sig")
        (DESTINATION / "LICENSE.txt").write_text(
            license_text, encoding="utf-8", newline="\n"
        )
    except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, OSError) as exc:
        print(f"Warning: could not save upstream LICENSE: {exc}")

    print(f"Rules added/updated: {added_or_updated}")
    print(f"Rules skipped: {skipped}")
    print("Personal .yar files were not overwritten.")
    print("Downloaded rules are stored separately; personal rules were not overwritten.")
    print("The scanner compiles valid .yar/.yara files from the entire rules folder on demand.")
    return 0 if added_or_updated else 1


if __name__ == "__main__":
    raise SystemExit(main())
