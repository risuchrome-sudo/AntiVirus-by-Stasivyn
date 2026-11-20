"""Update the local SHA-256 threat database from MalwareBazaar.

Expected project layout:
    engine/
        database_updater.py
        data/
            threat_hashes.txt

Set MALWAREBAZAAR_API_KEY in the environment before running this script.
No malware samples are downloaded; this script retrieves hash metadata only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API_URL = "https://mb-api.abuse.ch/api/v1/"
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
DEFAULT_HASH_FILE = Path(__file__).resolve().parent / "data" / "threat_hashes.txt"


class UpdateError(Exception):
    """Raised when the feed cannot be retrieved or validated."""


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value.strip()) is not None


def post_api(form_data: dict[str, str], api_key: str) -> dict[str, Any]:
    """Send one authenticated form request and parse the JSON response."""
    encoded_data = urlencode(form_data).encode("ascii")
    request = Request(
        API_URL,
        data=encoded_data,
        headers={
            "Auth-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "LocalAntivirusThreatHashUpdater/1.0",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=30) as response:
            raw_response = response.read()
    except HTTPError as exc:
        # The API can return useful JSON error details with an HTTP error code.
        raw_response = exc.read()
        try:
            error_data = json.loads(raw_response.decode("utf-8"))
            status = error_data.get("query_status", "unknown API error")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            status = f"HTTP {exc.code}"
        raise UpdateError(f"MalwareBazaar rejected the request: {status}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"Could not connect to MalwareBazaar: {exc}") from exc

    try:
        result = json.loads(raw_response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError("MalwareBazaar returned an unreadable response.") from exc

    if not isinstance(result, dict):
        raise UpdateError("MalwareBazaar returned an unexpected response format.")

    status = result.get("query_status")
    if status == "no_results":
        return {"query_status": status, "data": []}
    if status != "ok":
        raise UpdateError(f"MalwareBazaar API status: {status or 'missing status'}")

    records = result.get("data", [])
    if not isinstance(records, list):
        raise UpdateError("MalwareBazaar returned an invalid data list.")

    return result


def fetch_recent_detections(api_key: str, hours: int) -> tuple[set[str], int]:
    """Fetch family-labelled detections from the last 1–168 hours."""
    response = post_api(
        {"query": "recent_detections", "hours": str(hours)},
        api_key,
    )

    hashes: set[str] = set()
    invalid_records = 0

    for record in response.get("data", []):
        if not isinstance(record, dict):
            invalid_records += 1
            continue

        candidate = record.get("sha256_hash", "")
        if is_sha256(candidate):
            hashes.add(candidate.strip().lower())
        else:
            invalid_records += 1

    return hashes, invalid_records


def read_existing_hashes(path: Path) -> tuple[set[str], int]:
    """Load valid hashes already in the local file; ignore malformed lines."""
    if not path.exists():
        return set(), 0

    hashes: set[str] = set()
    invalid_lines = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                value = line.strip()
                if not value:
                    continue
                if is_sha256(value):
                    hashes.add(value.lower())
                else:
                    invalid_lines += 1
    except OSError as exc:
        raise UpdateError(f"Could not read {path}: {exc}") from exc

    return hashes, invalid_lines


def write_hashes_atomically(path: Path, hashes: set[str]) -> None:
    """Write a sorted database through a temporary file, then replace safely."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_name: str | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temp_file:
                temp_name = temp_file.name
                for value in sorted(hashes):
                    temp_file.write(value + "\n")
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.replace(temp_name, path)
            temp_name = None
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
    except OSError as exc:
        raise UpdateError(f"Could not safely write {path}: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Append verified SHA-256 detections to threat_hashes.txt."
    )
    parser.add_argument(
        "--hash-file",
        type=Path,
        default=DEFAULT_HASH_FILE,
        help=f"database path (default: {DEFAULT_HASH_FILE})",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=168,
        choices=range(1, 169),
        metavar="1-168",
        help="look-back window for family-labelled detections (default: 168 hours)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY", "").strip()

    if not api_key:
        print(
            "Error: set the MALWAREBAZAAR_API_KEY environment variable first.",
            file=sys.stderr,
        )
        return 2

    try:
        remote_hashes, invalid_remote = fetch_recent_detections(api_key, args.hours)
        existing_hashes, invalid_local = read_existing_hashes(args.hash_file)

        new_hashes = remote_hashes - existing_hashes
        combined_hashes = existing_hashes | remote_hashes

        # Do not touch the database until the API response has been validated.
        write_hashes_atomically(args.hash_file, combined_hashes)

    except UpdateError as exc:
        print(f"Update failed: {exc}", file=sys.stderr)
        return 1

    print(f"Feed: MalwareBazaar family-labelled detections (last {args.hours} hours)")
    print(f"New hashes added: {len(new_hashes)}")
    print(f"Total unique hashes: {len(combined_hashes)}")
    print(f"Invalid feed records skipped: {invalid_remote}")
    print(f"Invalid local lines removed: {invalid_local}")
    print(f"Database: {args.hash_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
