from __future__ import annotations

import csv
import json
import re
from pathlib import Path

REQUIRED_COLUMNS = {"task_id", "cwe", "language", "has_tests"}
_CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def load_inventory(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or ())
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise ValueError(f"Missing columns: {sorted(missing)}")
        return list(reader)


def _normalise_cwe(task_id: str) -> str:
    match = _CWE_PATTERN.search(task_id)
    return f"CWE-{int(match.group(1))}" if match else "UNKNOWN"


def scan_dataset(root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.jsonl")):
        subset = path.parent.name
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON in {path}:{line_number}: {exc}") from exc
                task_id = str(record.get("ID", ""))
                rows.append(
                    {
                        "subset": subset,
                        "line": str(line_number),
                        "task_id": task_id,
                        "cwe": _normalise_cwe(task_id),
                        "language": "python",
                        "has_tests": str(bool(record.get("Test"))).lower(),
                    }
                )
    return rows


def write_inventory(rows: list[dict[str, str]], output: Path) -> None:
    if not rows:
        raise ValueError("No JSONL task records found")
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
