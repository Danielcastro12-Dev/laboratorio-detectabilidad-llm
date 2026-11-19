from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate task manifest against experiment config")
    parser.add_argument("--tasks", type=Path, required=True)
    args = parser.parse_args()

    with args.tasks.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    errors = []
    required = {"task_id", "cwe", "source_dataset", "source_version", "language", "prompt_path", "prompt_line"}
    if rows:
        missing = required - set(rows[0])
        if missing:
            errors.append(f"Missing columns: {sorted(missing)}")
    else:
        errors.append("Manifest is empty")

    if not errors:
        from collections import Counter
        cwe_counts = Counter(r["cwe"] for r in rows)
        task_ids = [r["task_id"] for r in rows]
        duplicates = len(task_ids) - len(set(task_ids))
        missing_files = sum(1 for r in rows if not (Path(r["prompt_path"]).is_file()))
        invalid_lines = 0
        for r in rows:
            path = Path(r["prompt_path"])
            if path.is_file():
                line = int(r["prompt_line"])
                if line < 1 or line > len(path.read_text(encoding="utf-8").splitlines()):
                    invalid_lines += 1
            else:
                invalid_lines += 1

        print("Manifest valid" if not errors else "Manifest invalid")
        print(f"Tasks: {len(rows)}")
        print(f"CWE distribution: {dict(cwe_counts)}")
        print(f"Duplicate task_ids: {duplicates}")
        print(f"Missing files: {missing_files}")
        print(f"Invalid line numbers: {invalid_lines}")
        return 0 if not (duplicates or missing_files or invalid_lines) else 1

    for error in errors:
        print(error)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
