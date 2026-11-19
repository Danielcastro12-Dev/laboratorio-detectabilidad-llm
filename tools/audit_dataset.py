from __future__ import annotations

import argparse
from pathlib import Path

from llm_lab.dataset_inventory import scan_dataset, write_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a CodeSecEval-style JSONL dataset")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    files = sorted(args.root.rglob("*.jsonl"))
    rows = scan_dataset(args.root)
    write_inventory(rows, args.output)
    python_tasks = sum(row["language"] == "python" for row in rows)
    tasks_with_tests = sum(row["has_tests"] == "true" for row in rows)
    print(f"Scanned files: {len(files)}")
    print(f"Candidate tasks: {len(rows)}")
    print(f"Python tasks: {python_tasks}")
    print(f"Tasks with tests: {tasks_with_tests}")
    print(f"Inventory written: {args.output.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
