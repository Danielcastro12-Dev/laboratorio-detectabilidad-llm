from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from llm_lab.execution.test_runner import run_functional_test


def main() -> int:
    parser = argparse.ArgumentParser(description="Run functional tests on pilot outputs")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    with args.manifest.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    tasks: dict[str, dict[str, str]] = {}
    with args.tasks.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            tasks[row["task_id"]] = row

    raw_by_task: dict[str, dict[str, str]] = {}
    for task_id, task in tasks.items():
        path = Path(task["prompt_path"])
        line = int(task["prompt_line"])
        with path.open(encoding="utf-8") as f:
            for i, raw in enumerate(f, 1):
                if i == line:
                    raw_by_task[task_id] = json.loads(raw)
                    break

    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    pilot_dir = args.manifest.parent
    for record in manifest.get("records", []):
        if record.get("status") != "completed":
            continue
        task_id = record["task_id"]
        record_path = pilot_dir / f"{record['output_id']}.json"
        dataset_record = raw_by_task[task_id]
        result = run_functional_test(record_path, dataset_record)
        results.append(result)
        print(f"{result['model_id']} {task_id} -> {result['status']} ({result['duration_ms']}ms)")

    summary = {
        "total": len(results),
        "functional": sum(1 for r in results if r["status"] == "functional"),
        "non_functional": sum(1 for r in results if r["status"] == "non_functional"),
        "timeout": sum(1 for r in results if r["status"] == "timeout"),
        "results": results,
    }
    args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSummary: {summary['functional']}/{summary['total']} functional")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
