from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from llm_lab.execution.test_runner import (
    run_functional_test,  # type: ignore[import-untyped]
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run functional tests on full corpus outputs")
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

    dataset_root = Path("data/raw/CodeSecEval/data")
    raw_by_task: dict[str, dict[str, str]] = {}
    for task_id, task in tasks.items():
        subset = task.get("subset")
        if subset == "SecEvalBase":
            path = dataset_root / "SecEvalBase" / "test.jsonl"
        elif subset == "SecEvalPlus":
            path = dataset_root / "SecEvalPlus" / "test.jsonl"
        else:
            raise ValueError(f"Unknown subset {subset!r} for task {task_id}")
        line = int(task.get("line", task.get("prompt_line", "")))
        with path.open(encoding="utf-8") as f:
            for i, raw in enumerate(f, 1):
                if i == line:
                    raw_by_task[task_id] = json.loads(raw)
                    break

    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, object]] = []
    completed_ids: set[str] = set()
    if args.output.is_file():
        old = json.loads(args.output.read_text(encoding="utf-8"))
        results = old.get("results", [])
        completed_ids = {str(r["output_id"]) for r in results}
        print(f"Resuming: loaded {len(results)} existing results")

    corpus_dir = args.manifest.parent
    records = manifest.get("records", [])
    total = len(records)
    for idx, record in enumerate(records, 1):
        output_id = record["output_id"]
        if output_id in completed_ids:
            continue
        if record.get("status") != "completed":
            continue
        task_id = record["task_id"]
        task = tasks[task_id]
        record_path = corpus_dir / f"{output_id}.json"
        dataset_record = raw_by_task[task_id]
        dataset_record["entry_point"] = task.get("entry_point", "")
        result = run_functional_test(record_path, dataset_record)
        results.append(result)
        completed_ids.add(output_id)
        print(f"[{idx}/{total}] {record['model_id']} {task_id} -> {result['status']} ({result['duration_ms']}ms)")
        # Incremental save every 10 tests
        if len(results) % 10 == 0:
            summary = {
                "total": len(results),
                "functional": sum(1 for r in results if r["status"] == "functional"),
                "non_functional": sum(1 for r in results if r["status"] == "non_functional"),
                "partially_functional": sum(1 for r in results if r["status"] == "partially_functional"),
                "inconclusive": sum(1 for r in results if r["status"] == "inconclusive"),
                "timeout": sum(1 for r in results if r["status"] == "timeout"),
                "results": results,
            }
            args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    summary = {
        "total": len(results),
        "functional": sum(1 for r in results if r["status"] == "functional"),
        "non_functional": sum(1 for r in results if r["status"] == "non_functional"),
        "partially_functional": sum(1 for r in results if r["status"] == "partially_functional"),
        "inconclusive": sum(1 for r in results if r["status"] == "inconclusive"),
        "timeout": sum(1 for r in results if r["status"] == "timeout"),
        "results": results,
    }
    args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSummary: {summary['functional']}/{summary['total']} functional")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
