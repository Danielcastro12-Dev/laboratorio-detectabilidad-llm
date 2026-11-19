from __future__ import annotations

import argparse
import csv
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from llm_lab.detection.detector_runner import (
    extract_output_code,
    run_codeql_analyze,
    run_codeql_database_create,
)


def _cwe_from_task_id(task_id: str) -> str:
    """Derive expected CWE from the task ID prefix."""
    if task_id.startswith("CWE-"):
        part = task_id.split("_")[0]
        num = part.split("-")[1].lstrip("0") or "0"
        return f"CWE-{num}"
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CodeQL detector over generated corpus outputs")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("data/derived/detector_results_codeql.json"))
    parser.add_argument("--codeql-exe", type=Path, default=Path("tools/codeql/codeql/codeql.exe"))
    parser.add_argument("--query-suite", type=str, default="codeql/python-queries:codeql-suites/python-security-extended.qls")
    args = parser.parse_args()

    with args.manifest.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    tasks: dict[str, dict[str, str]] = {}
    with args.tasks.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            tasks[row["task_id"]] = row

    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    completed_ids: set[str] = set()
    if args.output.is_file():
        old = json.loads(args.output.read_text(encoding="utf-8"))
        results = old.get("results", [])
        completed_ids = {str(r["output_id"]) for r in results}
        print(f"Resuming: loaded {len(results)} existing CodeQL results")

    corpus_dir = args.manifest.parent
    records = manifest.get("records", [])

    # Group records by task_id to create one CodeQL database per task.
    by_task: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_task.setdefault(record["task_id"], []).append(record)

    total_tasks = len(by_task)
    tmp_root = Path(tempfile.mkdtemp(prefix="llm-lab-codeql-"))
    try:
        for task_idx, (task_id, task_records) in enumerate(by_task.items(), 1):
            task_records = [r for r in task_records if r["output_id"] not in completed_ids]
            if not task_records:
                print(f"[{task_idx}/{total_tasks}] {task_id}: all outputs already analyzed")
                continue

            expected_cwe = _cwe_from_task_id(task_id)
            source_dir = tmp_root / task_id
            source_dir.mkdir(parents=True, exist_ok=True)

            for record in task_records:
                record_path = corpus_dir / f"{record['output_id']}.json"
                code = extract_output_code(record_path)
                (source_dir / f"{record['output_id']}.py").write_text(code, encoding="utf-8")

            db_dir = tmp_root / f"{task_id}_db"
            sarif_path = tmp_root / f"{task_id}_results.sarif"

            try:
                run_codeql_database_create(source_dir, db_dir, args.codeql_exe)
                findings = run_codeql_analyze(
                    db_dir,
                    sarif_path,
                    args.codeql_exe,
                    query_suite=args.query_suite,
                )
            except RuntimeError as exc:
                print(f"[{task_idx}/{total_tasks}] {task_id}: CodeQL failed: {exc}")
                continue

            # Map findings back to output_id using the filename in the SARIF URI.
            findings_by_output: dict[str, list[str]] = {}
            for uri, cwes in findings.items():
                output_id = Path(uri).stem
                findings_by_output[output_id] = cwes

            for record in task_records:
                output_id = record["output_id"]
                result = {
                    "output_id": output_id,
                    "task_id": task_id,
                    "model_id": record["model_id"],
                    "repetition": record["repetition"],
                    "expected_cwe": expected_cwe,
                    "codeql": findings_by_output.get(output_id, []),
                }
                results.append(result)
                completed_ids.add(output_id)

            detected = sum(1 for r in results[-len(task_records):] if r["codeql"])
            print(f"[{task_idx}/{total_tasks}] {task_id}: analyzed {len(task_records)} outputs, {detected} with findings")

            if task_idx % 5 == 0:
                summary = {"total": len(results), "results": results}
                args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

            # Clean up per-task artifacts to save disk space.
            shutil.rmtree(source_dir, ignore_errors=True)
            shutil.rmtree(db_dir, ignore_errors=True)
            sarif_path.unlink(missing_ok=True)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    summary = {"total": len(results), "results": results}
    args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nCodeQL detector results written: {args.output} ({len(results)} outputs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
