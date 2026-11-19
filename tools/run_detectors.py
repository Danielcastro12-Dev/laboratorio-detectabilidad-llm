from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_lab.detection.detector_runner import (
    extract_output_code,
    run_bandit,
    run_llm_auditor,
    run_semgrep,
)
from llm_lab.generation.openrouter_client import OpenRouterClient, OpenRouterError


def _cwe_from_task_id(task_id: str) -> str:
    """Derive expected CWE from the task ID prefix (e.g. CWE-022_author_1.py -> CWE-22)."""
    if task_id.startswith("CWE-"):
        # Normalize three-digit prefixes like CWE-022 to CWE-22
        part = task_id.split("_")[0]
        num = part.split("-")[1].lstrip("0") or "0"
        return f"CWE-{num}"
    return ""


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run detectors over generated corpus outputs")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("data/derived/detector_results.json"))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--codeql-exe", type=Path, default=None)
    parser.add_argument("--skip-llm", action="store_true")
    parser.add_argument("--skip-codeql", action="store_true")
    args = parser.parse_args()

    with args.manifest.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    tasks: dict[str, dict[str, str]] = {}
    with args.tasks.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            tasks[row["task_id"]] = row

    client = OpenRouterClient()

    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    completed_ids: set[str] = set()
    if args.output.is_file():
        old = json.loads(args.output.read_text(encoding="utf-8"))
        results = old.get("results", [])
        completed_ids = {str(r["output_id"]) for r in results}
        print(f"Resuming: loaded {len(results)} existing detector results")

    corpus_dir = args.manifest.parent
    records = manifest.get("records", [])
    if args.limit:
        records = records[: args.limit]

    total = len(records)
    tmp_root = Path(tempfile.mkdtemp(prefix="llm-lab-detectors-"))
    try:
        for idx, record in enumerate(records, 1):
            output_id = record["output_id"]
            if output_id in completed_ids:
                continue

            task_id = record["task_id"]
            expected_cwe = _cwe_from_task_id(task_id)
            record_path = corpus_dir / f"{output_id}.json"
            code = extract_output_code(record_path)
            code_path = tmp_root / f"{output_id}.py"
            code_path.write_text(code, encoding="utf-8")

            semgrep_findings: list[str] = []
            bandit_findings: list[str] = []
            llm_result: dict[str, Any] = {"detected": None, "reason": "", "tokens": None}

            try:
                semgrep_findings = run_semgrep(code_path)
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                print(f"[{idx}/{total}] semgrep error for {output_id}: {exc}")

            try:
                bandit_findings = run_bandit(code_path)
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                print(f"[{idx}/{total}] bandit error for {output_id}: {exc}")

            if not args.skip_llm and expected_cwe:
                try:
                    llm_result = run_llm_auditor(code, expected_cwe, client)
                except (OpenRouterError, OSError) as exc:
                    print(f"[{idx}/{total}] llm auditor error for {output_id}: {exc}")
                    llm_result = {"detected": None, "reason": str(exc), "tokens": None}

            result = {
                "output_id": output_id,
                "task_id": task_id,
                "model_id": record["model_id"],
                "repetition": record["repetition"],
                "expected_cwe": expected_cwe,
                "semgrep": semgrep_findings,
                "bandit": bandit_findings,
                "llm_auditor": llm_result,
            }
            results.append(result)
            completed_ids.add(output_id)
            print(
                f"[{idx}/{total}] {record['model_id']} {task_id} "
                f"semgrep={semgrep_findings} bandit={bandit_findings} "
                f"llm={llm_result.get('detected')}"
            )

            if len(results) % 10 == 0:
                summary = {
                    "total": len(results),
                    "results": results,
                }
                args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    summary = {
        "total": len(results),
        "results": results,
    }
    args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nDetector results written: {args.output} ({len(results)} outputs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
