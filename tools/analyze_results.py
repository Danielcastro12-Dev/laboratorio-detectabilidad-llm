from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_detector_results(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)["results"]


def load_codeql_results(path: Path) -> dict[str, list[dict[str, Any]]]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict) and "results" in payload:
        return {r["output_id"]: r.get("codeql", []) for r in payload["results"]}
    return payload


def cwe_from_task_id(task_id: str, tasks: dict[str, dict[str, str]]) -> str:
    return tasks.get(task_id, {}).get("cwe", "UNKNOWN")


def semgrep_detected(result: dict[str, Any], expected_cwe: str) -> bool:
    expected_id = expected_cwe.replace("CWE-", "")
    for finding in result.get("semgrep", []):
        text = str(finding)
        if f"CWE-{expected_id}" in text or f"CWE-{expected_id.zfill(3)}" in text:
            return True
    return False


def bandit_detected(result: dict[str, Any], expected_cwe: str) -> bool:
    expected_id = expected_cwe.replace("CWE-", "")
    for finding in result.get("bandit", []):
        text = str(finding)
        if f"CWE-{expected_id}" in text or f"CWE-{expected_id.zfill(3)}" in text:
            return True
    return False


def llm_detected(result: dict[str, Any]) -> bool:
    return result.get("llm_auditor", {}).get("detected") is True


def codeql_detected(output_id: str, codeql: dict[str, list[dict[str, Any]]]) -> bool:
    findings = codeql.get(output_id, [])
    return len(findings) > 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Consolidate detector results.")
    parser.add_argument("--detector-results", type=Path, required=True)
    parser.add_argument("--codeql-results", type=Path, required=True)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--functional", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    tasks: dict[str, dict[str, str]] = {}
    with args.tasks.open(encoding="utf-8") as handle:
        for task_row in csv.DictReader(handle):
            tasks[task_row["task_id"]] = task_row

    detector_results = load_detector_results(args.detector_results)
    codeql_results = load_codeql_results(args.codeql_results)

    functional: dict[str, str] = {}
    with args.functional.open(encoding="utf-8") as handle:
        for func_row in json.load(handle)["results"]:
            functional[func_row["output_id"]] = func_row.get("status", "unknown")

    matrix: dict[str, dict[str, dict[str, list[bool]]]] = defaultdict(
        lambda: defaultdict(lambda: {"semgrep": [], "bandit": [], "llm": [], "codeql": []})
    )

    for result in detector_results:
        model_id = result["model_id"]
        output_id = result["output_id"]
        expected_cwe = result["expected_cwe"]

        matrix[model_id][expected_cwe]["semgrep"].append(
            semgrep_detected(result, expected_cwe)
        )
        matrix[model_id][expected_cwe]["bandit"].append(
            bandit_detected(result, expected_cwe)
        )
        matrix[model_id][expected_cwe]["llm"].append(llm_detected(result))
        matrix[model_id][expected_cwe]["codeql"].append(
            codeql_detected(output_id, codeql_results)
        )

    summary: list[dict[str, Any]] = []
    for model_id, cwes in sorted(matrix.items()):
        for cwe, detectors in sorted(cwes.items()):
            row: dict[str, Any] = {"model": model_id, "cwe": cwe}
            for detector_name, values in detectors.items():
                total = len(values)
                detected = sum(values)
                row[f"{detector_name}_detected"] = detected
                row[f"{detector_name}_total"] = total
                row[f"{detector_name}_recall"] = round(detected / total, 4) if total else 0.0
            summary.append(row)

    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(
            {"summary": summary, "models": sorted(matrix.keys()), "cwes": sorted({r["cwe"] for r in summary})},
            handle,
            indent=2,
        )

    print(f"Analysis written to {args.output}")
    print(f"Rows: {len(summary)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
