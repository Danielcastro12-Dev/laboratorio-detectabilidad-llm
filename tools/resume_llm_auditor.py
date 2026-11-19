from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_lab.detection.detector_runner import extract_output_code, run_llm_auditor
from llm_lab.generation.openrouter_client import OpenRouterClient, OpenRouterError


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Resume LLM auditor over missing detector results")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--detector-results", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--model", type=str, default="nvidia/nemotron-3-ultra-550b-a55b:free")
    args = parser.parse_args()

    output_path = args.output or args.detector_results

    with args.manifest.open(encoding="utf-8") as handle:
        json.load(handle)

    tasks: dict[str, dict[str, str]] = {}
    with args.tasks.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            tasks[row["task_id"]] = row

    corpus_dir = args.manifest.parent

    data = json.loads(args.detector_results.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = data.get("results", [])

    client = OpenRouterClient()

    total_missing = sum(1 for r in results if r.get("llm_auditor", {}).get("detected") is None)
    print(f"Resuming LLM auditor: {total_missing} outputs missing")

    processed = 0
    for idx, result in enumerate(results, 1):
        if result.get("llm_auditor", {}).get("detected") is not None:
            continue

        task_id = result["task_id"]
        expected_cwe = result["expected_cwe"]
        output_id = result["output_id"]
        record_path = corpus_dir / f"{output_id}.json"
        code = extract_output_code(record_path)

        try:
            llm_result = run_llm_auditor(code, expected_cwe, client, model=args.model)
        except (RuntimeError, OpenRouterError) as exc:
            print(f"[{idx}/{len(results)}] llm auditor error for {output_id}: {exc}")
            llm_result = {"detected": None, "reason": str(exc), "tokens": None}
            # Stop on rate limit to allow future resume
            if "429" in str(exc) or "Rate limit" in str(exc):
                print("Rate limit hit. Stopping to resume later.")
                break

        result["llm_auditor"] = llm_result
        processed += 1
        print(f"[{idx}/{len(results)}] {result['model_id']} {task_id} llm={llm_result.get('detected')}")

        if processed % 5 == 0:
            output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nLLM auditor resumed: {processed} outputs processed. Results written: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
