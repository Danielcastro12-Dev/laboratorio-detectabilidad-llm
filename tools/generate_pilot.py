from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_lab.generation.generator import generate_output, load_tasks
from llm_lab.generation.openrouter_client import OpenRouterClient


def select_pilot_tasks(tasks: list[dict[str, str]]) -> list[dict[str, str]]:
    seen_cwe: set[str] = set()
    selected: list[dict[str, str]] = []
    for task in tasks:
        cwe = task["cwe"]
        if cwe not in seen_cwe:
            selected.append(task)
            seen_cwe.add(cwe)
    return selected


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Generate pilot outputs for selected tasks")
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--prompt-template", type=Path, default=Path("prompts/generation_v0.1.txt"))
    args = parser.parse_args()

    tasks = load_tasks(args.tasks)
    pilot_tasks = select_pilot_tasks(tasks)

    import yaml

    model_config = yaml.safe_load(args.models.read_text(encoding="utf-8"))
    model_ids = [m["id"] for m in model_config.get("models", []) if m.get("enabled")]

    prompt_template = args.prompt_template.read_text(encoding="utf-8")
    parameters: dict[str, Any] = {
        "temperature": args.temperature,
        "top_p": args.top_p,
        "max_tokens": args.max_tokens,
    }

    client = OpenRouterClient()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    expected = len(pilot_tasks) * len(model_ids) * args.repetitions
    completed = 0
    failed = 0
    refusals = 0

    for task in pilot_tasks:
        for model_id in model_ids:
            for repetition in range(1, args.repetitions + 1):
                record = generate_output(task, model_id, repetition, client, prompt_template, parameters)
                if record.status == "completed":
                    completed += 1
                    if record.output.strip() == "":
                        refusals += 1
                else:
                    failed += 1
                records.append(record.to_dict())
                out_path = args.output_dir / f"{record.output_id}.json"
                out_path.write_text(record.to_json(), encoding="utf-8")

    manifest = {
        "experiment_id": "llm-detectability-pilot-v0.1",
        "expected": expected,
        "completed": completed,
        "failed": failed,
        "refusals": refusals,
        "records": records,
    }
    manifest_path = args.output_dir / "pilot_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Expected outputs: {expected}")
    print(f"Completed: {completed}")
    print(f"Failed: {failed}")
    print(f"Refusals: {refusals}")
    print(f"Manifest written: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
