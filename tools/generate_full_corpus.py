from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_lab.generation.generator import generate_output, load_tasks
from llm_lab.generation.openrouter_client import OpenRouterClient
from llm_lab.schemas import OutputRecord


def _build_tasks(args: argparse.Namespace) -> list[dict[str, str]]:
    tasks = load_tasks(args.tasks)
    dataset_root = Path("data/raw/CodeSecEval/data")
    for task in tasks:
        subset = task.get("subset")
        if subset == "SecEvalBase":
            task["prompt_path"] = str(dataset_root / "SecEvalBase" / "test.jsonl")
        elif subset == "SecEvalPlus":
            task["prompt_path"] = str(dataset_root / "SecEvalPlus" / "test.jsonl")
        else:
            raise ValueError(f"Unknown subset {subset!r} for task {task.get('task_id')}")
        task["prompt_line"] = task.get("line", "")
    return tasks


def _already_exists(output_dir: Path, task_id: str, model_id: str, repetition: int) -> bool:
    # Reconstruct output_id deterministically to check for existing files.
    record = OutputRecord.create(
        task_id=task_id,
        model_id=model_id,
        repetition=repetition,
        prompt="",
        output="",
        parameters={},
        finish_reason=None,
        cost_usd=None,
        status="pending",
        error=None,
    )
    return (output_dir / f"{record.output_id}.json").is_file()


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Generate full corpus outputs")
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--prompt-template", type=Path, default=Path("prompts/generation_v0.1.txt"))
    args = parser.parse_args()

    tasks = _build_tasks(args)

    import yaml  # type: ignore[import-untyped]

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

    # Load any existing manifest and scan the directory to resume gracefully.
    manifest_path = args.output_dir / "corpus_manifest.json"
    records: list[dict[str, Any]] = []
    existing_ids: set[str] = set()
    if manifest_path.is_file():
        old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        records = old_manifest.get("records", [])
        existing_ids = {r["output_id"] for r in records}
        print(f"Resuming: loaded {len(records)} existing records from {manifest_path}")

    # Always scan the directory for orphan output files and merge them into the manifest.
    for p in args.output_dir.glob("*.json"):
        if p.name == "corpus_manifest.json":
            continue
        output_id = p.stem
        if output_id not in existing_ids:
            try:
                records.append(json.loads(p.read_text(encoding="utf-8")))
                existing_ids.add(output_id)
            except (json.JSONDecodeError, OSError) as exc:
                print(f"Warning: could not read {p}: {exc}")
    print(f"Resuming: found {len(existing_ids)} existing output files")

    expected = len(tasks) * len(model_ids) * args.repetitions
    completed = sum(1 for r in records if r.get("status") == "completed")
    failed = sum(1 for r in records if r.get("status") != "completed")
    refusals = sum(1 for r in records if r.get("status") == "completed" and not r.get("output", "").strip())

    pending = 0
    for task in tasks:
        for model_id in model_ids:
            for repetition in range(1, args.repetitions + 1):
                temp_record = OutputRecord.create(
                    task_id=task["task_id"],
                    model_id=model_id,
                    repetition=repetition,
                    prompt="",
                    output="",
                    parameters={},
                    finish_reason=None,
                    cost_usd=None,
                    status="pending",
                    error=None,
                )
                if temp_record.output_id in existing_ids:
                    continue
                pending += 1
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
                # Save incremental manifest every 10 outputs for resilience.
                if (completed + failed) % 10 == 0:
                    manifest_path.write_text(
                        json.dumps(
                            {
                                "experiment_id": "llm-detectability-corpus-v0.1",
                                "expected": expected,
                                "completed": completed,
                                "failed": failed,
                                "refusals": refusals,
                                "records": records,
                            },
                            indent=2,
                            ensure_ascii=False,
                        ),
                        encoding="utf-8",
                    )

    manifest = {
        "experiment_id": "llm-detectability-corpus-v0.1",
        "expected": expected,
        "completed": completed,
        "failed": failed,
        "refusals": refusals,
        "records": records,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Expected outputs: {expected}")
    print(f"Already present: {len(existing_ids)}")
    print(f"Newly generated: {pending}")
    print(f"Completed: {completed}")
    print(f"Failed: {failed}")
    print(f"Refusals: {refusals}")
    print(f"Manifest written: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
