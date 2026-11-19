from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from llm_lab.generation.openrouter_client import (
    CompletionResponse,
    OpenRouterClient,
    OpenRouterError,
)
from llm_lab.schemas import OutputRecord


def load_tasks(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_raw_record(prompt_path: str, line: int) -> dict[str, Any]:
    path = Path(prompt_path)
    with path.open(encoding="utf-8") as handle:
        for i, raw in enumerate(handle, 1):
            if i == line:
                return json.loads(raw)
    raise ValueError(f"Line {line} not found in {path}")


def build_prompt(template: str, problem: str, entry_point: str) -> str:
    return template.format(problem=problem, entry_point=entry_point)


def generate_output(
    task: dict[str, str],
    model_id: str,
    repetition: int,
    client: OpenRouterClient,
    prompt_template: str,
    parameters: dict[str, Any],
) -> OutputRecord:
    raw = load_raw_record(task["prompt_path"], int(task["prompt_line"]))
    problem = str(raw.get("Problem", ""))
    entry_point = str(raw.get("Entry_Point", task.get("entry_point", "")))
    prompt = build_prompt(prompt_template, problem, entry_point)

    try:
        response: CompletionResponse = client.complete(
            model=model_id,
            messages=[{"role": "user", "content": prompt}],
            temperature=parameters.get("temperature", 0.2),
            top_p=parameters.get("top_p", 0.95),
            max_tokens=parameters.get("max_tokens", 8192),
            seed=parameters.get("seed"),
        )
        return OutputRecord.create(
            task_id=task["task_id"],
            model_id=model_id,
            repetition=repetition,
            prompt=prompt,
            output=response.content,
            parameters={"model": model_id, **parameters},
            finish_reason=response.finish_reason,
            cost_usd=None,
            status="completed",
            error=None,
        )
    except OpenRouterError as exc:
        return OutputRecord.create(
            task_id=task["task_id"],
            model_id=model_id,
            repetition=repetition,
            prompt=prompt,
            output="",
            parameters={"model": model_id, **parameters},
            finish_reason=None,
            cost_usd=None,
            status="api_error",
            error=str(exc),
        )
