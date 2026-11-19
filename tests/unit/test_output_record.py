from __future__ import annotations

import json

from llm_lab.schemas import OutputRecord


def test_hash_is_stable() -> None:
    record = OutputRecord.create(
        task_id="task-1",
        model_id="model-a",
        repetition=1,
        prompt="prompt text",
        output="output text",
        parameters={"temperature": 0.2},
        finish_reason="stop",
        cost_usd=0.001,
        status="completed",
        error=None,
    )
    assert record.prompt_hash == OutputRecord._hash("prompt text")
    assert record.output_hash == OutputRecord._hash("output text")


def test_output_id_is_unique() -> None:
    a = OutputRecord.create(
        task_id="task-1",
        model_id="model-a",
        repetition=1,
        prompt="x",
        output="y",
        parameters={},
        finish_reason=None,
        cost_usd=None,
        status="completed",
        error=None,
    )
    import time

    time.sleep(0.01)
    b = OutputRecord.create(
        task_id="task-1",
        model_id="model-a",
        repetition=1,
        prompt="x",
        output="y",
        parameters={},
        finish_reason=None,
        cost_usd=None,
        status="completed",
        error=None,
    )
    assert a.output_id != b.output_id


def test_empty_output_is_preserved() -> None:
    record = OutputRecord.create(
        task_id="task-1",
        model_id="model-a",
        repetition=1,
        prompt="x",
        output="",
        parameters={},
        finish_reason=None,
        cost_usd=None,
        status="empty",
        error=None,
    )
    assert record.output == ""
    assert record.output_hash == OutputRecord._hash("")


def test_timestamp_is_utc() -> None:
    record = OutputRecord.create(
        task_id="task-1",
        model_id="model-a",
        repetition=1,
        prompt="x",
        output="y",
        parameters={},
        finish_reason=None,
        cost_usd=None,
        status="completed",
        error=None,
    )
    assert record.timestamp_utc.endswith("Z")


def test_error_is_separate_from_output() -> None:
    record = OutputRecord.create(
        task_id="task-1",
        model_id="model-a",
        repetition=1,
        prompt="x",
        output="",
        parameters={},
        finish_reason=None,
        cost_usd=None,
        status="failed",
        error="timeout",
    )
    data = json.loads(record.to_json())
    assert data["status"] == "failed"
    assert data["error"] == "timeout"
    assert data["output"] == ""
