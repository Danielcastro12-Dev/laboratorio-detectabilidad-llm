from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class OutputRecord:
    output_id: str
    task_id: str
    model_id: str
    repetition: int
    prompt: str
    prompt_hash: str
    output: str
    output_hash: str
    parameters: dict[str, Any]
    timestamp_utc: str
    finish_reason: str | None
    cost_usd: float | None
    status: str
    error: str | None

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        task_id: str,
        model_id: str,
        repetition: int,
        prompt: str,
        output: str,
        parameters: dict[str, Any],
        finish_reason: str | None,
        cost_usd: float | None,
        status: str,
        error: str | None,
    ) -> OutputRecord:
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        output_id = f"{task_id}__{model_id.replace('/', '__')}__r{repetition}__{timestamp}"
        output_id = hashlib.sha256(output_id.encode("utf-8")).hexdigest()[:24]
        return cls(
            output_id=output_id,
            task_id=task_id,
            model_id=model_id,
            repetition=repetition,
            prompt=prompt,
            prompt_hash=cls._hash(prompt),
            output=output,
            output_hash=cls._hash(output),
            parameters=parameters,
            timestamp_utc=timestamp,
            finish_reason=finish_reason,
            cost_usd=cost_usd,
            status=status,
            error=error,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
