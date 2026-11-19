from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import httpx


class OpenRouterError(Exception):
    """Base error for OpenRouter client failures."""


@dataclass(frozen=True)
class CompletionResponse:
    content: str
    total_tokens: int | None
    finish_reason: str | None
    raw_response: dict[str, Any]


class OpenRouterClient:
    """Minimal OpenRouter client with retries and no secret logging."""

    BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = BASE_URL,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                base_url=self._base_url,
                timeout=timeout_seconds,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://localhost",
                    "X-Title": "LLM Detectability Lab",
                },
            )
            self._owns_client = True

    def complete(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        top_p: float = 0.95,
        max_tokens: int = 4096,
        seed: int | None = None,
    ) -> CompletionResponse:
        if not self._api_key:
            raise OpenRouterError("API key is required")

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
        }
        if seed is not None:
            payload["seed"] = seed

        last_error: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                response = self._client.post(
                    "/chat/completions",
                    json=payload,
                )
                if response.status_code == 429 and attempt < self._max_retries:
                    continue
                response.raise_for_status()
                try:
                    data = response.json()
                except json.JSONDecodeError as exc:
                    raise OpenRouterError(f"Invalid JSON response: {exc}") from exc
                choice = data.get("choices", [{}])[0]
                message = choice.get("message", {}) if isinstance(choice, dict) else {}
                return CompletionResponse(
                    content=str(message.get("content", "")),
                    total_tokens=data.get("usage", {}).get("total_tokens"),
                    finish_reason=choice.get("finish_reason") if isinstance(choice, dict) else None,
                    raw_response=data,
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                if attempt < self._max_retries:
                    continue
                raise OpenRouterError(f"Request failed after {attempt} attempts: timeout/network") from exc
            except httpx.HTTPStatusError as exc:
                raise OpenRouterError(f"HTTP {exc.response.status_code}: {exc.response.text}") from exc

        raise OpenRouterError(f"Request failed after {self._max_retries} attempts: {last_error}")
