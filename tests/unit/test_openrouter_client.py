from __future__ import annotations

import httpx
import pytest

from llm_lab.generation.openrouter_client import OpenRouterClient, OpenRouterError


def _mock_handler(request: httpx.Request) -> httpx.Response:
    if "no-key" in str(request.url):
        return httpx.Response(401, json={"error": {"message": "No auth"}})
    if "bad-json" in str(request.url):
        return httpx.Response(200, text="not json")
    if "timeout" in str(request.url):
        raise httpx.TimeoutException("timeout")
    if request.headers.get("authorization") != "Bearer valid-key":
        return httpx.Response(401, json={"error": {"message": "bad key"}})
    body = {"choices": [{"message": {"content": "OK"}}], "usage": {"total_tokens": 10}}
    return httpx.Response(200, json=body)


def _client(transport: httpx.MockTransport, base_url: str = "https://openrouter.ai/api/v1") -> OpenRouterClient:
    http_client = httpx.Client(base_url=base_url, transport=transport)
    http_client.headers["Authorization"] = "Bearer valid-key"
    return OpenRouterClient(
        api_key="valid-key",
        http_client=http_client,
    )


def test_valid_response_is_parsed() -> None:
    transport = httpx.MockTransport(_mock_handler)
    client = _client(transport)
    response = client.complete("model-x", [{"role": "user", "content": "hi"}])
    assert response.content == "OK"
    assert response.total_tokens == 10


def test_missing_api_key_raises() -> None:
    transport = httpx.MockTransport(_mock_handler)
    client = OpenRouterClient(api_key="", http_client=httpx.Client(base_url="https://openrouter.ai/api/v1", transport=transport))
    with pytest.raises(OpenRouterError, match="API key"):
        client.complete("model-x", [{"role": "user", "content": "hi"}])


def test_malformed_json_raises() -> None:
    transport = httpx.MockTransport(_mock_handler)
    client = _client(transport, base_url="https://bad-json")
    with pytest.raises(OpenRouterError, match="JSON"):
        client.complete("model-x", [{"role": "user", "content": "hi"}])


def test_timeout_is_caught() -> None:
    transport = httpx.MockTransport(_mock_handler)
    client = _client(transport, base_url="https://timeout")
    with pytest.raises(OpenRouterError, match="timeout"):
        client.complete("model-x", [{"role": "user", "content": "hi"}])


def test_empty_content_is_preserved() -> None:
    transport = httpx.MockTransport(_mock_handler)
    client = _client(transport)
    response = client.complete("model-x", [{"role": "user", "content": ""}])
    assert response.content == "OK"
