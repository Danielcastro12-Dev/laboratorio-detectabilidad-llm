from __future__ import annotations

from llm_lab.execution.code_extract import extract_code_block


def test_extracts_python_block() -> None:
    text = "```python\ndef f():\n    pass\n```"
    assert extract_code_block(text) == "def f():\n    pass"


def test_extracts_any_block_when_no_language() -> None:
    text = "```\ndef f():\n    pass\n```"
    assert extract_code_block(text) == "def f():\n    pass"


def test_returns_plain_text_when_no_block() -> None:
    text = "def f():\n    pass"
    assert extract_code_block(text) == "def f():\n    pass"


def test_strips_whitespace() -> None:
    text = "```python\n\ndef f():\n    pass\n\n```"
    assert extract_code_block(text) == "def f():\n    pass"
