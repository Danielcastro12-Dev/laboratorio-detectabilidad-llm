from __future__ import annotations

import re
from pathlib import Path


def extract_code_block(text: str) -> str:
    """Extract the first fenced Python code block, or return the text as-is."""
    pattern = re.compile(r"```python\n(.*?)\n```", re.DOTALL)
    match = pattern.search(text)
    if match:
        return match.group(1).strip()
    # Try any fenced block
    pattern_any = re.compile(r"```\n?(.*?)\n?```", re.DOTALL)
    match_any = pattern_any.search(text)
    if match_any:
        return match_any.group(1).strip()
    return text.strip()


def write_extracted_code(record_path: Path, output_dir: Path) -> Path:
    text = record_path.read_text(encoding="utf-8")
    import json

    data = json.loads(text)
    code = extract_code_block(data.get("output", ""))
    out_path = output_dir / f"{data['output_id']}.py"
    out_path.write_text(code, encoding="utf-8")
    return out_path
