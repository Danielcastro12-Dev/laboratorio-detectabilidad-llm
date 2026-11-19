"""Generate driver files that invoke generated functions with external inputs.

CodeQL's taint-tracking requires a complete data-flow path from a source to a
sink. Bare function definitions are not analyzed unless something calls them.
This module creates lightweight drivers so CodeQL can see the vulnerable path.
"""
from __future__ import annotations

import json
import re
from pathlib import Path


def extract_code_block(text: str) -> str:
    """Extract the first fenced Python code block, or return the text as-is."""
    pattern = re.compile(r"```python\n(.*?)\n```", re.DOTALL)
    match = pattern.search(text)
    if match:
        return match.group(1).strip()
    pattern_any = re.compile(r"```\n?(.*?)\n?```", re.DOTALL)
    match_any = pattern_any.search(text)
    if match_any:
        return match_any.group(1).strip()
    return text.strip()


def _parse_function_signature(code: str) -> tuple[str | None, list[str]]:
    """Return (name, parameters) of the first top-level function definition."""
    match = re.search(r"^def\s+(\w+)\s*\(([^)]*)\):", code, re.MULTILINE)
    if not match:
        return None, []
    name = match.group(1)
    params: list[str] = []
    for raw in match.group(2).split(","):
        raw = raw.strip()
        if not raw:
            continue
        # strip type annotations and default values
        param = raw.split(":")[0].split("=")[0].strip()
        if param:
            params.append(param)
    return name, params


def _make_driver(output_id: str, task_id: str, code: str) -> str:
    """Create a driver script for a single output."""
    func_name, params = _parse_function_signature(code)
    cwe_prefix = task_id.split("_")[0]  # e.g. "CWE-022"

    lines: list[str] = ["import sys", ""]

    # Import the generated module. We avoid top-level name collisions by using
    # a unique import alias.
    module_name = f"output_{output_id}"
    lines.append(f"import {module_name} as target")
    lines.append("")

    if func_name is None:
        lines.append("# No function found; cannot generate driver")
        lines.append("pass")
        return "\n".join(lines)

    # Determine argument source based on CWE / parameter list.
    if cwe_prefix in ("CWE-022", "CWE-089"):
        # Path traversal / SQL injection: first argument is user-controlled.
        args = []
        for idx, _ in enumerate(params):
            args.append(f"sys.argv[{idx + 1}] if len(sys.argv) > {idx + 1} else ''")
        call = f"target.{func_name}({', '.join(args)})"
    elif cwe_prefix == "CWE-078":
        if params:
            call = f"target.{func_name}(sys.argv[1] if len(sys.argv) > 1 else '')"
        else:
            # Function reads from input() internally; just call it.
            call = f"target.{func_name}()"
    elif cwe_prefix == "CWE-079":
        # Flask functions are hard to drive statically. Try calling directly if
        # it takes no args; otherwise pass a string argument.
        if params:
            call = f"target.{func_name}(sys.argv[1] if len(sys.argv) > 1 else '')"
        else:
            call = f"target.{func_name}()"
    elif cwe_prefix == "CWE-502":
        if params:
            call = f"target.{func_name}(sys.argv[1] if len(sys.argv) > 1 else '')"
        else:
            call = f"target.{func_name}()"
    else:
        if params:
            call = f"target.{func_name}(sys.argv[1] if len(sys.argv) > 1 else '')"
        else:
            call = f"target.{func_name}()"

    lines.append("if __name__ == '__main__':")
    lines.append(f"    {call}")
    return "\n".join(lines)


def generate_driver(record_path: Path, source_dir: Path) -> Path:
    """Write the generated module and its driver into source_dir."""
    record = json.loads(record_path.read_text(encoding="utf-8"))
    output_id = record["output_id"]
    task_id = record.get("task_id", "")
    code = extract_code_block(record.get("output", ""))

    module_name = f"output_{output_id}"
    module_path = source_dir / f"{module_name}.py"
    module_path.write_text(code, encoding="utf-8")

    driver_code = _make_driver(output_id, task_id, code)
    driver_path = source_dir / f"driver_{output_id}.py"
    driver_path.write_text(driver_code, encoding="utf-8")

    return driver_path


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate CodeQL driver files")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    with args.manifest.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir = args.manifest.parent

    for record in manifest.get("records", []):
        record_path = corpus_dir / f"{record['output_id']}.json"
        generate_driver(record_path, args.output_dir)

    print(f"Generated drivers in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
