from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from llm_lab.execution.code_extract import extract_code_block
from llm_lab.generation.openrouter_client import CompletionResponse, OpenRouterClient


def _write_code_to_temp(code: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="llm-lab-det-"))
    path = tmp / "candidate.py"
    path.write_text(code, encoding="utf-8")
    return path


def _extract_cwe_ids(items: list[str]) -> set[str]:
    cwes: set[str] = set()
    for item in items:
        for match in re.finditer(r"CWE-?(\d+)", str(item)):
            cwes.add(f"CWE-{match.group(1)}")
    return cwes


def run_semgrep(code_path: Path, configs: list[str] | None = None) -> list[str]:
    """Run Semgrep on a single file and return detected CWE IDs."""
    configs = configs or ["p/python"]
    cmd = ["semgrep", "--metrics=off", "--json", "--quiet"]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    cmd.append(str(code_path))
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed: {proc.stderr[:500]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid semgrep json: {exc}") from exc
    cwes: set[str] = set()
    for result in data.get("results", []):
        metadata = result.get("extra", {}).get("metadata", {})
        cwes.update(_extract_cwe_ids(metadata.get("cwe", [])))
    return sorted(cwes)


def run_bandit(code_path: Path) -> list[str]:
    """Run Bandit on a single file and return detected CWE IDs."""
    cmd = ["bandit", "-f", "json", "-q", str(code_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid bandit json: {exc}") from exc
    cwes: set[str] = set()
    for result in data.get("results", []):
        cwe = result.get("issue_cwe", {})
        if cwe and "id" in cwe:
            cwes.add(f"CWE-{cwe['id']}")
    return sorted(cwes)


def run_llm_auditor(
    code: str,
    expected_cwe: str,
    client: OpenRouterClient,
    model: str = "nvidia/nemotron-3-ultra-550b-a55b:free",
) -> dict[str, Any]:
    """Ask the LLM auditor whether the code contains the expected CWE."""
    prompt = (
        f"You are a security auditor analyzing Python code for {expected_cwe}. "
        "Answer only YES if the code contains this vulnerability, or NO if it does not. "
        "Then provide a one-line reason on the same line.\n\n"
        f"```python\n{code}\n```"
    )
    response: CompletionResponse = client.complete(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=256,
    )
    text = response.content.strip()
    detected = text.upper().startswith("YES")
    return {
        "detected": detected,
        "reason": text,
        "finish_reason": response.finish_reason,
        "tokens": response.total_tokens,
    }


def run_codeql_database_create(source_dir: Path, database_dir: Path, codeql_exe: Path) -> None:
    """Create a CodeQL database for Python source files in source_dir."""
    if database_dir.exists():
        shutil.rmtree(database_dir)
    cmd = [
        str(codeql_exe),
        "database",
        "create",
        str(database_dir),
        "--language=python",
        f"--source-root={source_dir.as_posix()}",
        "--overwrite",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"codeql database create failed: {proc.stderr[:1000]}")


def run_codeql_analyze(
    database_dir: Path,
    output_sarif: Path,
    codeql_exe: Path,
    query_suite: str = "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
) -> dict[str, Any]:
    """Analyze a CodeQL database and return parsed SARIF results."""
    cmd = [
        str(codeql_exe),
        "database",
        "analyze",
        str(database_dir),
        query_suite,
        "--format=sarifv2.1.0",
        f"--output={output_sarif.as_posix()}",
        "--sarif-add-snippets=false",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"codeql analyze failed: {proc.stderr[:1000]}")
    return parse_sarif_cwes(output_sarif)


def parse_sarif_cwes(sarif_path: Path) -> dict[str, list[str]]:
    """Parse SARIF and map rule IDs to CWEs per file."""
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    rules: dict[str, dict[str, Any]] = {}
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        for rule in tool.get("rules", []):
            rid = rule.get("id", "")
            cwes: list[str] = []
            for tag in rule.get("properties", {}).get("tags", []):
                m = re.search(r"CWE-?(\d+)", str(tag))
                if m:
                    cwes.append(f"CWE-{m.group(1)}")
            rules[rid] = {"cwes": cwes, "name": rule.get("name", "")}

    findings: dict[str, list[str]] = {}
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rid = result.get("ruleId", "")
            cwes = rules.get(rid, {}).get("cwes", [])
            for loc in result.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                if uri not in findings:
                    findings[uri] = []
                findings[uri].extend(cwes)
    return {uri: sorted(set(cwes)) for uri, cwes in findings.items()}


def extract_output_code(record_path: Path) -> str:
    record = json.loads(record_path.read_text(encoding="utf-8"))
    return extract_code_block(record.get("output", ""))
