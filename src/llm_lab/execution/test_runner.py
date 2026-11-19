from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from llm_lab.execution.code_extract import extract_code_block
from llm_lab.execution.sandbox_runner import run_in_sandbox


def _hash_file(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_functional_test(
    record_path: Path,
    dataset_record: dict[str, Any],
    timeout_seconds: int = 5,
) -> dict[str, Any]:
    """Run the generated code against the dataset's canonical test in the sandbox."""
    output_dir = Path(tempfile.mkdtemp(prefix="llm-lab-test-"))
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
        code = extract_code_block(record.get("output", ""))
        code_path = output_dir / "candidate.py"
        code_path.write_text(code, encoding="utf-8")

        test_code = str(dataset_record.get("Test", ""))
        test_path = output_dir / "test_suite.py"
        test_path.write_text(test_code, encoding="utf-8")

        entry_point = str(dataset_record.get("entry_point", "")).strip()
        if not entry_point:
            return {
                "output_id": record["output_id"],
                "task_id": record["task_id"],
                "model_id": record["model_id"],
                "return_code": None,
                "timed_out": False,
                "duration_ms": 0,
                "stdout": "",
                "stderr": "missing entry_point in dataset record",
                "status": "inconclusive",
            }

        wrapper = output_dir / "runner.py"
        wrapper.write_text(
            "import sys\n"
            "import importlib.util\n"
            "sys.path.insert(0, '/workspace/output')\n"
            "# Load candidate as a module so names live in module namespace\n"
            "spec = importlib.util.spec_from_file_location('candidate', '/workspace/output/candidate.py')\n"
            "candidate_mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(candidate_mod)\n"
            "# Load test suite into the same module namespace so check() is available\n"
            "with open('/workspace/output/test_suite.py') as _f:\n"
            "    exec(_f.read(), candidate_mod.__dict__)\n"
            "entry_point = open('/workspace/output/entry_point.txt').read().strip()\n"
            "candidate_fn = getattr(candidate_mod, entry_point)\n"
            "candidate_mod.check(candidate_fn)\n",
            encoding="utf-8",
        )

        extra_files = {
            "candidate.py": code,
            "test_suite.py": test_code,
            "entry_point.txt": entry_point,
        }
        result = run_in_sandbox(wrapper, timeout_seconds=timeout_seconds, extra_files=extra_files)
        status = "functional" if result.return_code == 0 else "non_functional"
        if result.timed_out:
            status = "timeout"

        return {
            "output_id": record["output_id"],
            "task_id": record["task_id"],
            "model_id": record["model_id"],
            "return_code": result.return_code,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "status": status,
        }
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
