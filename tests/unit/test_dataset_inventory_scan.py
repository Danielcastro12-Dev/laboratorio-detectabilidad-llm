import json
from pathlib import Path

from llm_lab.dataset_inventory import scan_dataset


def test_scan_dataset_reads_jsonl_task_fields(tmp_path: Path) -> None:
    dataset = tmp_path / "data" / "test.jsonl"
    dataset.parent.mkdir()
    row = {
        "ID": "CWE-78_demo",
        "Problem": "Return input",
        "Insecure Code": "def f(x): return x",
        "Secure Code": "def f(x): return x",
        "Test": "def check(candidate): assert candidate('x') == 'x'",
        "Test-FP": "def check(candidate): assert candidate('x') == 'x'",
        "Test-SP": "def check(candidate): assert candidate('x') == 'x'",
        "Entry_Point": "f",
    }
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")

    rows = scan_dataset(tmp_path)

    assert rows == [
        {
            "subset": "data",
            "line": "1",
            "task_id": "CWE-78_demo",
            "cwe": "CWE-78",
            "language": "python",
            "has_tests": "true",
        }
    ]
