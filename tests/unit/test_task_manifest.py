import csv
from pathlib import Path


def test_selection_has_five_tasks_per_cwe() -> None:
    path = Path("data/manifests/task_selection_v0.1.csv")
    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    cwe_counts: dict[str, int] = {}
    for row in rows:
        cwe_counts[row["cwe"]] = cwe_counts.get(row["cwe"], 0) + 1
    assert cwe_counts == {
        "CWE-22": 5,
        "CWE-78": 5,
        "CWE-79": 5,
        "CWE-89": 5,
        "CWE-502": 5,
    }


def test_manifest_has_required_columns() -> None:
    required = {
        "task_id",
        "cwe",
        "source_dataset",
        "source_version",
        "language",
        "prompt_path",
        "prompt_line",
    }
    with Path("data/manifests/tasks_v0.1.csv").open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert required.issubset(set(reader.fieldnames or []))
        rows = list(reader)
    assert len(rows) == 25
    task_ids = {row["task_id"] for row in rows}
    assert len(task_ids) == 25
    assert all(row["source_dataset"] == "CodeSecEval" for row in rows)


def test_source_lines_point_to_existing_records() -> None:
    with Path("data/manifests/tasks_v0.1.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        prompt_path = Path(row["prompt_path"])
        line = int(row["prompt_line"])
        assert prompt_path.exists(), f"Missing {prompt_path}"
        lines = prompt_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) >= line
