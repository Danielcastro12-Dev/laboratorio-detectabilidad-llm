from pathlib import Path


def test_dataset_inventory_has_required_columns(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.csv"
    inventory.write_text(
        "task_id,cwe,language,has_tests\n"
        "task-1,CWE-78,python,true\n",
        encoding="utf-8",
    )

    from llm_lab.dataset_inventory import load_inventory

    rows = load_inventory(inventory)
    assert rows[0]["task_id"] == "task-1"
    assert rows[0]["language"] == "python"
