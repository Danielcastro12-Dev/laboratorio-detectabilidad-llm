from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from llm_lab.detection.detector_runner import (  # type: ignore[import-untyped]
    extract_output_code,
)

CORPUS_DIR = Path("data/raw/corpus_v0.1")
MANIFEST = CORPUS_DIR / "corpus_manifest.json"
FUNCTIONAL = Path("data/derived/corpus_functional_results.json")
DETECTORS = Path("data/derived/detector_results.json")
TASKS = Path("data/manifests/task_selection_v0.1.csv")
QUEUE = Path("data/adjudicated/review_queue_full_v0.6.jsonl")
KEY = Path("data/adjudicated/review_queue_full_v0.6_key.json")


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    records = manifest["records"]

    # Map functional results by logical key
    disk_key: dict[str, tuple[str, str, int]] = {}
    for path in CORPUS_DIR.glob("*.json"):
        if path.name == "corpus_manifest.json":
            continue
        rec_disk = json.loads(path.read_text(encoding="utf-8"))
        disk_key[rec_disk["output_id"]] = (
            rec_disk["task_id"],
            rec_disk["model_id"],
            int(rec_disk["repetition"]),
        )
    status_by_key: dict[tuple[str, str, int], str] = {}
    for res in json.loads(FUNCTIONAL.read_text(encoding="utf-8"))["results"]:
        key = disk_key.get(res["output_id"])
        if key is not None:
            status_by_key[key] = res["status"]
    func: dict[str, str] = {}
    for rec in records:
        lkey = (rec["task_id"], rec["model_id"], int(rec["repetition"]))
        func[rec["output_id"]] = status_by_key.get(lkey, "unknown")

    det = {r["output_id"]: r for r in json.loads(DETECTORS.read_text(encoding="utf-8"))["results"]}
    cwe_of: dict[str, str] = {}
    with TASKS.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            cwe_of[row["task_id"]] = row["cwe"]

    QUEUE.parent.mkdir(parents=True, exist_ok=True)
    key_map: dict[str, dict] = {}
    with QUEUE.open("w", encoding="utf-8") as qh:
        for idx, r in enumerate(records, start=1):
            review_id = f"R{idx:03d}"
            code = extract_output_code(CORPUS_DIR / f"{r['output_id']}.json")
            cwe = cwe_of.get(r["task_id"], "UNKNOWN")
            item = {
                "review_id": review_id,
                "cwe_target": cwe,
                "functional_status": func[r["output_id"]],
                "code": code,
                "code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            }
            qh.write(json.dumps(item, ensure_ascii=False) + "\n")
            key_map[review_id] = {
                "output_id": r["output_id"],
                "model_id": r["model_id"],
                "task_id": r["task_id"],
                "repetition": r["repetition"],
                "stratum": "functional" if func[r["output_id"]] == "functional" else "non_functional",
                "detector_semgrep": det[r["output_id"]].get("semgrep", []),
                "detector_bandit": det[r["output_id"]].get("bandit", []),
                "detector_llm": det[r["output_id"]].get("llm_auditor", {}).get("detected"),
            }
    KEY.write_text(json.dumps(key_map, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"queue items: {len(records)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
