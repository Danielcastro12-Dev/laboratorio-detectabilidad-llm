from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild corpus manifest from existing output files")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    records: list[dict] = []
    for path in sorted(args.output_dir.glob("*.json")):
        if path.name == "corpus_manifest.json":
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        records.append(record)

    manifest = {
        "experiment_id": "llm-detectability-corpus-v0.1",
        "expected": len(records),
        "completed": sum(1 for r in records if r.get("status") == "completed"),
        "failed": sum(1 for r in records if r.get("status") != "completed"),
        "refusals": 0,
        "records": records,
    }

    out_path = args.output_dir / "corpus_manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote manifest with {len(records)} records to {out_path}")
    print(f"Completed: {manifest['completed']}, Failed: {manifest['failed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
