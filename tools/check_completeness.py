from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Check completeness of a generation manifest")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected", type=int, required=True)
    args = parser.parse_args()

    with args.manifest.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    expected = args.expected
    completed = manifest.get("completed", 0)
    failed = manifest.get("failed", 0)
    refusals = manifest.get("refusals", 0)
    total = len(manifest.get("records", []))

    if total != expected:
        print(f"FAIL: expected {expected} records, found {total}")
        return 1
    if completed + failed + refusals != expected:
        print(f"FAIL: completed({completed}) + failed({failed}) + refusals({refusals}) != expected({expected})")
        return 1

    print(f"Completeness check passed: {completed}/{expected} completed, {failed} failed, {refusals} refusals")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
