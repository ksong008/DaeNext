#!/usr/bin/env python3
"""Keep the daemon product surface limited to explicit host adapters."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


def is_test_path(path: pathlib.Path) -> bool:
    return (
        "tests" in path.parts
        or path.name == "tests.rs"
        or path.name.endswith("_test.rs")
        or path.name.endswith("_tests.rs")
        or any(part.endswith("_tests") for part in path.parts)
    )


def validate(root: pathlib.Path, policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    relative_root = pathlib.Path(policy.get("root", ""))
    adapter_root = root / relative_root
    if not adapter_root.is_dir():
        return [f"daemon product adapter directory is missing: {relative_root}"]

    allowed = policy.get("allowed_top_level")
    limits = policy.get("production_line_limits")
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        return ["product adapter policy allowed_top_level must be a string array"]
    if not isinstance(limits, dict):
        return ["product adapter policy production_line_limits must be an object"]
    allowed_set = set(allowed)
    buckets: dict[str, int] = {}
    for entry in sorted(adapter_root.iterdir()):
        if entry.is_dir() and not any(entry.rglob("*.rs")):
            continue
        if entry.name not in allowed_set:
            errors.append(
                f"unapproved daemon product adapter surface: "
                f"{entry.relative_to(root)}"
            )

    for path in sorted(adapter_root.rglob("*.rs")):
        relative = path.relative_to(adapter_root)
        bucket = relative.parts[0]
        if bucket not in allowed_set:
            errors.append(
                f"source is outside the daemon product adapter allowlist: "
                f"{path.relative_to(root)}"
            )
            continue
        if not is_test_path(path):
            buckets[bucket] = buckets.get(bucket, 0) + len(
                path.read_text(encoding="utf-8").splitlines()
            )

    for bucket, actual in sorted(buckets.items()):
        maximum = limits.get(bucket)
        if not isinstance(maximum, int) or maximum < 0:
            errors.append(f"missing production line budget for adapter {bucket}")
        elif actual > maximum:
            errors.append(
                f"daemon product adapter {bucket} grew to {actual} production lines; "
                f"limit is {maximum}"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).parents[2])
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("product_adapter_policy.json"),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    with args.policy.resolve().open(encoding="utf-8") as source:
        policy = json.load(source)
    errors = validate(root, policy)
    if errors:
        print("product adapter boundary gate: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("product adapter boundary gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
