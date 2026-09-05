#!/usr/bin/env python3
"""Bound non-test-named Rust LOC (including inline tests, comments and blanks).

The legacy 'production' field retains its v1 meaning. Subtree budgets overlap
package budgets and are checked independently, never added to a grand total.
"""

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


def line_counts(source_root: pathlib.Path) -> tuple[int, int]:
    production = 0
    tests = 0
    for path in sorted(source_root.rglob("*.rs")):
        lines = len(path.read_text(encoding="utf-8").splitlines())
        if is_test_path(path):
            tests += lines
        else:
            production += lines
    return production, tests


def validate(root: pathlib.Path, policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    packages = policy.get("packages")
    if not isinstance(packages, dict):
        return ["source boundary policy packages must be an object"]
    for package, limits in sorted(packages.items()):
        if not isinstance(limits, dict):
            errors.append(f"{package}: source boundary limits must be an object")
            continue
        source_root = root / "crates" / package / "src"
        if not source_root.is_dir():
            errors.append(f"{package}: source directory is missing")
            continue
        production, tests = line_counts(source_root)
        for kind, actual in (("production", production), ("tests", tests)):
            maximum = limits.get(kind)
            if not isinstance(maximum, int) or maximum < 0:
                errors.append(f"{package}: {kind} limit must be a non-negative integer")
            elif actual > maximum:
                errors.append(
                    f"{package}: {kind} source boundary grew to {actual} lines; "
                    f"limit is {maximum}"
                )
    subtrees = policy.get("subtrees", {})
    if not isinstance(subtrees, dict):
        return errors + ["source boundary policy subtrees must be an object"]
    for relative, limits in sorted(subtrees.items()):
        path = pathlib.Path(relative)
        if path.is_absolute() or ".." in path.parts or not relative.startswith("crates/"):
            errors.append(f"{relative}: subtree must be a repository-relative crates path")
            continue
        source_root = root / path
        if not source_root.is_dir():
            errors.append(f"{relative}: subtree source directory is missing")
            continue
        if not isinstance(limits, dict):
            errors.append(f"{relative}: subtree limits must be an object")
            continue
        for kind, actual in zip(("production", "tests"), line_counts(source_root)):
            maximum = limits.get(kind)
            if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
                errors.append(f"{relative}: {kind} limit must be a non-negative integer")
            elif actual > maximum:
                errors.append(f"{relative}: {kind} source boundary grew to {actual} lines; limit is {maximum}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).parents[2])
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("source_boundary_policy.json"),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    with args.policy.resolve().open(encoding="utf-8") as source:
        policy = json.load(source)
    errors = validate(root, policy)
    if errors:
        print("source boundary gate: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"source boundary gate: PASS ({len(policy['packages'])} packages, {len(policy.get('subtrees', {}))} overlapping subtrees; non-test-named LOC, not release feature evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
