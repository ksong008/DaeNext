#!/usr/bin/env python3
"""Require resident generation write coordination to use the core contract."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


DECLARATION = re.compile(
    r"\b(?:struct|enum|type)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
IMPLEMENTATION = re.compile(
    r"\bimpl(?:\s*<[^>{}]*>)?\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+for\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\b"
)


def is_guard_name(name: str) -> bool:
    lowered = name.lower()
    return any(
        marker in lowered
        for marker in (
            "generationfence",
            "generationgate",
            "generationguard",
            "fencegeneration",
            "gategeneration",
            "guardgeneration",
        )
    )


def is_test_path(path: pathlib.Path) -> bool:
    return (
        "tests" in path.parts
        or path.name == "tests.rs"
        or path.name.endswith("_test.rs")
        or path.name.endswith("_tests.rs")
        or any(part.endswith("_tests") for part in path.parts)
    )


def validate(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    crates_root = root / "crates"
    for crate_root in sorted(crates_root.glob("dae-resident-*/src")):
        if crate_root.parent.name == "dae-resident-core":
            continue
        for path in sorted(crate_root.rglob("*.rs")):
            if is_test_path(path):
                continue
            source = path.read_text(encoding="utf-8")
            names = [
                *DECLARATION.findall(source),
                *IMPLEMENTATION.findall(source),
            ]
            for name in sorted(set(names)):
                if is_guard_name(name):
                    relative = path.relative_to(root)
                    errors.append(
                        f"resident generation guard is declared outside dae-resident-core: "
                        f"{relative} ({name})"
                    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).parents[2])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("generation fence gate: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("generation fence gate: PASS (resident guard declarations are core-owned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
