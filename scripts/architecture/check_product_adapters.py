#!/usr/bin/env python3
"""Keep the daemon product surface limited to explicit host adapters."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
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


PRODUCT_CRATE_IMPORT = re.compile(r"\b(dae_product_[A-Za-z0-9_]+)\b")


def product_crate_imports(source: str) -> set[str]:
    imports: set[str] = set()
    for line in source.splitlines():
        stripped = line.split("//", 1)[0]
        if re.search(r"\b(?:use|extern\s+crate)\b", stripped):
            imports.update(PRODUCT_CRATE_IMPORT.findall(stripped))
        elif re.search(r"\bdae_product_[A-Za-z0-9_]+\s*::", stripped):
            imports.update(PRODUCT_CRATE_IMPORT.findall(stripped))
    return imports


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
    total_limit = policy.get("total_production_line_limit")
    if total_limit is not None and (not isinstance(total_limit, int) or total_limit < 0):
        return ["product adapter policy total_production_line_limit must be a non-negative integer"]
    allowed_set = set(allowed)
    roles = policy.get("adapter_roles")
    if not isinstance(roles, dict) or not roles:
        return ["product adapter policy adapter_roles must be a non-empty object"]
    role_paths: dict[str, str] = {}
    for role, paths in roles.items():
        if not isinstance(role, str) or not isinstance(paths, list) or not all(
            isinstance(path, str) for path in paths
        ):
            errors.append("product adapter policy adapter_roles must map names to string arrays")
            continue
        for path in paths:
            if path in role_paths:
                errors.append(
                    f"product adapter path {path!r} is assigned to multiple roles: "
                    f"{role_paths[path]} and {role}"
                )
            role_paths[path] = role
            if path not in allowed_set:
                errors.append(
                    f"product adapter role {role!r} names an unapproved path: {path}"
                )
    missing_roles = sorted(allowed_set - set(role_paths))
    errors.extend(
        f"product adapter path is missing an ownership role: {path}"
        for path in missing_roles
    )
    role_imports = policy.get("role_product_imports", {})
    if not isinstance(role_imports, dict):
        errors.append("product adapter policy role_product_imports must be an object")
        role_imports = {}
    for role, allowed_imports in role_imports.items():
        if not isinstance(role, str) or not isinstance(allowed_imports, list) or not all(
            isinstance(item, str) for item in allowed_imports
        ):
            errors.append(
                "product adapter policy role_product_imports must map names to string arrays"
            )
    buckets: dict[str, int] = {}
    for entry in sorted(adapter_root.iterdir()):
        if entry.is_dir() and not any(entry.rglob("*.rs")):
            continue
        if entry.name not in allowed_set:
            errors.append(
                f"unapproved daemon product adapter surface: "
                f"{entry.relative_to(root)}"
            )
        elif entry.name not in role_paths:
            errors.append(
                f"product adapter path has no ownership role: "
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
            role = role_paths.get(bucket)
            allowed_imports = set(role_imports.get(role, []))
            source = path.read_text(encoding="utf-8")
            for imported in sorted(product_crate_imports(source)):
                if imported not in allowed_imports:
                    errors.append(
                        f"product adapter {path.relative_to(root)} imports {imported}, "
                        f"which is not allowed for role {role!r}"
                    )
            buckets[bucket] = buckets.get(bucket, 0) + len(
                source.splitlines()
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
    if total_limit is not None:
        total = sum(buckets.values())
        if total > total_limit:
            errors.append(
                f"daemon product adapters grew to {total} production lines; "
                f"total limit is {total_limit}"
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
