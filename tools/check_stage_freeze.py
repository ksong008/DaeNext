#!/usr/bin/env python3
"""Fail if temporary migration stage assets grow past the frozen baseline."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]

BASELINE = {
    "cli_runtime_stage_root_files": 126,
    "cli_runtime_stage_dirs": 55,
    "cli_runtime_stage_nested_files": 212,
    "product_stage_root_files": 158,
    "product_stage_nested_files": 0,
    "engine_runtime_stage_dirs": 168,
    "engine_runtime_stage_files": 170,
    "product_daemon_stage_items": 161,
    "product_daemon_stage_files": 161,
}


def count_cli_runtime_stage_root_files() -> int:
    return len(list((ROOT / "rust/crates/dae-cli/src").glob("runtime_stage*.rs")))


def count_cli_runtime_stage_dirs() -> int:
    return len(
        [
            path
            for path in (ROOT / "rust/crates/dae-cli/src").glob("runtime_stage*")
            if path.is_dir()
        ]
    )


def count_cli_runtime_stage_nested_files() -> int:
    root = ROOT / "rust/crates/dae-cli/src"
    return len(
        [
            path
            for stage_dir in root.glob("runtime_stage*")
            if stage_dir.is_dir()
            for path in stage_dir.rglob("*")
            if path.is_file()
        ]
    )


def count_product_stage_root_files() -> int:
    return len(list((ROOT / "rust/crates/dae-product/src").glob("stage*.rs")))


def count_product_stage_nested_files() -> int:
    root = ROOT / "rust/crates/dae-product/src"
    return len(
        [
            path
            for stage_dir in root.glob("stage*")
            if stage_dir.is_dir()
            for path in stage_dir.rglob("*")
            if path.is_file()
        ]
    )


def count_engine_runtime_stage_dirs() -> int:
    return len(
        [
            path
            for path in (ROOT / "testdata/rebuild-golden/engine").glob("runtime_stage*")
            if path.is_dir()
        ]
    )


def count_engine_runtime_stage_files() -> int:
    root = ROOT / "testdata/rebuild-golden/engine"
    return len(
        [
            path
            for stage_dir in root.glob("runtime_stage*")
            if stage_dir.is_dir()
            for path in stage_dir.rglob("*")
            if path.is_file()
        ]
    )


def count_product_daemon_stage_items() -> int:
    root = ROOT / "testdata/rebuild-golden/product/daemon"
    if not root.exists():
        return 0
    return len(
        [
            path
            for path in root.glob("stage*")
            if path.is_dir() or (path.is_file() and path.suffix == ".json")
        ]
    )


def count_product_daemon_stage_files() -> int:
    root = ROOT / "testdata/rebuild-golden/product/daemon"
    if not root.exists():
        return 0
    return len(
        [
            path
            for stage_path in root.glob("stage*")
            for path in ([stage_path] if stage_path.is_file() else stage_path.rglob("*"))
            if path.is_file()
        ]
    )


COUNTERS = {
    "cli_runtime_stage_root_files": count_cli_runtime_stage_root_files,
    "cli_runtime_stage_dirs": count_cli_runtime_stage_dirs,
    "cli_runtime_stage_nested_files": count_cli_runtime_stage_nested_files,
    "product_stage_root_files": count_product_stage_root_files,
    "product_stage_nested_files": count_product_stage_nested_files,
    "engine_runtime_stage_dirs": count_engine_runtime_stage_dirs,
    "engine_runtime_stage_files": count_engine_runtime_stage_files,
    "product_daemon_stage_items": count_product_daemon_stage_items,
    "product_daemon_stage_files": count_product_daemon_stage_files,
}


def main() -> int:
    violations: list[str] = []
    for name, counter in COUNTERS.items():
        current = counter()
        allowed = BASELINE[name]
        if current > allowed:
            violations.append(f"{name}: current={current} baseline={allowed}")
        print(f"{name}: current={current} baseline={allowed}")

    if violations:
        print("\nstage freeze violation: temporary migration stage assets increased")
        for violation in violations:
            print(f"- {violation}")
        return 1

    print("\nstage freeze ok: no temporary migration stage asset growth")
    return 0


if __name__ == "__main__":
    sys.exit(main())
