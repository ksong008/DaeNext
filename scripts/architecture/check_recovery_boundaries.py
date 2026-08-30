#!/usr/bin/env python3
"""Keep product durable recovery separate from the resident direct-service path."""

from __future__ import annotations

import argparse
import pathlib
import sys


RECOVERY_ENTRYPOINT = "recover_product_durable_state"
RESIDENT_SERVICE = pathlib.Path("crates/dae-daemon/src/service_contract/resident_service.rs")
PRODUCT_SERVER = pathlib.Path("crates/dae-daemon/src/daed_product/cli_commands/server.rs")


def validate(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    resident_path = root / RESIDENT_SERVICE
    product_path = root / PRODUCT_SERVER
    if not resident_path.is_file():
        errors.append(f"resident service source is missing: {RESIDENT_SERVICE}")
    if not product_path.is_file():
        errors.append(f"product server source is missing: {PRODUCT_SERVER}")
    if errors:
        return errors

    resident_source = resident_path.read_text(encoding="utf-8")
    product_source = product_path.read_text(encoding="utf-8")
    if RECOVERY_ENTRYPOINT in resident_source:
        errors.append(
            "resident direct-service path must not invoke product durable recovery"
        )
    if RECOVERY_ENTRYPOINT not in product_source:
        errors.append("product server path must invoke product durable recovery")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=pathlib.Path, default=pathlib.Path(__file__).parents[2]
    )
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("recovery boundary gate: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("recovery boundary gate: PASS (product and resident recovery paths are separated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
