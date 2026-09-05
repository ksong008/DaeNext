#!/usr/bin/env python3
"""Check the selected product graph separately from workspace test/bench graphs.

Cargo tree reports a feature union for repeated host/target package identities.
This gate conservatively rejects forbidden features in that union; independent
product compilation remains required, especially for cross compilation.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

PROVIDERS = {"rustls", "tokio-rustls", "aws-lc-rs", "aws-lc-sys", "rcgen"}
SUPPORT = {
    "test-support", "benchmark-support", "dns-runtime-tests",
    "test-scalar-udp-recv", "test-scalar-udp-send", "test-anytls-legacy-frame-reader",
}
PACKAGE = re.compile(r"([A-Za-z0-9_-]+) v[^\s|]+(?: \(.*\))?")
FEATURE = re.compile(r"[A-Za-z0-9_+.-]+")


def parse_tree(output):
    selected = {}
    for line in output.splitlines():
        if not line.strip():
            continue  # Cargo separates workspace roots with blank lines.
        if line.endswith(" (*)"):
            line = line[:-4]
        identity, separator, raw_features = line.partition("|")
        match = PACKAGE.fullmatch(identity)
        features = set(raw_features.split(",")) if raw_features else set()
        if not separator or not match or any(not FEATURE.fullmatch(f) for f in features):
            raise ValueError(f"invalid cargo tree row: {line!r}")
        name, previous = selected.get(identity, (match.group(1), set()))
        selected[identity] = (name, previous | features)
    if not selected:
        raise ValueError("empty cargo tree output")
    return selected


def violations(selected, product=True):
    errors = []
    for identity, (name, features) in sorted(selected.items()):
        if name in PROVIDERS:
            errors.append(f"{identity}: forbidden TLS/test provider")
        if product and (hits := features & SUPPORT):
            errors.append(f"{identity}: forbidden product features {','.join(sorted(hits))}")
    return errors


def command(args, cwd):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout


def tree(cwd, roots, target, edges="normal,build", extra=()):
    return parse_tree(command([
        "cargo", "tree", "--locked", *roots, "--target", target,
        "-e", edges, "--prefix", "none", "--color", "never",
        "--format", "{p}|{f}", *extra,
    ], cwd))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--package", default="dae-daemon")
    parser.add_argument("--target", default=os.environ.get("CARGO_BUILD_TARGET"))
    parser.add_argument("--features")
    parser.add_argument("--no-default-features", action="store_true")
    parser.add_argument("--all-features", action="store_true", help="analyze workspace features, never enable all product features")
    parser.add_argument("--product-only", action="store_true")
    args = parser.parse_args()
    try:
        target = args.target or next(line.removeprefix("host: ") for line in command(["rustc", "-vV"], args.root).splitlines() if line.startswith("host: "))
        extra = ["--no-default-features"] if args.no_default_features else []
        if args.features:
            extra += ["--features", args.features]
        product = tree(args.root, ["-p", args.package], target, extra=extra)
        errors = violations(product)
        if errors:
            raise ValueError("\n".join(errors))
        print(f"OK: product {args.package} target={target}: {len(product)} package identities, forbidden support features=0")
        if not args.product_only:
            workspace = tree(args.root, ["--workspace"], target, extra=["--all-features"] if args.all_features else [])
            errors = violations(workspace, product=False)
            development = tree(args.root, ["--workspace"], target, "normal,build,dev", ["--all-features"])
            errors += violations(development, product=False)
            supported = sum("test-support" in features for _, features in development.values())
            if not supported:
                errors.append("development graph does not exercise test-support")
            if errors:
                raise ValueError("\n".join(errors))
            print(f"OK: workspace providers checked separately; development test-support identities={supported}")
    except (OSError, ValueError, StopIteration, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr[-4000:], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
