#!/usr/bin/env python3
"""Fail if a feature-gated runtime suite silently disappears from the test graph."""
import argparse
import json
import subprocess
import sys

SUITES = {
    "dae-resident-dataplane": "dns_runtime_tests::",
    "dae-resident-dns": "runtime::transport::udp_multiplex::tests::",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="production-performance")
    args = parser.parse_args()
    for package, prefix in SUITES.items():
        command = ["cargo", "test", "--locked", "--profile", args.profile,
                   "-p", package, "--lib", "--features", "dns-runtime-tests",
                   "--no-run", "--message-format=json"]
        binaries = []
        with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                message = json.loads(line)
                if (message.get("reason") == "compiler-artifact"
                        and message.get("profile", {}).get("test")
                        and message.get("executable")
                        and message["target"]["name"] == package.replace("-", "_")):
                    binaries.append(message["executable"])
            if process.wait():
                return 1
        if len(binaries) != 1:
            raise RuntimeError(f"{package}: expected one test executable")
        result = subprocess.run([binaries[0], "--list", "--format", "terse"],
                                text=True, capture_output=True, check=True)
        required = {line for line in result.stdout.splitlines()
                    if line.startswith(prefix) and line.endswith(": test")}
        ignored = subprocess.run([binaries[0], "--ignored", "--list", "--format", "terse"],
                                 text=True, capture_output=True, check=True)
        active = required - set(ignored.stdout.splitlines())
        if not active:
            raise RuntimeError(f"{package}: required suite {prefix} has no active tests")
        print(f"OK: {package} {prefix}: {len(active)} active, "
              f"{len(required) - len(active)} explicitly ignored tests")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
