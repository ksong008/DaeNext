#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

audit_file="${TMPDIR:-/tmp}/daenext-resident-production-panics.json"
trap ': > "$audit_file"' EXIT

packages=(
  dae-resident-core
  dae-resident-model
  dae-resident-plan
  dae-resident-transport
  dae-resident-dns
  dae-resident-tcp
  dae-resident-udp
  dae-resident-dataplane
)

cargo_args=()
for package in "${packages[@]}"; do
  cargo_args+=(-p "$package")
done

if ! cargo clippy "${cargo_args[@]}" --lib --message-format=json -- \
  -W clippy::unwrap_used -W clippy::expect_used >"$audit_file" 2>&1; then
  tail -c 12000 "$audit_file" >&2
  exit 1
fi

python3 - "$audit_file" scripts/resident_production_panic_baseline.tsv <<'PY'
from __future__ import annotations

import collections
import json
import pathlib
import sys


audit_path = pathlib.Path(sys.argv[1])
baseline_path = pathlib.Path(sys.argv[2])
resident_crates = {
    "dae-resident-core",
    "dae-resident-dataplane",
    "dae-resident-dns",
    "dae-resident-model",
    "dae-resident-plan",
    "dae-resident-tcp",
    "dae-resident-transport",
    "dae-resident-udp",
}

actual: collections.Counter[str] = collections.Counter()
with audit_path.open(encoding="utf-8") as audit:
    for raw_line in audit:
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-message":
            continue
        message = record["message"]
        code = (message.get("code") or {}).get("code")
        if code not in {"clippy::expect_used", "clippy::unwrap_used"}:
            continue
        spans = message.get("spans") or []
        primary = next((span for span in spans if span.get("is_primary")), None)
        if primary is None:
            continue
        source = primary["file_name"]
        parts = pathlib.PurePosixPath(source).parts
        if len(parts) >= 3 and parts[0] == "crates" and parts[1] in resident_crates:
            actual[source] += 1

baseline: dict[str, tuple[int, str]] = {}
with baseline_path.open(encoding="utf-8") as source:
    for line_number, raw_line in enumerate(source, 1):
        line = raw_line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t", 3)
        if len(fields) != 4:
            raise SystemExit(f"{baseline_path}:{line_number}: expected four tab-separated fields")
        path, maximum, category, _rationale = fields
        if category in {"ExternalInput", "RemotePeer"}:
            raise SystemExit(
                f"{baseline_path}:{line_number}: {category} panic cannot be approved"
            )
        baseline[path] = (int(maximum), category)

failures: list[str] = []
for path, count in sorted(actual.items()):
    approved = baseline.get(path)
    if approved is None:
        failures.append(f"unclassified production panic: {path} ({count})")
        continue
    maximum, category = approved
    if count > maximum:
        failures.append(
            f"production panic budget increased: {path}: {count} > {maximum} ({category})"
        )

if failures:
    print("FAIL: resident production panic surface")
    print("\n".join(failures))
    raise SystemExit(1)

totals: collections.Counter[str] = collections.Counter()
for path, count in actual.items():
    totals[baseline[path][1]] += count
print(
    "OK: resident production panic surface: "
    f"files={len(actual)}, total={sum(actual.values())}, "
    f"internal_invariant={totals['InternalInvariant']}, "
    "remote_peer=0, external_input=0"
)
PY
