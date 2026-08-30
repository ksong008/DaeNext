#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

baseline_commit="${BASELINE_COMMIT:-4f2a6ab209037a8c3538803293a9878d8a419662}"
current_commit="${CURRENT_COMMIT:-$(git rev-parse HEAD)}"
run_id="${RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
output_root="${OUTPUT_ROOT:-$repo_root/build/benchmark/architecture-ab-$run_id}"
work_root="/tmp/dae-architecture-ab-$run_id"
target_root="$work_root/target"
baseline_worktree="$work_root/baseline"
rounds="${AB_ROUNDS:-3}"
jobs="${CARGO_BUILD_JOBS:-1}"

if [[ ! "$rounds" =~ ^[1-9][0-9]*$ ]]; then
  echo "AB_ROUNDS must be a positive integer" >&2
  exit 2
fi
if [[ "$current_commit" == "$baseline_commit" ]]; then
  echo "baseline and current commits must differ" >&2
  exit 2
fi
while IFS= read -r status_line; do
  status_path="${status_line:3}"
  case "$status_path" in
    scripts/run_architecture_performance_ab.sh|scripts/run_ebpf_fault_matrix.sh|scripts/run_native_ebpf_runtime_gate.sh) ;;
    *)
      echo "working tree has non-validation changes before performance A/B: $status_line" >&2
      exit 2
      ;;
  esac
done < <(git status --porcelain)

mkdir -p "$output_root" "$work_root"
results="$output_root/results.jsonl"
: >"$results"

cleanup() {
  set +e
  if git worktree list --porcelain | grep -Fq "worktree $baseline_worktree"; then
    git worktree remove --force "$baseline_worktree" >/dev/null 2>&1
  fi
  if [[ -d "$target_root" ]]; then
    find "$target_root" -depth -delete >/dev/null 2>&1
  fi
  if [[ -d "$work_root" ]]; then
    find "$work_root" -depth -delete >/dev/null 2>&1
  fi
}
trap cleanup EXIT INT TERM

git worktree add --detach "$baseline_worktree" "$baseline_commit" >/dev/null

measure() {
  local log_file="$1"
  shift
  python3 - "$log_file" "$@" <<'PY'
import os
import resource
import subprocess
import sys
import time

log_file, *command = sys.argv[1:]
started = time.monotonic_ns()
with open(log_file, "wb") as output:
    result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=os.environ.copy())
elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
print(f"{elapsed_ms}\t{resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}\t{result.returncode}")
sys.exit(result.returncode)
PY
}

record() {
  local label="$1"
  local round="$2"
  local phase="$3"
  local elapsed_ms="$4"
  local max_rss_kib="$5"
  local status="$6"
  local packages="$7"
  python3 - "$results" "$label" "$round" "$phase" "$elapsed_ms" "$max_rss_kib" "$status" "$packages" <<'PY'
import json
import sys

path, label, round_number, phase, elapsed_ms, max_rss_kib, status, packages = sys.argv[1:]
with open(path, "a", encoding="utf-8") as output:
    output.write(json.dumps({
        "label": label,
        "round": int(round_number),
        "phase": phase,
        "elapsed_ms": int(elapsed_ms),
        "max_rss_kib": int(max_rss_kib),
        "status": int(status),
        "recompiled_packages": [item for item in packages.split(",") if item],
    }, sort_keys=True) + "\n")
PY
}

recompiled_packages() {
  local log_file="$1"
  python3 - "$log_file" <<'PY'
import json
import sys

packages = set()
with open(sys.argv[1], encoding="utf-8", errors="replace") as source:
    for line in source:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("reason") != "compiler-artifact" or event.get("fresh") is not False:
            continue
        target = event.get("target") or {}
        package_name = target.get("name", "")
        package_id = event.get("package_id", "")
        if not package_name:
            package_name = package_id.rsplit("#", 1)[-1].split("@", 1)[0]
        if package_name:
            packages.add(package_name)
        elif (event.get("target") or {}).get("name"):
            packages.add(event["target"]["name"])
print(",".join(sorted(packages)))
PY
}

clean_target() {
  if [[ -d "$target_root" ]]; then
    find "$target_root" -depth -delete
  fi
  mkdir -p "$target_root"
}

run_suite() (
  local label="$1"
  local source_root="$2"
  local round="$3"
  local suite_root="$output_root/$label/round-$round"
  local elapsed
  local rss
  local status
  local packages
  mkdir -p "$suite_root"
  cd "$source_root"

  export CARGO_BUILD_JOBS="$jobs"
  export CARGO_TARGET_DIR="$target_root"
  export CARGO_INCREMENTAL=1

  clean_target
  read -r elapsed rss status < <(
    measure "$suite_root/clean-check.log" cargo check --locked --workspace
  )
  record "$label" "$round" clean-check "$elapsed" "$rss" "$status" ""
  if [[ "$status" -ne 0 ]]; then
    echo "$label round $round clean check failed; see $suite_root/clean-check.log" >&2
    exit 1
  fi

  read -r elapsed rss status < <(
    measure "$suite_root/incremental-check.log" cargo check --locked --workspace
  )
  record "$label" "$round" incremental-check "$elapsed" "$rss" "$status" ""
  if [[ "$status" -ne 0 ]]; then
    echo "$label round $round incremental check failed; see $suite_root/incremental-check.log" >&2
    exit 1
  fi

  read -r elapsed rss status < <(
    measure "$suite_root/test-compile.log" \
      cargo test --locked --workspace --all-targets --no-run --quiet
  )
  record "$label" "$round" test-compile "$elapsed" "$rss" "$status" ""
  if [[ "$status" -ne 0 ]]; then
    echo "$label round $round test compile failed; see $suite_root/test-compile.log" >&2
    exit 1
  fi

  for domain in subscription geodata control; do
    local source_file="$source_root/crates/dae-product-$domain/src/lib.rs"
    local domain_log="$suite_root/incremental-$domain.json.log"
    if [[ ! -f "$source_file" ]]; then
      echo "missing domain source for $label: $source_file" >&2
      exit 1
    fi
    touch "$source_file"
    read -r elapsed rss status < <(
      measure "$domain_log" cargo check --locked --workspace --message-format=json
    )
    packages="$(recompiled_packages "$domain_log")"
    record "$label" "$round" "incremental-$domain" "$elapsed" "$rss" "$status" "$packages"
    if [[ "$status" -ne 0 ]]; then
      echo "$label round $round $domain incremental check failed; see $domain_log" >&2
      exit 1
    fi
  done

  read -r elapsed rss status < <(
    measure "$suite_root/functional-bench-run.log" \
      cargo run --locked -p dae-bench --quiet -- \
        --case all --iters auto --warmup 2 --repeat 1 \
        --output "$suite_root/functional-bench.jsonl"
  )
  record "$label" "$round" functional-bench "$elapsed" "$rss" "$status" ""
  if [[ "$status" -ne 0 ]]; then
    echo "$label round $round functional benchmark failed; see $suite_root/functional-bench-run.log" >&2
    exit 1
  fi
)

for round in $(seq 1 "$rounds"); do
  echo "A/B round $round/$rounds: baseline"
  run_suite baseline "$baseline_worktree" "$round"
  echo "A/B round $round/$rounds: current"
  run_suite current "$repo_root" "$round"
done

python3 - "$results" "$output_root/summary.md" "$baseline_commit" "$current_commit" <<'PY'
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict

results_path, summary_path, baseline_commit, current_commit = sys.argv[1:]
rows = [json.loads(line) for line in open(results_path, encoding="utf-8") if line.strip()]
groups = defaultdict(list)
for row in rows:
    groups[(row["label"], row["phase"])].append(row)

def median(label: str, phase: str, key: str) -> float:
    return statistics.median(row[key] for row in groups[(label, phase)])

round_count = len(groups[("baseline", "clean-check")])
phases = [
    "clean-check",
    "incremental-check",
    "test-compile",
    "incremental-subscription",
    "incremental-geodata",
    "incremental-control",
    "functional-bench",
]
lines = [
    "# Architecture performance A/B",
    "",
    f"- Baseline: `{baseline_commit}`",
    f"- Current: `{current_commit}`",
    f"- Rounds: `{round_count}`",
    "- Build jobs: `CARGO_BUILD_JOBS=1` unless overridden",
    "- LTO: workspace profiles keep `lto=false`",
    "",
    "| Phase | Baseline median | Current median | Delta | Decision |",
    "| --- | ---: | ---: | ---: | --- |",
]
for phase in phases:
    base_time = median("baseline", phase, "elapsed_ms")
    current_time = median("current", phase, "elapsed_ms")
    delta = (current_time / base_time - 1.0) * 100.0 if base_time else 0.0
    if phase == "clean-check":
        decision = "pass" if delta <= 10.0 else "review"
    elif phase.startswith("incremental-") and phase != "incremental-check":
        decision = "improved >=20%" if delta <= -20.0 else "evidence/review"
    else:
        decision = "observed"
    lines.append(f"| {phase} | {base_time:.0f} ms | {current_time:.0f} ms | {delta:+.1f}% | {decision} |")

lines.extend(["", "## Peak RSS", "", "| Phase | Baseline median | Current median | Delta |", "| --- | ---: | ---: | ---: |"])
for phase in phases:
    base_rss = median("baseline", phase, "max_rss_kib")
    current_rss = median("current", phase, "max_rss_kib")
    delta = (current_rss / base_rss - 1.0) * 100.0 if base_rss else 0.0
    lines.append(f"| {phase} | {base_rss:.0f} KiB | {current_rss:.0f} KiB | {delta:+.1f}% |")

lines.extend(["", "## Recompiled packages", ""])
for phase in phases:
    if not phase.startswith("incremental-") or phase == "incremental-check":
        continue
    base_sets = [set(row["recompiled_packages"]) for row in groups[("baseline", phase)]]
    current_sets = [set(row["recompiled_packages"]) for row in groups[("current", phase)]]
    lines.append(f"- `{phase}` baseline: `{', '.join(sorted(set.union(*base_sets))) or 'none'}`")
    lines.append(f"- `{phase}` current: `{', '.join(sorted(set.union(*current_sets))) or 'none'}`")

with open(summary_path, "w", encoding="utf-8") as output:
    output.write("\n".join(lines) + "\n")
PY

printf '%s\n' "$output_root"
