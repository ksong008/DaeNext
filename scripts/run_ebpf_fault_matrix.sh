#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "$(id -u)" != "0" ]]; then
  echo "eBPF fault matrix requires root" >&2
  exit 2
fi

run_id="${RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
output_root="${OUTPUT_ROOT:-$repo_root/build/benchmark/ebpf-fault-matrix-$run_id}"
matrix_json="$output_root/matrix.jsonl"
matrix_tsv="$output_root/matrix.tsv"
test_target="/tmp/dae-architecture-fault-$run_id-target"
mkdir -p "$output_root"
export CARGO_TARGET_DIR="$test_target"

cleanup() {
  set +e
  for temporary_path in \
    "/tmp/dae-architecture-fault-$run_id-target" \
    "/tmp/dae-daemon-native-ebpf-runtime-gate-$run_id"; do
    if [[ -e "$temporary_path" ]]; then
      find "$temporary_path" -depth -delete >/dev/null 2>&1
    fi
  done
}
trap cleanup EXIT INT TERM

resource_snapshot() {
  {
    printf 'netns\t'
    ip netns list 2>&1 | tr '\n' ' '
    printf '\nlinks\t'
    ip -d link show 2>&1 | grep -E 'dae0|dae50|dae-native|dae-aya|d0l-|d0r-' || true
    printf '\n'
    printf 'bpffs\t'
    find /sys/fs/bpf -maxdepth 2 \( -name 'dae-native-runtime-*' -o -name 'dae-aya-*' -o -name 'dae-cgroup-fixture-*' \) 2>&1 || true
    printf '\n'
  }
}

assert_clean() {
  local snapshot
  snapshot="$(resource_snapshot)"
  if rg -q 'netns\t.*(dae|d0l-|d0r-)|^(links|bpffs)\t.+' <<<"$snapshot"; then
    echo "eBPF fault matrix found resource leftovers" >&2
    printf '%s\n' "$snapshot" | head -c 12000 >&2
    exit 1
  fi
}

record_case() {
  local name="$1"
  local status="$2"
  local detail="$3"
  python3 - "$matrix_json" "$matrix_tsv" "$name" "$status" "$detail" <<'PY'
import json
import sys

json_path, tsv_path, name, status, detail = sys.argv[1:]
row = {"case": name, "status": status, "detail": detail}
with open(json_path, "a", encoding="utf-8") as output:
    output.write(json.dumps(row, sort_keys=True) + "\n")
with open(tsv_path, "a", encoding="utf-8") as output:
    output.write(f"{name}\t{status}\t{detail}\n")
PY
}

: >"$matrix_json"
printf 'case\tstatus\tdetail\n' >"$matrix_tsv"

run_network_case() {
  local name="$1"
  local log="$output_root/$name.log"
  local status=0
  RUN_ID="${run_id}-${name}" scripts/run_regression_network_fixture.sh >"$log" 2>&1 || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "$name failed; see $log" >&2
    tail -c 6000 "$log" >&2 || true
    exit 1
  fi
  record_case "$name" pass "untagged/VLAN/later-TC/L3"
  assert_clean
}

run_network_case normal

invalid_log="$output_root/invalid-vlan.log"
invalid_status=0
RUN_ID="${run_id}-invalid-vlan" FIXTURE_VLAN_ID=5000 \
  scripts/run_regression_network_fixture.sh >"$invalid_log" 2>&1 || invalid_status=$?
if [[ "$invalid_status" -eq 0 ]]; then
  echo "invalid VLAN fixture unexpectedly succeeded" >&2
  exit 1
fi
record_case invalid-vlan expected-failure-cleaned "status=$invalid_status"
assert_clean

cgroup_log="$output_root/cgroup-coexistence.log"
DAE_RUN_CGROUP_COEXISTENCE_FIXTURE=1 cargo test --locked -p dae-ebpf-support \
  --features aya-loader \
  cgroup_empty_multi_single_coexistence_fixture_is_env_gated_and_cleans_up \
  -- --nocapture >"$cgroup_log" 2>&1
record_case cgroup-empty-multi-single pass "empty/multi/single"
assert_clean

aya_log="$output_root/aya-attach-detach.log"
DAE_RUN_AYA_CGROUP_ATTACH_SMOKE=1 cargo test --locked -p dae-ebpf-support \
  --features aya-loader aya_cgroup_attach_detach_smoke_is_env_gated \
  -- --nocapture >"$aya_log" 2>&1
if rg -q 'skip aya cgroup attach smoke' "$aya_log"; then
  echo "Aya attach case skipped; admission evidence is required" >&2
  tail -c 6000 "$aya_log" >&2 || true
  exit 1
fi
record_case aya-attach-detach pass "native cgroup attach/detach"
assert_clean

native_root="/tmp/dae-daemon-native-ebpf-runtime-gate-$run_id"
native_log="$output_root/native-runtime.log"
RUN_ID="$run_id" RUN_ROOT="$native_root" \
  CONFIG_FILE="$output_root/native-runtime.dae" \
  RUNTIME_GATE_LOG="$native_log" \
  scripts/run_native_ebpf_runtime_gate.sh >"$output_root/native-runtime-gate.log" 2>&1
record_case native-runtime-attach-reload pass "TCP/UDP/DNS attach/reload/cleanup"
find "$native_root" -depth -delete
assert_clean

python3 - "$matrix_json" "$output_root/summary.json" <<'PY'
import json
import sys

rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
summary = {
    "cases": rows,
    "case_count": len(rows),
    "passed": sum(row["status"] in {"pass", "expected-failure-cleaned"} for row in rows),
    "resource_cleanup_verified_after_each_case": True,
}
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
if summary["passed"] != summary["case_count"]:
    raise SystemExit(1)
PY

printf '%s\n' "$output_root"
