#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_id="${RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
output_root="${OUTPUT_ROOT:-/tmp/daenext-regression-baseline-${run_id}}"
report="${REPORT:-$output_root/baseline.md}"
iterations="${BASELINE_BENCH_ITERS:-auto}"
warmup="${BASELINE_BENCH_WARMUP:-2}"
repeat="${BASELINE_BENCH_REPEAT:-3}"

mkdir -p "$output_root"
mkdir -p "$(dirname "$report")"

test_log="$output_root/workspace-tests.log"
bench_jsonl="$output_root/functional-bench.jsonl"
test_started="$(date +%s%N)"
cargo test --workspace --all-targets --quiet -- --test-threads=1 >"$test_log" 2>&1
test_finished="$(date +%s%N)"
test_elapsed_ms="$(((test_finished - test_started) / 1000000))"

cargo run -p dae-bench --quiet -- \
  --case all \
  --iters "$iterations" \
  --warmup "$warmup" \
  --repeat "$repeat" \
  --output "$bench_jsonl" \
  >"$output_root/functional-bench.log" 2>&1

kernel_fixture_status="not-requested"
if [[ "${RUN_KERNEL_FIXTURES:-0}" == "1" ]]; then
  kernel_fixture_status="pass"
  if ! scripts/run_regression_network_fixture.sh \
    >"$output_root/network-fixture.log" 2>&1; then
    kernel_fixture_status="fail"
  fi
  if ! DAE_RUN_CGROUP_COEXISTENCE_FIXTURE=1 cargo test \
    -p dae-ebpf-support \
    --features aya-loader \
    cgroup_empty_multi_single_coexistence_fixture_is_env_gated_and_cleans_up \
    -- --nocapture \
    >"$output_root/cgroup-matrix.log" 2>&1; then
    kernel_fixture_status="fail"
  fi
fi

native_gate_status="not-requested"
native_attach_count="not-recorded"
native_reload_ns="not-recorded"
native_tcp_ns="not-recorded"
native_udp_ns="not-recorded"
native_dns_ns="not-recorded"
observed_map_payload_bytes="not-recorded"
native_max_rss_kib="not-recorded"
native_max_threads="not-recorded"
native_max_fds="not-recorded"
native_max_processes="not-recorded"
if [[ "${RUN_NATIVE_RUNTIME_GATE:-0}" == "1" ]]; then
  native_gate_status="pass"
  native_run_root="/tmp/dae-daemon-native-ebpf-runtime-gate-baseline-${run_id}"
  if ! RUN_ROOT="$native_run_root" \
    CONFIG_FILE="$output_root/native-runtime.dae" \
    RUNTIME_GATE_LOG="$output_root/native-runtime.log" \
    RUNTIME_RESOURCE_LOG="$output_root/native-resources.env" \
    CGROUP_LOG="$output_root/native-cgroup.log" \
    scripts/run_native_ebpf_runtime_gate.sh \
    >"$output_root/native-gate.log" 2>&1; then
    native_gate_status="fail"
  fi
  if [[ -f "$native_run_root/run/daed-run.json" ]]; then
    cp "$native_run_root/run/daed-run.json" "$output_root/native-run.json"
    native_attach_count="$(jq '[.production_runtime_owner.executed_steps[]? | select(.native_attach.attached == true)] | length' "$output_root/native-run.json")"
    native_reload_ns="$(jq -r '.production_runtime_owner.reload_runtime.elapsed_ns // "not-recorded"' "$output_root/native-run.json")"
    native_tcp_ns="$(jq -r '.production_runtime_owner.active_tcp.relay_benchmark.ns_per_connection // "not-recorded"' "$output_root/native-run.json")"
    native_udp_ns="$(jq -r '.production_runtime_owner.active_udp.benchmark.ns_per_packet // "not-recorded"' "$output_root/native-run.json")"
    native_dns_ns="$(jq -r '.production_runtime_owner.active_dns.benchmark.ns_per_query // "not-recorded"' "$output_root/native-run.json")"
    observed_map_payload_bytes="$(jq '[.. | objects | select(has("map_type") and has("max_entries") and has("key_size") and has("value_size")) | {id, bytes: ((.key_size + .value_size) * .max_entries)}] | unique_by(.id) | map(.bytes) | add // 0' "$output_root/native-run.json")"
  fi
  if [[ -f "$output_root/native-resources.env" ]]; then
    native_max_rss_kib="$(awk -F= '$1 == "max_rss_kib" {print $2}' "$output_root/native-resources.env")"
    native_max_threads="$(awk -F= '$1 == "max_threads" {print $2}' "$output_root/native-resources.env")"
    native_max_fds="$(awk -F= '$1 == "max_fds" {print $2}' "$output_root/native-resources.env")"
    native_max_processes="$(awk -F= '$1 == "max_processes" {print $2}' "$output_root/native-resources.env")"
  fi
  rm -rf "$native_run_root"
fi

commit="$(git rev-parse HEAD)"
kernel="$(uname -srmo)"
cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)"
mem_total_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
thread_count="$(find /proc/self/task -mindepth 1 -maxdepth 1 -type d | wc -l)"
fd_count="$(find /proc/self/fd -mindepth 1 -maxdepth 1 | wc -l)"

{
  printf '# DaeNext local regression baseline\n\n'
  printf -- '- Recorded: `%s`\n' "$(date --iso-8601=seconds)"
  printf -- '- Commit: `%s`\n' "$commit"
  printf -- '- Kernel: `%s`\n' "$kernel"
  printf -- '- Online CPUs: `%s`\n' "$cpu_count"
  printf -- '- MemTotal KiB: `%s`\n' "$mem_total_kib"
  printf -- '- Workspace tests elapsed ms: `%s`\n' "$test_elapsed_ms"
  printf -- '- Baseline process threads: `%s`\n' "$thread_count"
  printf -- '- Baseline process FDs: `%s`\n' "$fd_count"
  printf -- '- Native runtime gate: `%s`\n' "$native_gate_status"
  printf -- '- Kernel fixtures: `%s`\n' "$kernel_fixture_status"
  printf -- '- Native attached tproxy programs observed: `%s`\n' "$native_attach_count"
  printf -- '- Native reload elapsed ns: `%s`\n' "$native_reload_ns"
  printf -- '- Native TCP relay ns/connection: `%s`\n' "$native_tcp_ns"
  printf -- '- Native UDP ns/packet: `%s`\n' "$native_udp_ns"
  printf -- '- Native DNS ns/query: `%s`\n' "$native_dns_ns"
  printf -- '- Observed map payload lower bound bytes: `%s`\n' "$observed_map_payload_bytes"
  printf -- '- Native runtime process-tree max RSS KiB: `%s`\n' "$native_max_rss_kib"
  printf -- '- Native runtime process-tree max threads/tasks: `%s`\n' "$native_max_threads"
  printf -- '- Native runtime process-tree max FDs: `%s`\n' "$native_max_fds"
  printf -- '- Native runtime process-tree max processes: `%s`\n' "$native_max_processes"
  printf -- '- Functional benchmark JSONL: `%s`\n' "$bench_jsonl"
  printf -- '- Workspace test log: `%s`\n' "$test_log"
} >"$report"

if [[ "$native_gate_status" == "fail" ]]; then
  tail -c 12000 "$output_root/native-gate.log" >&2 || true
  exit 1
fi
if [[ "$kernel_fixture_status" == "fail" ]]; then
  tail -c 8000 "$output_root/network-fixture.log" >&2 || true
  tail -c 8000 "$output_root/cgroup-matrix.log" >&2 || true
  exit 1
fi

printf '%s\n' "$report"
