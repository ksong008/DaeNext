#!/usr/bin/env bash
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Root-gated local validation for the native Aya eBPF runtime evidence path.
# The gate records native backend admission without changing live host state.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "$(id -u)" != "0" ]]; then
  echo "native eBPF runtime gate requires root for netns, tproxy, and TC attach" >&2
  exit 2
fi

run_id="${RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
run_root="${RUN_ROOT:-/tmp/dae-daemon-native-ebpf-runtime-gate-${run_id}}"
config_file="${CONFIG_FILE:-/tmp/dae-native-ebpf-runtime-gate-${run_id}.dae}"
cargo_target_dir="${CARGO_TARGET_DIR:-target}"
rust_native_object="${RUST_NATIVE_OBJECT:-$cargo_target_dir/bpfel-unknown-none/release/libdae_ebpf_program.so}"
cargo_log="${RUNTIME_GATE_LOG:-${CARGO_LOG:-/tmp/dae-native-ebpf-runtime-gate-${run_id}.log}}"
cgroup_log="${CGROUP_LOG:-/tmp/dae-native-ebpf-cgroup-gate-${run_id}.log}"
resource_log="${RUNTIME_RESOURCE_LOG:-/tmp/dae-native-ebpf-runtime-resources-${run_id}.env}"
backend="${NATIVE_EBPF_BACKEND:-${DAE_NATIVE_EBPF_BACKEND:-auto}}"
netns_link="${NETNS_LINK:-${DAE_NETNS_LINK:-auto}}"
native_object_mode="${NATIVE_EBPF_OBJECT_MODE:-auto}"
runtime_timeout="${RUNTIME_TIMEOUT:-180s}"

case "$native_object_mode" in
  auto|pname-core|current-comm) ;;
  *)
    echo "unsupported NATIVE_EBPF_OBJECT_MODE: $native_object_mode" >&2
    exit 2
    ;;
esac

case "$run_root" in
  /tmp/dae-daemon-native-ebpf-runtime-gate*) ;;
  *)
    echo "refusing unsafe RUN_ROOT outside /tmp/dae-daemon-native-ebpf-runtime-gate*: $run_root" >&2
    exit 2
    ;;
esac

unset CARGO_LOG
printf 'global {\n  log_level: info\n}\ndns {}\nrouting {\n  fallback: direct\n}\n' > "$config_file"
rm -rf "$run_root"
mkdir -p "$run_root"

echo "building native Aya loader object from crates/dae-ebpf-program"
echo "native object source: crates/dae-ebpf-program"
cargo +nightly build -Z build-std=core --manifest-path Cargo.toml \
  -p dae-ebpf-program \
  --target bpfel-unknown-none \
  --release
if [[ ! -f "$rust_native_object" ]]; then
  echo "missing Rust native eBPF object after build: $rust_native_object" >&2
  exit 1
fi
native_object_symbols="$(llvm-readelf -s "$rust_native_object" 2>/dev/null || true)"
if ! grep -q ' PARAM$' <<<"$native_object_symbols"; then
  echo "Rust native eBPF object does not expose expected PARAM symbol: $rust_native_object" >&2
  exit 1
fi

echo "running Aya cgroup attach/detach gate"
if ! DAE_RUN_AYA_CGROUP_ATTACH_SMOKE=1 cargo test --manifest-path Cargo.toml \
  -p dae-ebpf-support \
  --features aya-loader \
  aya_cgroup_attach_detach_smoke_is_env_gated \
  -- --nocapture >"$cgroup_log" 2>&1; then
  echo "Aya cgroup attach/detach gate failed; tail of cargo log follows" >&2
  tail -c 20000 "$cgroup_log" >&2 || true
  exit 1
fi
if grep -q 'skip aya cgroup attach smoke' "$cgroup_log"; then
  echo "Aya cgroup attach/detach gate skipped; this is not admission evidence" >&2
  tail -c 20000 "$cgroup_log" >&2 || true
  exit 1
fi
echo "Aya cgroup attach/detach gate passed"

process_tree_pids() {
  local root_pid="$1"
  local queue=("$root_pid")
  local index=0
  while ((index < ${#queue[@]})); do
    local pid="${queue[$index]}"
    index=$((index + 1))
    printf '%s\n' "$pid"
    if command -v pgrep >/dev/null 2>&1; then
      while read -r child; do
        [[ -n "$child" ]] && queue+=("$child")
      done < <(pgrep -P "$pid" 2>/dev/null || true)
    fi
  done
}

run_with_resource_sample() {
  local output="$1"
  shift
  local max_rss_kib=0
  local max_threads=0
  local max_fds=0
  local max_processes=0
  local samples=0

  "$@" &
  local root_pid="$!"
  while kill -0 "$root_pid" >/dev/null 2>&1; do
    local rss_kib=0
    local threads=0
    local fds=0
    local processes=0
    while read -r pid; do
      [[ -r "/proc/$pid/status" ]] || continue
      processes=$((processes + 1))
      local process_rss
      local process_threads
      local process_fds
      process_rss="$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)"
      process_threads="$(awk '/^Threads:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)"
      process_fds="$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l || true)"
      rss_kib=$((rss_kib + ${process_rss:-0}))
      threads=$((threads + ${process_threads:-0}))
      fds=$((fds + ${process_fds:-0}))
    done < <(process_tree_pids "$root_pid")
    if ((rss_kib > max_rss_kib)); then
      max_rss_kib="$rss_kib"
    fi
    if ((threads > max_threads)); then
      max_threads="$threads"
    fi
    if ((fds > max_fds)); then
      max_fds="$fds"
    fi
    if ((processes > max_processes)); then
      max_processes="$processes"
    fi
    samples=$((samples + 1))
    sleep 0.02
  done

  local status=0
  wait "$root_pid" || status="$?"
  {
    printf 'max_rss_kib=%s\n' "$max_rss_kib"
    printf 'max_threads=%s\n' "$max_threads"
    printf 'max_fds=%s\n' "$max_fds"
    printf 'max_processes=%s\n' "$max_processes"
    printf 'samples=%s\n' "$samples"
    printf 'exit_status=%s\n' "$status"
  } >"$output"
  return "$status"
}

echo "running native eBPF runtime gate: root=$run_root backend=$backend netns_link=$netns_link object=$native_object_mode timeout=$runtime_timeout"
: >"$cargo_log"
if ! cargo build --manifest-path Cargo.toml \
  -p dae-daemon \
  --features native-ebpf \
  --bin daed-contract-runner \
  >>"$cargo_log" 2>&1; then
  echo "native eBPF contract runner build failed; tail follows" >&2
  tail -c 20000 "$cargo_log" >&2 || true
  exit 1
fi
if ! run_with_resource_sample "$resource_log" timeout "$runtime_timeout" \
  "$cargo_target_dir/debug/daed-contract-runner" run \
  --config "$config_file" \
  --root "$run_root" \
  --no-listener-smoke \
  --no-reload-smoke \
  --execute-production-runtime-owner \
  --execute-production-runtime-active-tcp \
  --execute-production-runtime-active-tcp-relay \
  --execute-production-runtime-active-udp \
  --execute-production-runtime-active-dns \
  --execute-production-runtime-reload-parity \
  --ack-root-gate \
  --production-runtime-native-ebpf \
  --production-runtime-native-ebpf-local-admission \
  --production-runtime-native-ebpf-backend "$backend" \
  --production-runtime-netns-link "$netns_link" \
  --exit-after-ready >>"$cargo_log" 2>&1; then
  echo "native eBPF runtime gate failed; tail of cargo log follows" >&2
  tail -c 20000 "$cargo_log" >&2 || true
  exit 1
fi

manifest="$run_root/run/daed-run.json"
if [[ ! -f "$manifest" ]]; then
  echo "missing run manifest: $manifest" >&2
  tail -c 20000 "$cargo_log" >&2 || true
  exit 1
fi

python3 - "$manifest" "$backend" "$netns_link" "$native_object_mode" <<'PY'
import json
import sys

manifest, expected_backend_raw, expected_netns_link_raw, expected_object = sys.argv[1:5]
expected_backend = expected_backend_raw.replace("-", "_")
expected_netns_link = expected_netns_link_raw.strip().lower()
accepted_backends = (
    {"tcx", "tc_netlink"}
    if expected_backend == "auto"
    else {expected_backend}
)
with open(manifest, "r", encoding="utf-8") as fh:
    root = json.load(fh)
owner = root.get("production_runtime_owner", {})
native_object = owner.get("native_object") or {}

required = [
    "daemon_owned_production_runtime_owner_smoke_passed",
    "production_dataplane_admitted",
    "production_reload_runtime_parity_passed",
    "reload_runtime_parity_admitted",
    "active_tcp_tproxy_ingress_smoke_passed",
    "active_tcp_relay_smoke_passed",
    "active_tcp_relay_benchmark_recorded",
    "route_dial_tcp_magic_network_mark_mptcp_observed",
    "so_mark_real_outbound_socket_observed",
    "mptcp_real_outbound_socket_observed",
    "active_udp_tproxy_admitted",
    "active_udp_tproxy_benchmark_recorded",
    "udp_endpoint_pool_live_recorded",
    "udp_packetconn_write_read_recorded",
    "udp_sendpkt_reply_recorded",
    "udp_so_mark_real_outbound_socket_observed",
    "active_dns_tproxy_admitted",
    "active_dns_tproxy_benchmark_recorded",
    "dns_cache_restore_recorded",
    "dns_upstream_query_recorded",
    "dns_response_validation_recorded",
    "domain_routing_owner_migration_recorded",
    "dns_sendpkt_reply_recorded",
    "dns_so_mark_upstream_socket_observed",
    "live_reload_executed",
    "production_listener_reused",
    "production_bpf_owner_transferred",
    "production_dns_cache_migrated",
    "dns_cache_migration_guard_verified",
    "bounded_close_verified",
    "runtime_overview_parity_verified",
    "reload_scoped_resources_flushed",
    "invalid_config_restore_verified",
]
missing = [key for key in required if owner.get(key) is not True]

native_steps = [
    step for step in owner.get("executed_steps", [])
    if step.get("name") in {
        "attach-production-dae0peer-native-ebpf-program",
        "attach-lan-ingress-native-ebpf-program",
        "attach-production-dae0-native-ebpf-program",
    }
]
if len(native_steps) != 3:
    missing.append("native attach peer/lan/host steps")
for step in native_steps:
    if step.get("status") != "pass":
        missing.append(f"{step.get('name')}.status")
    if step.get("backend") not in accepted_backends:
        missing.append(f"{step.get('name')}.backend")
    if step.get("backend_switch_used") is not False:
        missing.append(f"{step.get('name')}.backend_switch_used")
    attach = step.get("native_attach") or {}
    if attach.get("attached") is not True:
        missing.append(f"{step.get('name')}.native_attach.attached")

if expected_netns_link in {"netkit", "veth"}:
    selected_steps = {
        step.get("name"): step
        for step in owner.get("executed_steps", [])
        if step.get("name") in {
            "select-production-netns-link-mode",
            "select-active-tcp-netns-link-mode",
        }
    }
    for name in [
        "select-production-netns-link-mode",
        "select-active-tcp-netns-link-mode",
    ]:
        step = selected_steps.get(name)
        if not step:
            missing.append(name)
            continue
        if step.get("status") != "pass":
            missing.append(f"{name}.status")
        if step.get("selected") != expected_netns_link:
            missing.append(f"{name}.selected")
    topology_values = owner.get("topology_values") or {}
    if topology_values.get("production_host_link_kind") != expected_netns_link:
        missing.append("topology_values.production_host_link_kind")
    if topology_values.get("production_peer_link_kind") != expected_netns_link:
        missing.append("topology_values.production_peer_link_kind")

cleanup_failures = [
    step for step in owner.get("cleanup_steps", [])
    if step.get("status") == "fail"
]
if cleanup_failures:
    missing.append("cleanup_steps_without_failures")

selected_object = native_object.get("selectedObject")
core_enabled = native_object.get("coreEnabled")
core_status = native_object.get("coreStatus")
if selected_object not in {
    "memory:native-ebpf-object",
    "memory:native-ebpf-object-pname-core",
}:
    missing.append("native_object.selectedObject")
if expected_object == "pname-core":
    if selected_object != "memory:native-ebpf-object-pname-core":
        missing.append("native_object.pname_core_selected")
    if core_enabled is not True or core_status != "enhanced_load_succeeded":
        missing.append("native_object.pname_core_admitted")
    if native_object.get("currentTaskArgvEnabled") is not True:
        missing.append("native_object.current_task_argv_enabled")
    if (native_object.get("targetBtf") or {}).get("parseOk") is not True:
        missing.append("native_object.target_btf_parse")
elif expected_object == "current-comm":
    if selected_object != "memory:native-ebpf-object":
        missing.append("native_object.current_comm_selected")
    if core_enabled is not False or core_status != "fallback_to_current_comm":
        missing.append("native_object.current_comm_fallback")
elif selected_object == "memory:native-ebpf-object-pname-core":
    if core_enabled is not True or core_status != "enhanced_load_succeeded":
        missing.append("native_object.auto_pname_core_consistency")
elif core_enabled is not False or core_status != "fallback_to_current_comm":
    missing.append("native_object.auto_current_comm_consistency")

evidence = {
    "manifest": manifest,
    "scope": owner.get("production_runtime_owner_scope"),
    "production_dataplane_admitted": owner.get("production_dataplane_admitted"),
    "reload_runtime_parity_admitted": owner.get("reload_runtime_parity_admitted"),
    "active_tcp_relay_benchmark": (owner.get("active_tcp") or {}).get("relay_benchmark"),
    "active_udp_benchmark": (owner.get("active_udp") or {}).get("benchmark"),
    "active_dns_benchmark": (owner.get("active_dns") or {}).get("benchmark"),
    "netns_link": {
        "expected": expected_netns_link,
        "topology_values": owner.get("topology_values"),
        "selection_steps": [
            {
                "name": step.get("name"),
                "status": step.get("status"),
                "requested": step.get("requested"),
                "selected": step.get("selected"),
                "backend_switch_used": step.get("backend_switch_used"),
            }
            for step in owner.get("executed_steps", [])
            if step.get("name") in {
                "select-production-netns-link-mode",
                "select-active-tcp-netns-link-mode",
            }
        ],
    },
    "native_object": native_object,
    "native_steps": [
        {
            "name": step.get("name"),
            "status": step.get("status"),
            "backend": step.get("backend"),
            "accepted_backends": sorted(accepted_backends),
            "role": step.get("role"),
            "backend_switch_used": step.get("backend_switch_used"),
            "iface": (step.get("native_attach") or {}).get("iface"),
            "netns": (step.get("native_attach") or {}).get("netns"),
        }
        for step in native_steps
    ],
    "cleanup_failures": cleanup_failures,
}
print(json.dumps(evidence, indent=2, ensure_ascii=False))

if missing:
    print("native eBPF runtime gate missing required evidence:", file=sys.stderr)
    for key in missing:
        print(f"- {key}", file=sys.stderr)
    sys.exit(1)
PY

netns_leftovers="$(ip netns list 2>&1 | grep -E 'daens|dae50|dae-native|dae-aya' || true)"
link_leftovers="$(ip -d link show 2>&1 | grep -E 'dae0|dae50|dae-native|dae-aya' || true)"
bpf_leftovers="$(find /sys/fs/bpf -maxdepth 2 \( -name 'dae-native-runtime-*' -o -name 'dae-aya-*' \) 2>&1 || true)"

if [[ -n "$netns_leftovers" || -n "$link_leftovers" || -n "$bpf_leftovers" ]]; then
  echo "native eBPF runtime gate left temporary resources" >&2
  printf '%s\n%s\n%s\n' "$netns_leftovers" "$link_leftovers" "$bpf_leftovers" | head -c 20000 >&2
  exit 1
fi

echo "cleanup check passed: no daens/dae50/dae-native/dae-aya netns, links, or bpffs leftovers"
echo "native eBPF runtime gate passed"
