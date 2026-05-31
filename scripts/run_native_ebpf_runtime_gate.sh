#!/usr/bin/env bash
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Root-gated local validation for the explicit native Aya eBPF runtime path.
# This does not switch defaults; it only exercises the opt-in native backend.

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
native_object="${NATIVE_OBJECT:-/tmp/dae-native-bpf_bpfel.o}"
rust_native_object="${RUST_NATIVE_OBJECT:-rust/target/bpfel-unknown-none/release/libdae_ebpf_program.so}"
cargo_log="${CARGO_LOG:-/tmp/dae-native-ebpf-runtime-gate-${run_id}.log}"
cgroup_log="${CGROUP_LOG:-/tmp/dae-native-ebpf-cgroup-gate-${run_id}.log}"
backend="${DAE_NATIVE_EBPF_BACKEND:-auto}"
netns_link="${DAE_NETNS_LINK:-auto}"
runtime_timeout="${RUNTIME_TIMEOUT:-180s}"
fallback_retirement_product_chain_recertified="${DAE_BPF_FALLBACK_RETIREMENT_PRODUCT_CHAIN_RECERTIFIED:-0}"
fallback_retirement_explicit_approval="${DAE_BPF_FALLBACK_RETIREMENT_EXPLICIT_APPROVAL:-0}"

case "$run_root" in
  /tmp/dae-daemon-native-ebpf-runtime-gate*) ;;
  *)
    echo "refusing unsafe RUN_ROOT outside /tmp/dae-daemon-native-ebpf-runtime-gate*: $run_root" >&2
    exit 2
    ;;
esac

printf 'global {\n  log_level: info\n}\n' > "$config_file"
rm -rf "$run_root"
mkdir -p "$run_root"

echo "building native Aya classifier object: $native_object"
echo "native object source: rust/crates/dae-ebpf-program"
cargo +nightly build -Z build-std=core --manifest-path rust/Cargo.toml \
  -p dae-ebpf-program \
  --target bpfel-unknown-none \
  --release
if [[ ! -f "$rust_native_object" ]]; then
  echo "missing Rust native eBPF object after build: $rust_native_object" >&2
  exit 1
fi
mkdir -p "$(dirname "$native_object")"
rust_native_object_real="$(readlink -f "$rust_native_object")"
native_object_real="$(readlink -m "$native_object")"
if [[ "$rust_native_object_real" != "$native_object_real" ]]; then
  cp "$rust_native_object" "$native_object"
fi
chmod 0644 "$native_object"
native_object_symbols="$(llvm-readelf -s "$native_object" 2>/dev/null || true)"
if ! grep -q ' PARAM$' <<<"$native_object_symbols"; then
  echo "Rust native eBPF object does not expose expected PARAM symbol: $native_object" >&2
  exit 1
fi

echo "running Aya cgroup attach/detach gate"
if ! DAE_RUN_AYA_CGROUP_ATTACH_SMOKE=1 cargo test --manifest-path rust/Cargo.toml \
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

echo "running native eBPF runtime gate: root=$run_root backend=$backend netns_link=$netns_link timeout=$runtime_timeout"
fallback_retirement_args=()
case "$fallback_retirement_product_chain_recertified" in
  1 | true | TRUE | on | ON | yes | YES)
    fallback_retirement_args+=(--production-runtime-fallback-retirement-product-chain-recertified)
    ;;
esac
case "$fallback_retirement_explicit_approval" in
  1 | true | TRUE | on | ON | yes | YES)
    fallback_retirement_args+=(--production-runtime-fallback-retirement-explicit-approval)
    ;;
esac

if ! DAE_RUST_NATIVE_BPF_OBJECT="$native_object" timeout "$runtime_timeout" cargo run --manifest-path rust/Cargo.toml \
  -p dae-daemon \
  --features native-ebpf \
  --bin dae-daemon-optin \
  -- run \
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
  --production-runtime-native-ebpf-completed-a3-local \
  --production-runtime-native-ebpf-backend "$backend" \
  --production-runtime-netns-link "$netns_link" \
  --production-runtime-native-ebpf-object "$native_object" \
  "${fallback_retirement_args[@]}" \
  --exit-after-ready >"$cargo_log" 2>&1; then
  echo "native eBPF runtime gate failed; tail of cargo log follows" >&2
  tail -c 20000 "$cargo_log" >&2 || true
  exit 1
fi

manifest="$run_root/run/dae-daemon-optin-run.json"
if [[ ! -f "$manifest" ]]; then
  echo "missing run manifest: $manifest" >&2
  tail -c 20000 "$cargo_log" >&2 || true
  exit 1
fi

python3 - "$manifest" "$backend" "$netns_link" <<'PY'
import json
import sys

manifest, expected_backend_raw, expected_netns_link_raw = sys.argv[1:4]
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
    "invalid_config_rollback_verified",
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
    if step.get("fallback_used") is not False:
        missing.append(f"{step.get('name')}.fallback_used")
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
                "fallback_used": step.get("fallback_used"),
            }
            for step in owner.get("executed_steps", [])
            if step.get("name") in {
                "select-production-netns-link-mode",
                "select-active-tcp-netns-link-mode",
            }
        ],
    },
    "native_steps": [
        {
            "name": step.get("name"),
            "status": step.get("status"),
            "backend": step.get("backend"),
            "accepted_backends": sorted(accepted_backends),
            "role": step.get("role"),
            "fallback_used": step.get("fallback_used"),
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
