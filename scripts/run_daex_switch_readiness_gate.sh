#!/usr/bin/env bash
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Read-only DAEX switch readiness admission gate.
# This does not switch defaults or write host service/binary targets.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "$(id -u)" != "0" ]]; then
  echo "DAEX switch readiness gate requires root for native eBPF runtime evidence and matched daemon benchmark" >&2
  exit 2
fi

run_id="${RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
gate_root="${GATE_ROOT:-/tmp/dae-daex-switch-readiness-gate-${run_id}}"
config_file_explicit=0
if [[ -n "${CONFIG_FILE:-}" ]]; then
  config_file_explicit=1
fi
config_file="${CONFIG_FILE:-${gate_root}/example.dae}"
candidate_binary="${CANDIDATE_BINARY:-${repo_root}/rust/target/debug/dae-daemon-optin}"
go_tool="${GO_TOOL:-/root/.local/go1.25.9/bin/go}"
native_run_root="${NATIVE_RUN_ROOT:-/tmp/dae-daemon-native-ebpf-runtime-gate-${run_id}}"
native_config_file="${NATIVE_CONFIG_FILE:-${gate_root}/native-runtime.dae}"
native_object="${NATIVE_OBJECT:-${gate_root}/dae-native-bpf_bpfel.o}"
native_log="${NATIVE_LOG:-${gate_root}/native-ebpf-runtime.log}"
cgroup_log="${CGROUP_LOG:-${gate_root}/native-ebpf-cgroup.log}"
matched_run_root="${MATCHED_RUN_ROOT:-/tmp/dae-daemon-daex-switch-matched-${run_id}}"
matched_log="${MATCHED_LOG:-${gate_root}/matched-default-benchmark.log}"
product_run_root="${PRODUCT_RUN_ROOT:-/tmp/dae-daemon-daex-switch-product-${run_id}}"
product_log="${PRODUCT_LOG:-${gate_root}/product-chain-recertification.log}"
admission_file="${ADMISSION_FILE:-${gate_root}/product-chain-admission-evidence.json}"
summary_file="${SUMMARY_FILE:-${gate_root}/daex-switch-readiness.json}"
matched_iterations="${MATCHED_BENCHMARK_ITERATIONS:-10}"
matched_ready_timeout_ms="${MATCHED_READY_TIMEOUT_MS:-15000}"
backend="${DAE_NATIVE_EBPF_BACKEND:-tc-netlink}"

case "$gate_root" in
  /tmp/dae-daex-switch-readiness-gate*) ;;
  *)
    echo "refusing unsafe GATE_ROOT outside /tmp/dae-daex-switch-readiness-gate*: $gate_root" >&2
    exit 2
    ;;
esac

rm -rf "$gate_root"
mkdir -p "$gate_root"

if [[ ! -x "$go_tool" ]]; then
  echo "matched benchmark requires an executable Go tool compatible with /root/project/go.work: $go_tool" >&2
  echo "set GO_TOOL to a Go 1.24+ binary" >&2
  exit 2
fi

if [[ "$config_file_explicit" == "1" ]]; then
  if [[ ! -f "$config_file" ]]; then
    echo "explicit CONFIG_FILE does not exist: $config_file" >&2
    exit 2
  fi
else
  cat > "$config_file" <<'EOF'
global {
  log_level: info
}

routing {
  pname(NetworkManager, systemd-resolved, dnsmasq) -> must_direct
}
EOF
  chmod 0600 "$config_file"
fi

echo "building DAEX native-capable candidate: $candidate_binary"
cargo build --manifest-path rust/Cargo.toml \
  -p dae-daemon \
  --features native-ebpf \
  --bin dae-daemon-optin

echo "running native Aya/eBPF runtime gate"
if ! RUN_ID="$run_id" \
  RUN_ROOT="$native_run_root" \
  CONFIG_FILE="$native_config_file" \
  NATIVE_OBJECT="$native_object" \
  CARGO_LOG="$native_log" \
  CGROUP_LOG="$cgroup_log" \
  DAE_NATIVE_EBPF_BACKEND="$backend" \
  ./scripts/run_native_ebpf_runtime_gate.sh >"${gate_root}/native-ebpf-runtime-gate.stdout" 2>"${gate_root}/native-ebpf-runtime-gate.stderr"; then
  echo "native Aya/eBPF runtime gate failed" >&2
  tail -c 20000 "${gate_root}/native-ebpf-runtime-gate.stderr" >&2 || true
  tail -c 20000 "${gate_root}/native-ebpf-runtime-gate.stdout" >&2 || true
  exit 1
fi
native_manifest="${native_run_root}/run/dae-daemon-optin-run.json"

echo "running matched Go/Rust default daemon benchmark: iterations=$matched_iterations"
if ! "$candidate_binary" run \
  --config "$config_file" \
  --root "$matched_run_root" \
  --disable-timestamp \
  --disable-sudo \
  --execute-matched-default-benchmark \
  --matched-benchmark-iterations "$matched_iterations" \
  --matched-ready-timeout-ms "$matched_ready_timeout_ms" \
  --ack-root-gate \
  --go-tool "$go_tool" \
  --rust-binary "$candidate_binary" \
  --source-dir "$repo_root" \
  --exit-after-ready >"$matched_log" 2>&1; then
  echo "matched Go/Rust default daemon benchmark failed; tail follows" >&2
  tail -c 20000 "$matched_log" >&2 || true
  exit 1
fi
matched_manifest="${matched_run_root}/run/dae-daemon-optin-run.json"

echo "materializing combined product-chain admission evidence"
python3 - "$native_manifest" "$matched_manifest" "$admission_file" <<'PY'
import json
import sys

native_manifest, matched_manifest, admission_file = sys.argv[1:4]
with open(native_manifest, "r", encoding="utf-8") as fh:
    native_root = json.load(fh)
with open(matched_manifest, "r", encoding="utf-8") as fh:
    matched_root = json.load(fh)
owner = native_root.get("production_runtime_owner", {})
matched = matched_root.get("matched_default_benchmark", {})
production_dataplane_admitted = owner.get("production_dataplane_admitted") is True
reload_runtime_parity_admitted = owner.get("reload_runtime_parity_admitted") is True
matched_recorded = matched.get("matched_go_rust_default_daemon_benchmark_recorded") is True
admission = {
    "production_dataplane_admitted": production_dataplane_admitted,
    "reload_runtime_parity_admitted": reload_runtime_parity_admitted,
    "matched_go_rust_default_daemon_benchmark_recorded": matched_recorded,
    "true_rust_default_daemon_admitted": (
        production_dataplane_admitted
        and reload_runtime_parity_admitted
        and matched_recorded
    ),
    "native_ebpf_runtime_gate_manifest": native_manifest,
    "matched_default_benchmark_manifest": matched_manifest,
    "evidence_class": "daex-switch-readiness-combined-admission-v1",
}
with open(admission_file, "w", encoding="utf-8") as fh:
    json.dump(admission, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
if not admission["true_rust_default_daemon_admitted"]:
    print("combined admission evidence is incomplete", file=sys.stderr)
    print(json.dumps(admission, indent=2, ensure_ascii=False), file=sys.stderr)
    sys.exit(1)
PY

echo "running daed2.0 product-chain recertification in read-only switch-readiness mode"
if ! "$candidate_binary" run \
  --config "$config_file" \
  --root "$product_run_root" \
  --disable-timestamp \
  --disable-sudo \
  --no-listener-smoke \
  --no-reload-smoke \
  --execute-product-chain-recertification \
  --product-chain-admission-evidence "$admission_file" \
  --request-default-path-mutation \
  --plan-production-run-command-replacement \
  --execute-production-run-command-replacement \
  --plan-production-run-command-apply \
  --allow-host-default-path-mutation \
  --product-chain-resident-default-daemon-binary-source "$candidate_binary" \
  --product-chain-fresh-install-binary-source "$candidate_binary" \
  --product-chain-dae-repo "$repo_root" \
  --product-chain-dae-wing-repo /root/project/daed/wing \
  --product-chain-daed-repo /root/project/daed \
  --product-chain-outbound-repo /root/project/outbound \
  --product-chain-quic-go-repo /root/project/quic-go \
  --product-chain-service-file install/dae.service \
  --product-chain-go-mod-file go.mod \
  --ack-root-gate \
  --exit-after-ready >"$product_log" 2>&1; then
  echo "daed2.0 product-chain recertification failed; tail follows" >&2
  tail -c 20000 "$product_log" >&2 || true
  exit 1
fi
product_manifest="${product_run_root}/run/dae-daemon-optin-run.json"

echo "writing DAEX switch readiness summary: $summary_file"
python3 - "$native_manifest" "$matched_manifest" "$product_manifest" "$admission_file" "$summary_file" "$gate_root" <<'PY'
import json
import sys

native_manifest, matched_manifest, product_manifest, admission_file, summary_file, gate_root = sys.argv[1:7]

def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

native_root = load(native_manifest)
matched_root = load(matched_manifest)
product_root = load(product_manifest)
admission = load(admission_file)
owner = native_root.get("production_runtime_owner", {})
matched = matched_root.get("matched_default_benchmark", {})
product = product_root.get("product_chain_recertification", {})
readiness = product.get("production_replacement_readiness", {})
rehearsal = product.get("daed2_product_chain_switch_rehearsal", {})
freeze = product.get("production_host_write_plan_freeze", {})

native_steps = [
    step for step in owner.get("executed_steps", [])
    if step.get("name") in {
        "attach-production-dae0peer-native-ebpf-program",
        "attach-lan-ingress-native-ebpf-program",
        "attach-production-dae0-native-ebpf-program",
    }
]
native_gate_passed = (
    owner.get("production_dataplane_admitted") is True
    and owner.get("reload_runtime_parity_admitted") is True
    and len(native_steps) == 3
    and all(step.get("status") == "pass" for step in native_steps)
    and all(step.get("fallback_used") is False for step in native_steps)
)
matched_recorded = matched.get("matched_go_rust_default_daemon_benchmark_recorded") is True
product_chain_clean = product.get("product_chain_recertification_clean") is True
product_switch_allowed = product.get("product_chain_switch_allowed") is True
readiness_passed = readiness.get("ready_for_manual_authorization") is True
rehearsal_passed = rehearsal.get("pass") is True
host_freeze_passed = freeze.get("pass") is True
core_switch_readiness_passed = (
    native_gate_passed
    and matched_recorded
    and admission.get("true_rust_default_daemon_admitted") is True
    and product_chain_clean
    and product_switch_allowed
    and readiness_passed
    and rehearsal_passed
)
summary = {
    "name": "daex-switch-readiness-gate",
    "schema": "daex-switch-readiness-gate-v1",
    "status": "pass" if core_switch_readiness_passed else "blocked",
    "core_switch_readiness_passed": core_switch_readiness_passed,
    "ready_for_manual_switch_authorization": core_switch_readiness_passed,
    "host_write_allowed": False,
    "host_write_executed": False,
    "default_path_mutation_executed": False,
    "production_run_command_replaced": False,
    "manual_authorization_required": True,
    "local_host_write_plan_freeze_passed": host_freeze_passed,
    "local_host_write_plan_freeze_required_for_this_gate": False,
    "checks": {
        "native_ebpf_runtime_gate_passed": native_gate_passed,
        "matched_go_rust_default_daemon_benchmark_recorded": matched_recorded,
        "true_rust_default_daemon_admitted": admission.get("true_rust_default_daemon_admitted") is True,
        "product_chain_recertification_clean": product_chain_clean,
        "product_chain_switch_allowed": product_switch_allowed,
        "production_replacement_ready_for_manual_authorization": readiness_passed,
        "daed2_product_chain_switch_rehearsal_passed": rehearsal_passed,
        "local_host_write_plan_freeze_passed": host_freeze_passed,
        "go_fallback_required": product.get("go_fallback_required") is True,
        "go_default_path_preserved": product.get("go_default_path_preserved") is True,
    },
    "blockers": [],
    "artifacts": {
        "gate_root": gate_root,
        "native_manifest": native_manifest,
        "matched_manifest": matched_manifest,
        "product_manifest": product_manifest,
        "admission_file": admission_file,
        "product_chain_manifest": product.get("manifest_file"),
        "production_replacement_readiness_file": product.get("production_replacement_readiness_file"),
        "daed2_product_chain_switch_rehearsal_file": product.get("daed2_product_chain_switch_rehearsal_file"),
        "production_host_write_plan_freeze_file": product.get("production_host_write_plan_freeze_file"),
    },
    "native_evidence": {
        "scope": owner.get("production_runtime_owner_scope"),
        "active_tcp_relay_benchmark": (owner.get("active_tcp") or {}).get("relay_benchmark"),
        "active_udp_benchmark": (owner.get("active_udp") or {}).get("benchmark"),
        "active_dns_benchmark": (owner.get("active_dns") or {}).get("benchmark"),
        "native_steps": [
            {
                "name": step.get("name"),
                "status": step.get("status"),
                "backend": step.get("backend"),
                "role": step.get("role"),
                "fallback_used": step.get("fallback_used"),
                "iface": (step.get("native_attach") or {}).get("iface"),
                "netns": (step.get("native_attach") or {}).get("netns"),
            }
            for step in native_steps
        ],
    },
    "matched_benchmark_aggregate": matched.get("aggregate"),
    "product_chain_blockers": product.get("remaining_blockers", []),
    "production_replacement_blockers": readiness.get("readiness_blockers", []),
    "daed2_rehearsal_blockers": rehearsal.get("blockers", []),
    "local_host_write_plan_freeze_blockers": freeze.get("blockers", []),
    "source": [
        "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:Aya/BPF switch-readiness",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:default-path-service-runtime-contract",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:daed2-runtime-control-api",
    ],
}
for key, passed in summary["checks"].items():
    if key == "local_host_write_plan_freeze_passed":
        continue
    if passed is not True:
        summary["blockers"].append(key)
if not core_switch_readiness_passed:
    for bucket in [
        "product_chain_blockers",
        "production_replacement_blockers",
        "daed2_rehearsal_blockers",
    ]:
        for item in summary.get(bucket, []):
            if item not in summary["blockers"]:
                summary["blockers"].append(item)
with open(summary_file, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print(json.dumps(summary, indent=2, ensure_ascii=False))
if not core_switch_readiness_passed:
    sys.exit(1)
PY

echo "DAEX switch readiness gate passed"
