use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage161_temporary_ebpf_map_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage161Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let smoke = if opts.execute_smoke {
        Some(run_stage161_smoke())
    } else {
        None
    };
    RunnerOutput::ok(format!("{}\n", stage161_report(smoke)))
}

#[derive(Debug, Clone, Copy)]
struct Stage161Options {
    execute_smoke: bool,
}

impl Stage161Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
        };
        for arg in args {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage161 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn run_stage161_smoke() -> Result<Value, String> {
    let pin_root = dae_ebpf_support::default_bpffs_mount()
        .map_err(|err| format!("bpffs unavailable: {err}"))?;
    let pin_name = format!("dae-stage161-{}-temporary-map", std::process::id());
    let smoke = dae_ebpf_support::run_temporary_array_map_pin_smoke(&pin_root, &pin_name)
        .map_err(|err| format!("temporary BPF map smoke failed: {err}"))?;
    Ok(json!({
        "pin_root": pin_root.display().to_string(),
        "pin_path": smoke.pin_path.display().to_string(),
        "map_type": smoke.map_type,
        "map_name": smoke.map_name,
        "key_size": smoke.key_size,
        "value_size": smoke.value_size,
        "max_entries": smoke.max_entries,
        "key_written": smoke.key_written,
        "value_written": smoke.value_written,
        "value_read": smoke.value_read,
        "map_fd_reopened": smoke.map_fd_reopened,
        "pin_removed": smoke.pin_removed
    }))
}

fn stage161_report(smoke: Option<Result<Value, String>>) -> Value {
    let execute_smoke = smoke.is_some();
    let (smoke_passed, smoke_value, smoke_error) = match smoke {
        Some(Ok(value)) => (true, Some(value), None),
        Some(Err(err)) => (false, None, Some(err)),
        None => (false, None, None),
    };
    let mut blockers = vec![
        "temporary tc/program attach smoke is not executed in Stage161",
        "production listener binding and eBPF attach remain closed",
        "matched Go/Rust default daemon benchmark remains blocked",
        "default daemon and product-chain switches remain closed",
    ];
    if smoke_error.is_some() {
        blockers.insert(
            0,
            "temporary BPF map create/pin smoke failed in the current environment",
        );
    }

    let mut report = json!({
        "name": "stage161-temporary-ebpf-map-preflight-gate",
        "stage": "stage161",
        "prior_gate": "stage160-isolated-listener-ebpf-preflight-harness-gate",
        "evidence_class": "opt-in-temporary-ebpf-map-create-pin-cleanup-preflight-gate",
        "execute_smoke": execute_smoke,
        "read_only": !execute_smoke,
        "blocked": true,
        "blockers": blockers
    });
    for key in [
        "temporary_ebpf_map_preflight_harness_available",
        "bpffs_pin_root_discovery_available",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "temporary_ebpf_map_create_smoke_passed",
        "temporary_ebpf_map_update_lookup_smoke_passed",
        "temporary_ebpf_pin_reopen_smoke_passed",
        "temporary_ebpf_pin_cleanup_smoke_passed",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "temporary_ebpf_attach_smoke_passed",
        "production_listener_bound",
        "isolated_namespace_listener_smoke_passed",
        "ebpf_attached",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["preflight_rows"] = json!([
        {
            "area": "BPF map create",
            "status": if smoke_passed { "passed-opt-in-smoke" } else if execute_smoke { "blocked-by-environment-or-syscall" } else { "harness-available-not-executed" },
            "evidence": "create a temporary Array map through the bpf syscall with key_size=4 value_size=4 max_entries=1",
            "boundary": "does not load a program or attach tc hooks",
            "closed_flag": "temporary_ebpf_attach_smoke_passed=false"
        },
        {
            "area": "BPF map update/lookup",
            "status": if smoke_passed { "passed-roundtrip" } else if execute_smoke { "not-passed" } else { "not-executed" },
            "evidence": "write key 0 value 161 and read it back from the temporary map",
            "boundary": "array map roundtrip does not prove dae map schema parity",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "BPF pin/reopen cleanup",
            "status": if smoke_passed { "pinned-reopened-cleaned" } else if execute_smoke { "not-passed" } else { "not-executed" },
            "evidence": "pin under discovered bpffs as dae-stage161-* file, reopen with BPF_OBJ_GET, then unlink",
            "boundary": "temporary bpffs file is not a production pinned dae map",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "no production listener, no tc attach, no default daemon switch, no product-chain switch",
            "boundary": "Stage161 is eBPF map syscall preflight only",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["remaining_blockers"] = json!([
        "temporary eBPF program/tc attach smoke remains closed",
        "production listener binding remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage162",
            "target": "temporary eBPF program attach preflight",
            "required_output": "use temporary program/map paths and cleanup to prove attach/eject behavior without touching production tc hooks"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage161/temporary_ebpf_map_preflight_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage161_temporary_ebpf_map_preflight_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage161-temporary-ebpf-map-preflight-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage161-temporary-ebpf-map-preflight-gate --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage161 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage161 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage160 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-ebpf-support -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage161",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage160",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-ebpf-support/src/temporary_map.rs"
    ]);
    if let Some(value) = smoke_value {
        report["smoke"] = value;
    }
    if let Some(err) = smoke_error {
        report["smoke_error"] = json!(err);
    }
    report
}
