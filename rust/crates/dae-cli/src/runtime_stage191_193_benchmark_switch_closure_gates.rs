use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum StageMode<'a> {
    ReadOnly,
    Write { root: &'a str, prior_root: &'a str },
}

pub(crate) fn run_stage191_bounded_same_corpus_benchmark_admission_input_gate(
    args: &[String],
) -> RunnerOutput {
    match parse_args(
        args,
        "stage191",
        "--write-admission-input",
        "--stage190-root",
    ) {
        Ok(StageMode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage191_report(None))),
        Ok(StageMode::Write { root, prior_root }) => {
            match write_stage191_admission_input(root, prior_root) {
                Ok(result) => RunnerOutput::ok(format!("{}\n", stage191_report(Some(result)))),
                Err(err) => RunnerOutput::stdout_error(err),
            }
        }
        Err(err) => RunnerOutput::usage(err),
    }
}

pub(crate) fn run_stage192_default_product_switch_recertification_input_gate(
    args: &[String],
) -> RunnerOutput {
    match parse_args(
        args,
        "stage192",
        "--write-recertification-input",
        "--stage191-root",
    ) {
        Ok(StageMode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage192_report(None))),
        Ok(StageMode::Write { root, prior_root }) => {
            match write_stage192_recertification_input(root, prior_root) {
                Ok(result) => RunnerOutput::ok(format!("{}\n", stage192_report(Some(result)))),
                Err(err) => RunnerOutput::stdout_error(err),
            }
        }
        Err(err) => RunnerOutput::usage(err),
    }
}

pub(crate) fn run_stage193_default_product_switch_hard_gate_closure(
    args: &[String],
) -> RunnerOutput {
    match parse_args(
        args,
        "stage193",
        "--write-hard-gate-closure",
        "--stage192-root",
    ) {
        Ok(StageMode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage193_report(None))),
        Ok(StageMode::Write { root, prior_root }) => {
            match write_stage193_hard_gate_closure(root, prior_root) {
                Ok(result) => RunnerOutput::ok(format!("{}\n", stage193_report(Some(result)))),
                Err(err) => RunnerOutput::stdout_error(err),
            }
        }
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_args<'a>(
    args: &'a [String],
    stage: &str,
    write_flag: &str,
    prior_arg: &str,
) -> Result<StageMode<'a>, String> {
    let mut write = false;
    let mut root = None;
    let mut prior_root = None;
    let prior_arg_eq = format!("{prior_arg}=");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            flag if flag == write_flag => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err(format!("{stage} --root requires a value"));
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            value if value == prior_arg => {
                let Some(next) = iter.next() else {
                    return Err(format!("{stage} {prior_arg} requires a value"));
                };
                prior_root = Some(next.as_str());
            }
            _ if arg.starts_with(&prior_arg_eq) => {
                prior_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported {stage} argument: {arg}")),
        }
    }
    match (write, root, prior_root) {
        (false, None, None) => Ok(StageMode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err(format!("{stage} --root/{prior_arg} require {write_flag}"))
        }
        (true, Some(root), Some(prior_root)) => Ok(StageMode::Write { root, prior_root }),
        (true, None, _) => Err(format!("{stage} {write_flag} requires --root")),
        (true, _, None) => Err(format!("{stage} {write_flag} requires {prior_arg}")),
    }
}

fn stage191_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage191-bounded-same-corpus-benchmark-admission-input-gate",
        "stage": "stage191",
        "prior_gate": "stage190-live-reload-runtime-parity-execution-evidence-gate",
        "evidence_class": "explicit-temp-root-bounded-benchmark-admission-input-blocker",
        "read_only": !written,
        "write_admission_input": written,
        "artifact_root_policy": "explicit /tmp/dae-stage191* root only",
        "stage190_root_policy": "explicit /tmp/dae-stage190* root containing Stage190 live reload/runtime parity gap bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "bounded_same_corpus_benchmark_admission_input_gate_available",
        "stage190_reload_runtime_bundle_required",
        "stage190_bundle_verifier_available",
        "production_dataplane_blocker_available",
        "reload_runtime_parity_blocker_available",
        "matched_benchmark_command_blocker_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage190_reload_runtime_bundle_verified",
        "production_dataplane_blocker_written",
        "reload_runtime_parity_blocker_written",
        "matched_benchmark_command_blocker_written",
        "stage192_default_product_switch_input_written",
    ] {
        report[key] = json!(written);
    }
    add_closed_runtime_flags(&mut report);
    report["stage190_required_files"] = json!(stage190_files());
    report["stage191_expected_files"] = json!(stage191_files());
    report["benchmark_admission_rows"] = stage191_rows(written);
    report["gate_summary"] = stage191_gates();
    report["gate_decision"] = json!(
        "Stage191 verifies the explicit Stage190 reload/runtime parity gap bundle and records bounded benchmark admission blockers. It does not execute a matched Go/Rust default daemon benchmark or switch default/product paths"
    );
    report["remaining_blockers"] = json!(stage191_blockers());
    report["next_admission_queue"] = json!([
        {
            "stage": "stage192",
            "target": "default/product switch recertification input",
            "required_output": "default switch remains blocked until matched benchmark data exists and production dataplane plus reload/runtime parity are admitted"
        }
    ]);
    report["validation_commands"] = json!(stage191_validation_commands());
    report["source"] = json!(stage191_source());
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn stage192_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage192-default-product-switch-recertification-input-gate",
        "stage": "stage192",
        "prior_gate": "stage191-bounded-same-corpus-benchmark-admission-input-gate",
        "evidence_class": "explicit-temp-root-default-product-switch-recertification-input-blocker",
        "read_only": !written,
        "write_recertification_input": written,
        "artifact_root_policy": "explicit /tmp/dae-stage192* root only",
        "stage191_root_policy": "explicit /tmp/dae-stage191* root containing Stage191 benchmark admission blocker bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "default_product_switch_recertification_input_gate_available",
        "stage191_benchmark_admission_bundle_required",
        "stage191_bundle_verifier_available",
        "default_daemon_switch_blocker_available",
        "product_chain_switch_blocker_available",
        "rollback_recertification_gap_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage191_benchmark_admission_bundle_verified",
        "default_daemon_switch_blocker_written",
        "product_chain_switch_blocker_written",
        "rollback_recertification_gap_written",
        "stage193_hard_gate_input_written",
    ] {
        report[key] = json!(written);
    }
    add_closed_runtime_flags(&mut report);
    report["stage191_required_files"] = json!(stage191_files());
    report["stage192_expected_files"] = json!(stage192_files());
    report["switch_recertification_rows"] = stage192_rows(written);
    report["gate_summary"] = stage192_gates();
    report["gate_decision"] = json!(
        "Stage192 verifies the explicit Stage191 benchmark admission blocker bundle and records default/product switch recertification blockers. It does not execute benchmark data review, mutate default path, or admit product-chain switch"
    );
    report["remaining_blockers"] = json!(stage192_blockers());
    report["next_admission_queue"] = json!([
        {
            "stage": "stage193",
            "target": "default/product switch hard-gate closure",
            "required_output": "keep default/product switch closed and point the next implementation work back to true production execution evidence"
        }
    ]);
    report["validation_commands"] = json!(stage192_validation_commands());
    report["source"] = json!(stage192_source());
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn stage193_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage193-default-product-switch-hard-gate-closure",
        "stage": "stage193",
        "prior_gate": "stage192-default-product-switch-recertification-input-gate",
        "evidence_class": "explicit-temp-root-default-product-switch-hard-gate-closure",
        "read_only": !written,
        "write_hard_gate_closure": written,
        "artifact_root_policy": "explicit /tmp/dae-stage193* root only",
        "stage192_root_policy": "explicit /tmp/dae-stage192* root containing Stage192 switch recertification blocker bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "default_product_switch_hard_gate_closure_available",
        "stage192_recertification_bundle_required",
        "stage192_bundle_verifier_available",
        "default_switch_hard_gate_summary_available",
        "product_chain_hard_gate_summary_available",
        "benchmark_dataplane_reload_blocker_summary_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage192_recertification_bundle_verified",
        "default_switch_hard_gate_summary_written",
        "product_chain_hard_gate_summary_written",
        "benchmark_dataplane_reload_blocker_summary_written",
        "stage194_true_production_execution_input_written",
    ] {
        report[key] = json!(written);
    }
    add_closed_runtime_flags(&mut report);
    report["stage192_required_files"] = json!(stage192_files());
    report["stage193_expected_files"] = json!(stage193_files());
    report["hard_gate_closure_rows"] = stage193_rows(written);
    report["gate_summary"] = stage193_gates();
    report["gate_decision"] = json!(
        "Stage193 verifies the explicit Stage192 switch recertification bundle and closes default/product switch hard gates until true production dataplane, live reload/runtime parity, and matched benchmark evidence exist"
    );
    report["remaining_blockers"] = json!(stage193_blockers());
    report["next_admission_queue"] = json!([
        {
            "stage": "stage194",
            "target": "true production execution implementation input",
            "required_output": "implement or execute real production listener/sockmap/tc/eBPF/netns/reload evidence before any benchmark/default admission"
        }
    ]);
    report["validation_commands"] = json!(stage193_validation_commands());
    report["source"] = json!(stage193_source());
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn add_closed_runtime_flags(report: &mut Value) {
    for key in [
        "hard_gates_resolved",
        "rust_production_dae_run_command_admitted",
        "production_listener_bound",
        "listen_socket_map_written",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "netns_setup_executed",
        "dae0_attach_executed",
        "bpf_owner_handoff_executed",
        "production_dataplane_admitted",
        "live_reload_executed",
        "production_listener_reused",
        "production_bpf_owner_transferred",
        "production_dns_cache_migrated",
        "dns_cache_migration_guard_verified",
        "bounded_close_verified",
        "runtime_overview_parity_verified",
        "reload_scoped_resources_flushed",
        "reload_runtime_parity_admitted",
        "benchmark_readiness_admitted",
        "bounded_benchmark_executed",
        "default_path_mutation_allowed",
    ] {
        report[key] = json!(false);
    }
}

fn write_stage191_admission_input(root: &str, stage190_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage190_path = Path::new(stage190_root);
    validate_root(root_path, "stage191")?;
    validate_root(stage190_path, "stage190")?;
    ensure_new_root(root_path, "stage191")?;
    let verification = verify_stage190_bundle(stage190_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage191 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage190-reload-runtime-verification.json",
        &verification,
        "stage191",
    )?;
    write_json(
        root_path,
        "benchmark/production-dataplane-blocker.json",
        &json!({
            "stage": "stage191",
            "blocker": "production dataplane execution not admitted",
            "required_before_benchmark": [
                "production listener bind",
                "listen_socket_map key 0/1 writes",
                "tc/eBPF attach",
                "netns/dae0 setup",
                "BPF owner handoff"
            ],
            "production_dataplane_admitted": false,
            "benchmark_executable_now": false
        }),
        "stage191",
    )?;
    write_json(
        root_path,
        "benchmark/reload-runtime-parity-blocker.json",
        &json!({
            "stage": "stage191",
            "blocker": "live reload/runtime parity not admitted",
            "required_before_benchmark": [
                "listener reuse",
                "BPF owner transfer",
                "DNS cache migration guard",
                "bounded Close",
                "RuntimeOverview parity"
            ],
            "reload_runtime_parity_admitted": false,
            "benchmark_executable_now": false
        }),
        "stage191",
    )?;
    write_json(
        root_path,
        "benchmark/matched-benchmark-command-blocker.json",
        &json!({
            "stage": "stage191",
            "blocker": "same-corpus Go/Rust default daemon benchmark command remains blocked",
            "go_default_path_preserved": true,
            "matched_go_rust_default_daemon_benchmark_recorded": false,
            "benchmark_executable_now": false,
            "default_switch_allowed": false
        }),
        "stage191",
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": stage191_gates() }),
        "stage191",
    )?;
    write_json(
        root_path,
        "next/stage192-default-product-switch-recertification-input.json",
        &json!({
            "stage": "stage191",
            "next_stage": "stage192",
            "stage190_reload_runtime_bundle_verified": true,
            "bounded_benchmark_admission_input_written": true,
            "production_dataplane_admitted": false,
            "reload_runtime_parity_admitted": false,
            "benchmark_executable_now": false,
            "matched_go_rust_default_daemon_benchmark_recorded": false,
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false
        }),
        "stage191",
    )?;
    write_manifest(
        root_path,
        "stage191",
        "bounded-same-corpus-benchmark-admission-input-blocker",
        "stage190_root",
        stage190_path,
        stage191_files(),
        verification,
        json!({
            "production_dataplane_blocker_written": true,
            "reload_runtime_parity_blocker_written": true,
            "matched_benchmark_command_blocker_written": true,
            "stage192_default_product_switch_input_written": true
        }),
    )?;
    ensure_files(root_path, &stage191_files(), "stage191")?;

    Ok(json!({
        "root": path_string(root_path),
        "stage190_root": path_string(stage190_path),
        "expected_file_count": stage191_files().len(),
        "files_written_count": stage191_files().len(),
        "missing_files": [],
        "stage190_reload_runtime_bundle_verified": true,
        "production_dataplane_blocker_written": true,
        "reload_runtime_parity_blocker_written": true,
        "matched_benchmark_command_blocker_written": true,
        "stage192_default_product_switch_input_written": true,
        "matched_benchmark_gate": "admission_input_blocked",
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn write_stage192_recertification_input(root: &str, stage191_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage191_path = Path::new(stage191_root);
    validate_root(root_path, "stage192")?;
    validate_root(stage191_path, "stage191")?;
    ensure_new_root(root_path, "stage192")?;
    let verification = verify_stage191_bundle(stage191_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage192 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage191-benchmark-admission-verification.json",
        &verification,
        "stage192",
    )?;
    write_json(
        root_path,
        "switch/default-daemon-switch-blocker.json",
        &json!({
            "stage": "stage192",
            "blocker": "default daemon switch cannot open without matched benchmark evidence",
            "true_rust_default_daemon_admitted": false,
            "default_switch_allowed": false,
            "default_path_mutation_allowed": false
        }),
        "stage192",
    )?;
    write_json(
        root_path,
        "switch/product-chain-switch-blocker.json",
        &json!({
            "stage": "stage192",
            "blocker": "dae-wing/daed product-chain switch cannot open before default daemon and benchmark recertification",
            "product_chain_switch_allowed": false,
            "default_switch_allowed": false
        }),
        "stage192",
    )?;
    write_json(
        root_path,
        "switch/rollback-recertification-gap.json",
        &json!({
            "stage": "stage192",
            "gap": "default/product rollback recertification evidence missing",
            "required_before_switch": [
                "matched benchmark review",
                "default path rollback command",
                "product-chain smoke",
                "failure rollback evidence"
            ],
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false
        }),
        "stage192",
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": stage192_gates() }),
        "stage192",
    )?;
    write_json(
        root_path,
        "next/stage193-default-product-switch-hard-gate-input.json",
        &json!({
            "stage": "stage192",
            "next_stage": "stage193",
            "stage191_benchmark_admission_bundle_verified": true,
            "default_product_recertification_input_written": true,
            "benchmark_executable_now": false,
            "matched_go_rust_default_daemon_benchmark_recorded": false,
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false
        }),
        "stage192",
    )?;
    write_manifest(
        root_path,
        "stage192",
        "default-product-switch-recertification-input-blocker",
        "stage191_root",
        stage191_path,
        stage192_files(),
        verification,
        json!({
            "default_daemon_switch_blocker_written": true,
            "product_chain_switch_blocker_written": true,
            "rollback_recertification_gap_written": true,
            "stage193_hard_gate_input_written": true
        }),
    )?;
    ensure_files(root_path, &stage192_files(), "stage192")?;

    Ok(json!({
        "root": path_string(root_path),
        "stage191_root": path_string(stage191_path),
        "expected_file_count": stage192_files().len(),
        "files_written_count": stage192_files().len(),
        "missing_files": [],
        "stage191_benchmark_admission_bundle_verified": true,
        "default_daemon_switch_blocker_written": true,
        "product_chain_switch_blocker_written": true,
        "rollback_recertification_gap_written": true,
        "stage193_hard_gate_input_written": true,
        "default_product_switch_gate": "recertification_input_blocked",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    }))
}

fn write_stage193_hard_gate_closure(root: &str, stage192_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage192_path = Path::new(stage192_root);
    validate_root(root_path, "stage193")?;
    validate_root(stage192_path, "stage192")?;
    ensure_new_root(root_path, "stage193")?;
    let verification = verify_stage192_bundle(stage192_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage193 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage192-switch-recertification-verification.json",
        &verification,
        "stage193",
    )?;
    write_json(
        root_path,
        "closure/default-switch-hard-gate-summary.json",
        &json!({
            "stage": "stage193",
            "decision": "default switch remains hard-closed",
            "requires": [
                "production dataplane admitted",
                "reload/runtime parity admitted",
                "matched benchmark recorded",
                "default rollback recertified"
            ],
            "default_switch_allowed": false,
            "true_rust_default_daemon_admitted": false
        }),
        "stage193",
    )?;
    write_json(
        root_path,
        "closure/product-chain-hard-gate-summary.json",
        &json!({
            "stage": "stage193",
            "decision": "product-chain switch remains hard-closed",
            "requires": [
                "default daemon switch allowed",
                "dae-wing/daed smoke",
                "rollback evidence",
                "matched benchmark review"
            ],
            "product_chain_switch_allowed": false,
            "default_switch_allowed": false
        }),
        "stage193",
    )?;
    write_json(
        root_path,
        "closure/benchmark-dataplane-reload-blocker-summary.json",
        &json!({
            "stage": "stage193",
            "decision": "benchmark execution remains blocked",
            "production_dataplane_admitted": false,
            "reload_runtime_parity_admitted": false,
            "benchmark_executable_now": false,
            "matched_go_rust_default_daemon_benchmark_recorded": false
        }),
        "stage193",
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": stage193_gates() }),
        "stage193",
    )?;
    write_json(
        root_path,
        "next/stage194-true-production-execution-implementation-input.json",
        &json!({
            "stage": "stage193",
            "next_stage": "stage194",
            "stage192_recertification_bundle_verified": true,
            "default_product_switch_hard_gate_closed": true,
            "requires_true_production_dataplane_implementation": true,
            "requires_live_reload_runtime_parity_execution": true,
            "benchmark_executable_now": false,
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false
        }),
        "stage193",
    )?;
    write_manifest(
        root_path,
        "stage193",
        "default-product-switch-hard-gate-closure",
        "stage192_root",
        stage192_path,
        stage193_files(),
        verification,
        json!({
            "default_switch_hard_gate_summary_written": true,
            "product_chain_hard_gate_summary_written": true,
            "benchmark_dataplane_reload_blocker_summary_written": true,
            "stage194_true_production_execution_input_written": true
        }),
    )?;
    ensure_files(root_path, &stage193_files(), "stage193")?;

    Ok(json!({
        "root": path_string(root_path),
        "stage192_root": path_string(stage192_path),
        "expected_file_count": stage193_files().len(),
        "files_written_count": stage193_files().len(),
        "missing_files": [],
        "stage192_recertification_bundle_verified": true,
        "default_switch_hard_gate_summary_written": true,
        "product_chain_hard_gate_summary_written": true,
        "benchmark_dataplane_reload_blocker_summary_written": true,
        "stage194_true_production_execution_input_written": true,
        "default_product_switch_gate": "hard_gate_closed",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    }))
}

fn verify_stage190_bundle(root: &Path) -> Result<Value, String> {
    verify_bundle(
        root,
        "stage190",
        &stage190_files(),
        "next/stage191-bounded-benchmark-execution-input.json",
        &[
            "listener_reuse_gap_written",
            "bpf_owner_transfer_gap_written",
            "dns_cache_migration_guard_gap_written",
            "bounded_close_runtime_overview_gap_written",
            "stage191_bounded_benchmark_input_written",
        ],
        &[
            ("corpus_gate", "prepared_for_daemon_smoke"),
            ("rust_production_command_gate", "closed"),
            ("daemon_execution_gate", "identity_smoke_passed"),
            ("production_dataplane_gate", "execution_gap_recorded"),
            ("matched_benchmark_gate", "closed"),
            ("default_product_switch_gate", "closed"),
        ],
    )
}

fn verify_stage191_bundle(root: &Path) -> Result<Value, String> {
    verify_bundle(
        root,
        "stage191",
        &stage191_files(),
        "next/stage192-default-product-switch-recertification-input.json",
        &[
            "production_dataplane_blocker_written",
            "reload_runtime_parity_blocker_written",
            "matched_benchmark_command_blocker_written",
            "stage192_default_product_switch_input_written",
        ],
        &[
            ("corpus_gate", "prepared_for_daemon_smoke"),
            ("rust_production_command_gate", "closed"),
            ("daemon_execution_gate", "identity_smoke_passed"),
            ("production_dataplane_gate", "execution_gap_recorded"),
            ("matched_benchmark_gate", "admission_input_blocked"),
            ("default_product_switch_gate", "closed"),
        ],
    )
}

fn verify_stage192_bundle(root: &Path) -> Result<Value, String> {
    verify_bundle(
        root,
        "stage192",
        &stage192_files(),
        "next/stage193-default-product-switch-hard-gate-input.json",
        &[
            "default_daemon_switch_blocker_written",
            "product_chain_switch_blocker_written",
            "rollback_recertification_gap_written",
            "stage193_hard_gate_input_written",
        ],
        &[
            ("corpus_gate", "prepared_for_daemon_smoke"),
            ("rust_production_command_gate", "closed"),
            ("daemon_execution_gate", "identity_smoke_passed"),
            ("production_dataplane_gate", "execution_gap_recorded"),
            ("matched_benchmark_gate", "admission_input_blocked"),
            (
                "default_product_switch_gate",
                "recertification_input_blocked",
            ),
        ],
    )
}

fn verify_bundle(
    root: &Path,
    stage: &str,
    files: &[&'static str],
    next_file: &str,
    written_flags: &[&str],
    gates: &[(&str, &str)],
) -> Result<Value, String> {
    let missing = files
        .iter()
        .filter(|relative| !root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "{stage} bundle missing required files: {missing:?}"
        ));
    }

    let manifest = read_json(root, "manifest.json")?;
    expect_str(&manifest, "stage", stage, "manifest stage mismatch")?;
    for key in written_flags {
        expect_bool(
            &manifest,
            key,
            true,
            "manifest missing required written flag",
        )?;
    }
    for key in [
        "hard_gates_resolved",
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
    ] {
        expect_bool(
            &manifest,
            key,
            false,
            "manifest unexpectedly opened a hard gate",
        )?;
    }

    let gate_summary = read_json(root, "shared/gate-summary.json")?;
    for (gate, status) in gates {
        expect_gate_status(&gate_summary, gate, status)?;
    }

    let next = read_json(root, next_file)?;
    for key in [
        "benchmark_executable_now",
        "default_switch_allowed",
        "product_chain_switch_allowed",
    ] {
        expect_bool(
            &next,
            key,
            false,
            "next-stage input unexpectedly opened a hard gate",
        )?;
    }

    Ok(json!({
        "root": path_string(root),
        "stage": stage,
        "required_files_verified": true,
        "required_file_count": files.len(),
        "bundle_verified": true,
        "next_input_verified": true,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    }))
}

fn write_manifest(
    root: &Path,
    stage: &str,
    bundle: &str,
    prior_key: &str,
    prior_root: &Path,
    files: Vec<&'static str>,
    verification: Value,
    written_flags: Value,
) -> Result<(), String> {
    let mut manifest = json!({
        "stage": stage,
        "bundle": bundle,
        "root": path_string(root),
        prior_key: path_string(prior_root),
        "expected_file_count": files.len(),
        "files_written_count": files.len(),
        "missing_files": [],
        "prior_verification": verification,
        "hard_gates_resolved": false,
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for (key, value) in written_flags.as_object().into_iter().flatten() {
        manifest[key.as_str()] = value.clone();
    }
    write_json(root, "manifest.json", &manifest, stage)
}

fn stage191_rows(written: bool) -> Value {
    let status = if written {
        "blocker-written"
    } else {
        "requires-explicit-stage191-writer"
    };
    json!([
        row(
            "Stage190 reload/runtime gap verification",
            status,
            "Stage191 verifies the explicit Stage190 reload/runtime parity gap bundle before benchmark admission input",
            "verification is not benchmark execution",
            "benchmark_executable_now=false"
        ),
        row(
            "production dataplane blocker",
            status,
            "Stage191 records production dataplane admission as a benchmark prerequisite",
            "does not execute production dataplane",
            "production_dataplane_admitted=false"
        ),
        row(
            "reload/runtime parity blocker",
            status,
            "Stage191 records live reload/runtime parity admission as a benchmark prerequisite",
            "does not execute live reload/runtime parity",
            "reload_runtime_parity_admitted=false"
        ),
        row(
            "matched benchmark command blocker",
            status,
            "Stage191 records that same-corpus Go/Rust default daemon benchmark commands remain blocked",
            "does not run benchmark",
            "matched_go_rust_default_daemon_benchmark_recorded=false"
        ),
        row(
            "default/product safety",
            "closed-preserved",
            "Stage191 keeps default and product switches closed until benchmark evidence exists",
            "no default path mutation",
            "default_switch_allowed=false"
        )
    ])
}

fn stage192_rows(written: bool) -> Value {
    let status = if written {
        "blocker-written"
    } else {
        "requires-explicit-stage192-writer"
    };
    json!([
        row(
            "Stage191 benchmark admission verification",
            status,
            "Stage192 verifies the explicit Stage191 benchmark admission blocker bundle",
            "verification is not switch recertification",
            "default_switch_allowed=false"
        ),
        row(
            "default daemon switch blocker",
            status,
            "Stage192 records default daemon switch blockers from missing benchmark/default admission",
            "does not mutate default path",
            "default_path_mutation_allowed=false"
        ),
        row(
            "product-chain switch blocker",
            status,
            "Stage192 records dae-wing/daed product-chain switch blockers",
            "does not change product chain",
            "product_chain_switch_allowed=false"
        ),
        row(
            "rollback recertification gap",
            status,
            "Stage192 records missing rollback and failure-path recertification evidence",
            "does not certify rollback",
            "default_switch_allowed=false"
        ),
        row(
            "benchmark/default safety",
            "closed-preserved",
            "Stage192 keeps benchmark and default/product switches closed",
            "no benchmark data recorded",
            "benchmark_executable_now=false"
        )
    ])
}

fn stage193_rows(written: bool) -> Value {
    let status = if written {
        "closure-written"
    } else {
        "requires-explicit-stage193-writer"
    };
    json!([
        row(
            "Stage192 recertification verification",
            status,
            "Stage193 verifies the explicit Stage192 switch recertification blocker bundle",
            "verification is not admission",
            "default_switch_allowed=false"
        ),
        row(
            "default switch hard gate",
            status,
            "Stage193 records default switch hard-closed until production and benchmark evidence exists",
            "does not switch default path",
            "default_switch_allowed=false"
        ),
        row(
            "product-chain hard gate",
            status,
            "Stage193 records product-chain switch hard-closed until default/product recertification passes",
            "does not change product chain",
            "product_chain_switch_allowed=false"
        ),
        row(
            "benchmark/dataplane/reload blocker summary",
            status,
            "Stage193 records that benchmark remains blocked by production dataplane and reload/runtime gaps",
            "does not run benchmark",
            "benchmark_executable_now=false"
        ),
        row(
            "next implementation input",
            status,
            "Stage193 points Stage194 back to true production execution implementation evidence",
            "does not admit runtime",
            "production_dataplane_admitted=false"
        )
    ])
}

fn row(area: &str, status: &str, evidence: &str, boundary: &str, closed_flag: &str) -> Value {
    json!({
        "area": area,
        "status": status,
        "evidence": evidence,
        "boundary": boundary,
        "closed_flag": closed_flag
    })
}

fn stage191_gates() -> Value {
    gates(
        "Stage183 reviewed corpus binding remains carried through Stage184-191",
        "admission_input_blocked",
        "closed",
    )
}

fn stage192_gates() -> Value {
    gates(
        "Stage183 reviewed corpus binding remains carried through Stage184-192",
        "admission_input_blocked",
        "recertification_input_blocked",
    )
}

fn stage193_gates() -> Value {
    gates(
        "Stage183 reviewed corpus binding remains carried through Stage184-193",
        "admission_input_blocked",
        "hard_gate_closed",
    )
}

fn gates(corpus_opens_after: &str, benchmark_status: &str, switch_status: &str) -> Value {
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": corpus_opens_after
        },
        {
            "gate": "rust_production_command_gate",
            "status": "closed",
            "opens_after": "production-shaped Rust dae run command identity is admitted"
        },
        {
            "gate": "daemon_execution_gate",
            "status": "identity_smoke_passed",
            "opens_after": "Stage184 same-corpus identity smoke has passed but is not benchmark admission"
        },
        {
            "gate": "production_dataplane_gate",
            "status": "execution_gap_recorded",
            "opens_after": "real production listener bind, listen_socket_map key 0/1 write, netns/dae0 setup, tc/eBPF attach, and BPF owner handoff evidence pass"
        },
        {
            "gate": "matched_benchmark_gate",
            "status": benchmark_status,
            "opens_after": "production dataplane and reload/runtime parity pass with a same-corpus Go/Rust default daemon benchmark"
        },
        {
            "gate": "default_product_switch_gate",
            "status": switch_status,
            "opens_after": "matched benchmark results and default/product recertification pass"
        }
    ])
}

fn stage191_blockers() -> Vec<&'static str> {
    vec![
        "production dataplane execution remains a gap from Stage189",
        "live reload/runtime parity remains a gap from Stage190",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed",
    ]
}

fn stage192_blockers() -> Vec<&'static str> {
    vec![
        "Stage191 benchmark admission bundle keeps benchmark execution blocked",
        "matched Go/Rust default daemon benchmark has not been recorded or reviewed",
        "default path rollback and product-chain recertification evidence are missing",
        "default daemon and product-chain switches remain closed",
    ]
}

fn stage193_blockers() -> Vec<&'static str> {
    vec![
        "production dataplane execution evidence is still missing",
        "live reload/runtime parity execution evidence is still missing",
        "matched Go/Rust default daemon benchmark has not executed",
        "default and product-chain switches remain hard-closed",
    ]
}

fn read_json(root: &Path, relative: &str) -> Result<Value, String> {
    let path = root.join(relative);
    let content = fs::read_to_string(&path)
        .map_err(|err| format!("read {} failed: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {} failed: {err}", path.display()))
}

fn write_json(root: &Path, relative: &str, value: &Value, stage: &str) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create {stage} parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode {stage} file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write {stage} file {} failed: {err}", path.display()))
}

fn expect_str(value: &Value, key: &str, expected: &str, message: &str) -> Result<(), String> {
    match value.get(key).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{message}: expected {expected}, got {actual}")),
        None => Err(format!("{message}: missing {key}")),
    }
}

fn expect_bool(value: &Value, key: &str, expected: bool, message: &str) -> Result<(), String> {
    match value.get(key).and_then(Value::as_bool) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{message}: expected {expected}, got {actual}")),
        None => Err(format!("{message}: missing {key}")),
    }
}

fn expect_gate_status(value: &Value, gate: &str, expected: &str) -> Result<(), String> {
    let status = value
        .get("gates")
        .and_then(Value::as_array)
        .and_then(|gates| {
            gates.iter().find_map(|entry| {
                (entry.get("gate").and_then(Value::as_str) == Some(gate))
                    .then(|| entry.get("status").and_then(Value::as_str))
                    .flatten()
            })
        });
    if status == Some(expected) {
        return Ok(());
    }
    Err(format!(
        "gate {gate} mismatch: expected {expected}, got {status:?}"
    ))
}

fn validate_root(path: &Path, stage: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{stage} root must be absolute"));
    }
    let prefix = format!("/tmp/dae-{stage}");
    if !path.to_string_lossy().starts_with(&prefix) {
        return Err(format!("{stage} root must be under {prefix}*"));
    }
    Ok(())
}

fn ensure_new_root(path: &Path, stage: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "{stage} root already exists, remove it first: {}",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_files(root: &Path, files: &[&'static str], stage: &str) -> Result<(), String> {
    let missing = files
        .iter()
        .filter(|relative| !root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "{stage} bundle missing files after write: {missing:?}"
        ));
    }
    Ok(())
}

fn stage190_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage189-dataplane-verification.json",
        "reload/listener-reuse-execution-gap.json",
        "reload/bpf-owner-transfer-execution-gap.json",
        "reload/dns-cache-migration-guard-gap.json",
        "runtime/bounded-close-runtime-overview-gap.json",
        "shared/gate-summary.json",
        "next/stage191-bounded-benchmark-execution-input.json",
    ]
}

fn stage191_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage190-reload-runtime-verification.json",
        "benchmark/production-dataplane-blocker.json",
        "benchmark/reload-runtime-parity-blocker.json",
        "benchmark/matched-benchmark-command-blocker.json",
        "shared/gate-summary.json",
        "next/stage192-default-product-switch-recertification-input.json",
    ]
}

fn stage192_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage191-benchmark-admission-verification.json",
        "switch/default-daemon-switch-blocker.json",
        "switch/product-chain-switch-blocker.json",
        "switch/rollback-recertification-gap.json",
        "shared/gate-summary.json",
        "next/stage193-default-product-switch-hard-gate-input.json",
    ]
}

fn stage193_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage192-switch-recertification-verification.json",
        "closure/default-switch-hard-gate-summary.json",
        "closure/product-chain-hard-gate-summary.json",
        "closure/benchmark-dataplane-reload-blocker-summary.json",
        "shared/gate-summary.json",
        "next/stage194-true-production-execution-implementation-input.json",
    ]
}

fn stage191_validation_commands() -> Vec<&'static str> {
    vec![
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage191/bounded_same_corpus_benchmark_admission_input_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage191_bounded_same_corpus_benchmark_admission_input_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage191-bounded-same-corpus-benchmark-admission-input-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage191 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage191 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check",
    ]
}

fn stage192_validation_commands() -> Vec<&'static str> {
    vec![
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage192/default_product_switch_recertification_input_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage192_default_product_switch_recertification_input_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage192-default-product-switch-recertification-input-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage192 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage192 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check",
    ]
}

fn stage193_validation_commands() -> Vec<&'static str> {
    vec![
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage193/default_product_switch_hard_gate_closure.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage193_default_product_switch_hard_gate_closure.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage193-default-product-switch-hard-gate-closure",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage193 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage193 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check",
    ]
}

fn stage191_source() -> Vec<&'static str> {
    vec![
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage191",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage190",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
    ]
}

fn stage192_source() -> Vec<&'static str> {
    vec![
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage192",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage191",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
    ]
}

fn stage193_source() -> Vec<&'static str> {
    vec![
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage193",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage192",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage191",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
    ]
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
