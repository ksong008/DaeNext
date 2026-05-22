use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage173Mode<'a> {
    ReadOnly,
    VerifyDryRunRoot { root: &'a str },
}

pub(crate) fn run_stage173_matched_benchmark_command_capture_verifier(
    args: &[String],
) -> RunnerOutput {
    match parse_stage173_args(args) {
        Ok(Stage173Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage173_report(None))),
        Ok(Stage173Mode::VerifyDryRunRoot { root }) => {
            match verify_stage172_command_capture_root(root) {
                Ok(result) => RunnerOutput::ok(format!("{}\n", stage173_report(Some(result)))),
                Err(err) => RunnerOutput::stdout_error(err),
            }
        }
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage173_args(args: &[String]) -> Result<Stage173Mode<'_>, String> {
    let mut verify = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--verify-dry-run-root" => verify = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage173 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage173 argument: {arg}")),
        }
    }
    match (verify, root) {
        (false, None) => Ok(Stage173Mode::ReadOnly),
        (false, Some(_)) => Err("stage173 --root requires --verify-dry-run-root".to_string()),
        (true, Some(root)) => Ok(Stage173Mode::VerifyDryRunRoot { root }),
        (true, None) => Err("stage173 --verify-dry-run-root requires --root".to_string()),
    }
}

fn stage173_report(verification_result: Option<Value>) -> Value {
    let verified = verification_result.is_some();
    let mut report = json!({
        "name": "stage173-matched-benchmark-command-capture-artifact-verifier",
        "stage": "stage173",
        "prior_gate": "stage172-matched-benchmark-command-capture-dry-run",
        "evidence_class": "explicit-stage172-dry-run-command-capture-artifact-verifier",
        "read_only": !verified,
        "verify_dry_run_root": verified,
        "blocked": true,
        "blockers": [
            "Stage171 digest input remains a placeholder dry-run corpus",
            "Rust production dae run command is not admitted",
            "verifying Stage172 artifact symmetry does not execute Go or Rust daemons",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage172* Stage172 dry-run root only"
    });
    for key in [
        "command_capture_artifact_verifier_available",
        "stage172_command_capture_contract_required",
        "explicit_stage172_root_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "rust_production_dae_run_command_exists",
        "real_benchmark_corpus_materialized",
        "go_default_daemon_executed",
        "rust_optin_daemon_executed",
        "production_listener_bound",
        "production_tc_attach_smoke_passed",
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
    report["command_template_symmetry_verified"] = json!(verified);
    report["stage171_digest_input_verified"] = json!(verified);
    report["runtime_evidence_contract_verified"] = json!(verified);
    report["rust_optin_blocker_verified"] = json!(verified);
    report["required_stage172_files"] = json!(stage172_files());
    if let Some(result) = verification_result {
        report["verification_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage173 verifies only the explicit Stage172 command capture dry-run artifacts: Go and Rust command templates must share Stage171 digest inputs, preserve the Rust opt-in blocker, and carry runtime evidence requirements before any daemon benchmark execution"
    );
    report["remaining_blockers"] = json!([
        "Rust production dae run command is not admitted",
        "real matched benchmark corpus is not materialized",
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage174",
            "target": "matched benchmark real corpus materialization queue",
            "required_output": "replace the Stage171 placeholder corpus boundary with a reviewed same-corpus materialization queue before daemon execution"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage173/matched_benchmark_command_capture_artifact_verifier.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage173_matched_benchmark_command_capture_artifact_verifier.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage173-matched-benchmark-command-capture-artifact-verifier",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage173-matched-benchmark-command-capture-artifact-verifier --verify-dry-run-root --root /tmp/dae-stage172-command-capture-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage173 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage173 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage172 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage173",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage172",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage171",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage157",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn verify_stage172_command_capture_root(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage172_root(root_path)?;
    let missing = stage172_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage173 Stage172 dry-run root is missing required files: {}",
            missing.join(", ")
        ));
    }

    let manifest = read_json(root_path, "manifest.json")?;
    let go_template = read_json(root_path, "go/command-template.json")?;
    let rust_template = read_json(root_path, "rust/command-template.json")?;
    let capture_contract = read_json(root_path, "shared/command-capture-contract.json")?;
    let stage171_digest_input = read_json(root_path, "shared/stage171-digest-input.json")?;

    require_json_eq(
        "stage172 manifest",
        &manifest,
        &json!({
            "stage": "stage172",
            "source_digest_contract": "stage171",
            "go_default_command_template_written": true,
            "rust_optin_command_template_written": true,
            "stage157_control_plane_evidence_required": true,
            "commands_executed": false,
            "rust_production_dae_run_command_exists": false,
            "matched_go_rust_default_daemon_benchmark_recorded": false
        }),
    )?;
    require_eq(
        "Go template owner",
        go_template["owner"].as_str(),
        Some("go-default-daemon"),
    )?;
    require_eq(
        "Rust template owner",
        rust_template["owner"].as_str(),
        Some("rust-optin-daemon"),
    )?;
    require_eq(
        "Go template entrypoint",
        go_template["entrypoint"].as_str(),
        Some("dae run"),
    )?;
    require_eq(
        "Rust template entrypoint",
        rust_template["entrypoint"].as_str(),
        Some("dae-daemon-optin stage156-default-run-identity-admission"),
    )?;
    require_json_eq(
        "Go and Rust digest inputs",
        &go_template["digest_inputs"],
        &rust_template["digest_inputs"],
    )?;
    require_json_eq(
        "Stage171 shared digest inputs",
        &go_template["digest_inputs"],
        &json!([
            "<stage171-root>/config/corpus.dae",
            "<stage171-root>/shared/corpus-digests.json"
        ]),
    )?;
    require_contains(
        "Go Stage171 corpus argv",
        &go_template["command"],
        "<stage171-root>/config/corpus.dae",
    )?;
    require_contains(
        "Rust Stage171 corpus argv",
        &rust_template["command"],
        "<stage171-root>/config/corpus.dae",
    )?;
    require_json_eq(
        "Rust Stage157 evidence requirement",
        &rust_template["stage157_control_plane_evidence_required"],
        &json!(true),
    )?;
    require_json_eq(
        "Rust production dae run blocker",
        &rust_template["rust_production_dae_run_command_exists"],
        &json!(false),
    )?;
    require_json_eq(
        "Go command execution",
        &go_template["executes_now"],
        &json!(false),
    )?;
    require_json_eq(
        "Rust command execution",
        &rust_template["executes_now"],
        &json!(false),
    )?;
    require_json_eq(
        "runtime evidence contract",
        &capture_contract["runtime_evidence_requirements"],
        &json!([
            "startup and OnReady pid/progress/sdnotify",
            "reload listener reuse and rollback",
            "BPF owner transfer and listen_socket_map readiness",
            "DNS cache migration guard and RuntimeOverview samples"
        ]),
    )?;
    require_json_eq(
        "capture contract execution",
        &capture_contract["commands_executed"],
        &json!(false),
    )?;
    require_json_eq(
        "Stage171 required files",
        &stage171_digest_input["required_stage171_files"],
        &json!([
            "<stage171-root>/config/corpus.dae",
            "<stage171-root>/config/outbound-matrix.json",
            "<stage171-root>/shared/corpus-digests.json"
        ]),
    )?;
    require_json_eq(
        "Stage171 placeholder boundary",
        &stage171_digest_input["dry_run_digest_input_is_placeholder"],
        &json!(true),
    )?;
    require_json_eq(
        "real corpus materialization boundary",
        &stage171_digest_input["real_benchmark_corpus_materialized"],
        &json!(false),
    )?;

    Ok(json!({
        "root": root_path.display().to_string(),
        "verified_file_count": stage172_files().len(),
        "missing_files": missing,
        "go_rust_stage171_corpus_symmetric": true,
        "digest_input_symmetry_verified": true,
        "runtime_evidence_contract_verified": true,
        "stage171_digest_input_verified": true,
        "rust_optin_blocker_verified": true,
        "commands_executed": false,
        "rust_production_dae_run_command_exists": false,
        "real_benchmark_corpus_materialized": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn validate_stage172_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage173 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage172") {
        return Err("stage173 root must be a /tmp/dae-stage172* dry-run root".to_string());
    }
    Ok(())
}

fn read_json(root: &Path, relative: &str) -> Result<Value, String> {
    let path = root.join(relative);
    let content = fs::read_to_string(&path).map_err(|err| {
        format!(
            "read stage173 verifier input {} failed: {err}",
            path.display()
        )
    })?;
    serde_json::from_str(&content).map_err(|err| {
        format!(
            "parse stage173 verifier input {} failed: {err}",
            path.display()
        )
    })
}

fn require_json_eq(label: &str, actual: &Value, expected: &Value) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "stage173 verifier mismatch for {label}: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn require_eq<T>(label: &str, actual: Option<T>, expected: Option<T>) -> Result<(), String>
where
    T: std::fmt::Debug + PartialEq,
{
    if actual != expected {
        return Err(format!(
            "stage173 verifier mismatch for {label}: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn require_contains(label: &str, value: &Value, expected: &str) -> Result<(), String> {
    let contains = value
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)));
    if !contains {
        return Err(format!(
            "stage173 verifier mismatch for {label}: missing {expected}"
        ));
    }
    Ok(())
}

fn stage172_files() -> [&'static str; 5] {
    [
        "manifest.json",
        "go/command-template.json",
        "rust/command-template.json",
        "shared/command-capture-contract.json",
        "shared/stage171-digest-input.json",
    ]
}
