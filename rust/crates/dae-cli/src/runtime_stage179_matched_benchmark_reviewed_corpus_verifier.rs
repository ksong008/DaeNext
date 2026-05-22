use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage179Mode<'a> {
    ReadOnly,
    VerifyReviewedRoot { root: &'a str },
}

pub(crate) fn run_stage179_matched_benchmark_reviewed_corpus_verifier(
    args: &[String],
) -> RunnerOutput {
    match parse_stage179_args(args) {
        Ok(Stage179Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage179_report(None))),
        Ok(Stage179Mode::VerifyReviewedRoot { root }) => match verify_reviewed_root(root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage179_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage179_args(args: &[String]) -> Result<Stage179Mode<'_>, String> {
    let mut verify = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--verify-reviewed-root" => verify = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage179 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            _ => return Err(format!("unsupported stage179 argument: {arg}")),
        }
    }
    match (verify, root) {
        (false, None) => Ok(Stage179Mode::ReadOnly),
        (false, Some(_)) => Err("stage179 --root requires --verify-reviewed-root".to_string()),
        (true, Some(root)) => Ok(Stage179Mode::VerifyReviewedRoot { root }),
        (true, None) => Err("stage179 --verify-reviewed-root requires --root".to_string()),
    }
}

fn stage179_report(verification: Option<Value>) -> Value {
    let verified = verification.is_some();
    let mut report = json!({
        "name": "stage179-matched-benchmark-reviewed-corpus-artifact-verifier",
        "stage": "stage179",
        "prior_gate": "stage178-matched-benchmark-reviewed-corpus-materializer-dry-run",
        "evidence_class": "explicit-stage178-reviewed-corpus-artifact-verifier",
        "read_only": !verified,
        "verify_reviewed_root": verified,
        "blocked": true,
        "blockers": [
            "Stage179 verifies only Stage178 reviewed dry-run artifacts",
            "reviewed_real_corpus_ready remains false",
            "real benchmark corpus is not materialized",
            "Rust production dae run command is not admitted",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage178* reviewed dry-run root only"
    });
    for key in [
        "reviewed_corpus_artifact_verifier_available",
        "stage178_reviewed_artifact_contract_required",
        "explicit_stage178_root_required",
        "reviewed_digest_recompute_required",
        "redaction_evidence_required",
        "runtime_evidence_scope_required",
        "command_binding_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "reviewed_real_corpus_ready",
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
    report["reviewed_file_set_verified"] = json!(verified);
    report["reviewed_digest_verified"] = json!(verified);
    report["redaction_evidence_verified"] = json!(verified);
    report["runtime_evidence_scope_verified"] = json!(verified);
    report["command_binding_verified"] = json!(verified);
    report["closed_benchmark_flags_verified"] = json!(verified);
    report["required_stage178_files"] = json!(reviewed_files());
    report["verifier_rows"] = verifier_rows();
    report["digest_algorithm"] = json!("blake3");
    if let Some(result) = verification {
        report["verification_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage179 verifies only the explicit Stage178 reviewed corpus dry-run artifact file set, recomputed blake3 digests, redaction evidence, runtime evidence scope, Stage172/173 command binding, and closed benchmark flags; it does not make the reviewed corpus ready, materialize a real benchmark corpus, execute daemons, or switch default/product paths"
    );
    report["remaining_blockers"] = json!([
        "reviewed real corpus is not ready",
        "Rust production dae run command is not admitted",
        "real matched benchmark corpus is not materialized",
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([{
        "stage": "stage180",
        "target": "matched benchmark reviewed corpus readiness admission queue",
        "required_output": "decide which verifier evidence and runtime blockers must pass before reviewed_real_corpus_ready or real_benchmark_corpus_materialized can open"
    }]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage179/matched_benchmark_reviewed_corpus_artifact_verifier.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage179_matched_benchmark_reviewed_corpus_artifact_verifier.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage179-matched-benchmark-reviewed-corpus-artifact-verifier",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage179-matched-benchmark-reviewed-corpus-artifact-verifier --verify-reviewed-root --root /tmp/dae-stage178-reviewed-corpus-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage179 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage179 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage178 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage179",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage178",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage177",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn verify_reviewed_root(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage178_root(root_path)?;
    let missing = reviewed_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage179 Stage178 reviewed root is missing required files: {}",
            missing.join(", ")
        ));
    }
    let manifest = read_json(root_path, "manifest.json")?;
    let digest_contract = read_json(root_path, "shared/reviewed-corpus-digests.json")?;
    let review = read_json(root_path, "review/review-admission-evidence.json")?;
    let runtime_scope = read_json(root_path, "shared/runtime-evidence-scope.json")?;
    let command_binding = read_json(root_path, "commands/stage172-binding.json")?;

    require_bool(
        "manifest reviewed corpus dry-run",
        &manifest["reviewed_corpus_artifact_dry_run"],
        true,
    )?;
    require_closed_flags("manifest", &manifest)?;
    require_bool(
        "digest reviewed corpus dry-run",
        &digest_contract["reviewed_corpus_artifact_dry_run"],
        true,
    )?;
    require_bool(
        "digest reviewed readiness",
        &digest_contract["reviewed_real_corpus_ready"],
        false,
    )?;
    require_bool(
        "digest real corpus boundary",
        &digest_contract["real_benchmark_corpus_materialized"],
        false,
    )?;
    require_bool(
        "digest matched benchmark boundary",
        &digest_contract["matched_go_rust_default_daemon_benchmark_recorded"],
        false,
    )?;
    require_str("digest algorithm", &digest_contract["algorithm"], "blake3")?;

    let corpus = read_file(root_path, "config/corpus.reviewed.dae")?;
    let outbound_matrix = read_file(root_path, "config/outbound-matrix.reviewed.json")?;
    let corpus_digest = blake3::hash(corpus.as_bytes()).to_hex().to_string();
    let outbound_matrix_digest = blake3::hash(outbound_matrix.as_bytes())
        .to_hex()
        .to_string();
    require_str(
        "reviewed corpus digest",
        &digest_contract["reviewed_corpus_digest"],
        &corpus_digest,
    )?;
    require_str(
        "reviewed outbound matrix digest",
        &digest_contract["reviewed_outbound_matrix_digest"],
        &outbound_matrix_digest,
    )?;

    require_bool(
        "review evidence dry-run",
        &review["reviewed_corpus_artifact_dry_run"],
        true,
    )?;
    require_bool(
        "review evidence readiness",
        &review["reviewed_real_corpus_ready"],
        false,
    )?;
    require_bool(
        "review evidence real corpus boundary",
        &review["real_benchmark_corpus_materialized"],
        false,
    )?;
    require_str(
        "review evidence sign-off",
        &review["reviewer_signoff"],
        "dry-run-evidence-only",
    )?;
    require_array_len(
        "review admission rows",
        &review["review_admission_rows_carried"],
        6,
    )?;
    for key in [
        "secret_material_present",
        "subscription_credentials_present",
        "private_endpoint_material_present",
        "host_specific_mutable_paths_present",
    ] {
        require_bool(
            &format!("redaction evidence {key}"),
            &review["redaction_evidence"][key],
            false,
        )?;
    }

    require_array_len(
        "runtime evidence scope",
        &runtime_scope["runtime_evidence_scope"],
        6,
    )?;
    require_bool(
        "runtime production listener boundary",
        &runtime_scope["production_listener_bound"],
        false,
    )?;
    require_bool(
        "runtime production tc boundary",
        &runtime_scope["production_tc_attach_smoke_passed"],
        false,
    )?;
    require_bool(
        "runtime ebpf boundary",
        &runtime_scope["ebpf_attached"],
        false,
    )?;
    require_bool(
        "runtime real corpus boundary",
        &runtime_scope["real_benchmark_corpus_materialized"],
        false,
    )?;

    require_str(
        "command capture source",
        &command_binding["source_command_capture"],
        "stage172-matched-benchmark-command-capture-dry-run",
    )?;
    require_str(
        "command verifier source",
        &command_binding["source_command_verifier"],
        "stage173-matched-benchmark-command-capture-artifact-verifier",
    )?;
    require_bool(
        "Go command template",
        &command_binding["go_default_command_template_preserved"],
        true,
    )?;
    require_bool(
        "Rust command template",
        &command_binding["rust_optin_command_template_preserved"],
        true,
    )?;
    require_bool(
        "Rust production command blocker",
        &command_binding["rust_production_dae_run_command_exists"],
        false,
    )?;
    require_bool(
        "Go command execution boundary",
        &command_binding["go_default_daemon_executed"],
        false,
    )?;
    require_bool(
        "Rust command execution boundary",
        &command_binding["rust_optin_daemon_executed"],
        false,
    )?;

    Ok(json!({
        "root": root_path.display().to_string(),
        "verified_file_count": reviewed_files().len(),
        "missing_files": missing,
        "reviewed_corpus_digest": corpus_digest,
        "reviewed_outbound_matrix_digest": outbound_matrix_digest,
        "reviewed_file_set_verified": true,
        "reviewed_digest_verified": true,
        "redaction_evidence_verified": true,
        "runtime_evidence_scope_verified": true,
        "command_binding_verified": true,
        "closed_benchmark_flags_verified": true,
        "reviewed_real_corpus_ready": false,
        "real_benchmark_corpus_materialized": false,
        "go_default_daemon_executed": false,
        "rust_optin_daemon_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn validate_stage178_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage179 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage178") {
        return Err("stage179 root must be a /tmp/dae-stage178* reviewed root".to_string());
    }
    Ok(())
}

fn read_file(root: &Path, relative: &str) -> Result<String, String> {
    let path = root.join(relative);
    fs::read_to_string(&path).map_err(|err| {
        format!(
            "read stage179 verifier input {} failed: {err}",
            path.display()
        )
    })
}

fn read_json(root: &Path, relative: &str) -> Result<Value, String> {
    let content = read_file(root, relative)?;
    serde_json::from_str(&content)
        .map_err(|err| format!("parse stage179 verifier input {relative} failed: {err}"))
}

fn require_bool(label: &str, value: &Value, expected: bool) -> Result<(), String> {
    if value.as_bool() != Some(expected) {
        return Err(format!(
            "stage179 verifier mismatch for {label}: expected {expected}, got {value}"
        ));
    }
    Ok(())
}

fn require_str(label: &str, value: &Value, expected: &str) -> Result<(), String> {
    if value.as_str() != Some(expected) {
        return Err(format!(
            "stage179 verifier mismatch for {label}: expected {expected}, got {value}"
        ));
    }
    Ok(())
}

fn require_array_len(label: &str, value: &Value, expected: usize) -> Result<(), String> {
    let Some(items) = value.as_array() else {
        return Err(format!(
            "stage179 verifier mismatch for {label}: got {value}"
        ));
    };
    if items.len() != expected {
        return Err(format!(
            "stage179 verifier mismatch for {label}: expected {expected}, got {}",
            items.len()
        ));
    }
    Ok(())
}

fn require_closed_flags(label: &str, value: &Value) -> Result<(), String> {
    for key in [
        "reviewed_real_corpus_ready",
        "real_benchmark_corpus_materialized",
        "go_default_daemon_executed",
        "rust_optin_daemon_executed",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "product_chain_switch_allowed",
    ] {
        require_bool(&format!("{label} {key}"), &value[key], false)?;
    }
    Ok(())
}

fn reviewed_files() -> [&'static str; 7] {
    [
        "manifest.json",
        "config/corpus.reviewed.dae",
        "config/outbound-matrix.reviewed.json",
        "shared/reviewed-corpus-digests.json",
        "review/review-admission-evidence.json",
        "shared/runtime-evidence-scope.json",
        "commands/stage172-binding.json",
    ]
}

fn verifier_rows() -> Value {
    json!([
        {
            "area": "reviewed artifact file set",
            "status": "explicit-root-verified",
            "evidence": "all seven Stage178 reviewed dry-run artifact files are required from explicit /tmp/dae-stage178* root",
            "boundary": "file set verification does not make reviewed_real_corpus_ready true",
            "closed_flag": "reviewed_real_corpus_ready=false"
        },
        {
            "area": "reviewed digest",
            "status": "recomputed",
            "evidence": "reviewed config and outbound matrix bytes must match Stage178 blake3 digest contract",
            "boundary": "digest parity is not matched daemon benchmark execution",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        },
        {
            "area": "redaction and runtime scope",
            "status": "verified",
            "evidence": "redaction evidence, startup/reload/listen_socket_map/DNS/runtime cleanup scope, and command binding are all checked",
            "boundary": "scope verification is not production listener, tc attach, or eBPF execution",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "Rust production dae run command, Go/Rust daemon execution, real corpus materialization, and default/product switches remain false",
            "boundary": "Stage179 remains pre-benchmark evidence only",
            "closed_flag": "benchmark_executable_now=false"
        }
    ])
}
