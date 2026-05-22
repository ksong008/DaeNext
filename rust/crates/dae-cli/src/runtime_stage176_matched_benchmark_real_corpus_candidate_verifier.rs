use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage176Mode<'a> {
    ReadOnly,
    VerifyCandidateRoot { root: &'a str },
}

pub(crate) fn run_stage176_matched_benchmark_real_corpus_candidate_verifier(
    args: &[String],
) -> RunnerOutput {
    match parse_stage176_args(args) {
        Ok(Stage176Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage176_report(None))),
        Ok(Stage176Mode::VerifyCandidateRoot { root }) => match verify_candidate_root(root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage176_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage176_args(args: &[String]) -> Result<Stage176Mode<'_>, String> {
    let mut verify = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--verify-candidate-root" => verify = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage176 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, v)| v),
            _ => return Err(format!("unsupported stage176 argument: {arg}")),
        }
    }
    match (verify, root) {
        (false, None) => Ok(Stage176Mode::ReadOnly),
        (false, Some(_)) => Err("stage176 --root requires --verify-candidate-root".to_string()),
        (true, Some(root)) => Ok(Stage176Mode::VerifyCandidateRoot { root }),
        (true, None) => Err("stage176 --verify-candidate-root requires --root".to_string()),
    }
}

fn stage176_report(verification: Option<Value>) -> Value {
    let verified = verification.is_some();
    let mut report = json!({
        "name": "stage176-matched-benchmark-real-corpus-candidate-artifact-verifier",
        "stage": "stage176",
        "prior_gate": "stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run",
        "evidence_class": "explicit-stage175-real-corpus-candidate-artifact-verifier",
        "read_only": !verified,
        "verify_candidate_root": verified,
        "blocked": true,
        "blockers": [
            "Stage175 artifact remains a review-pending candidate",
            "real benchmark corpus is not materialized",
            "Rust production dae run command is not admitted",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage175* candidate root only"
    });
    for key in [
        "real_corpus_candidate_artifact_verifier_available",
        "stage175_candidate_contract_required",
        "explicit_stage175_root_required",
        "candidate_digest_recompute_required",
        "candidate_review_pending_required",
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
    report["candidate_file_set_verified"] = json!(verified);
    report["candidate_digest_verified"] = json!(verified);
    report["candidate_review_boundary_verified"] = json!(verified);
    report["closed_benchmark_flags_verified"] = json!(verified);
    report["required_stage175_files"] = json!(candidate_files());
    if let Some(result) = verification {
        report["verification_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage176 verifies only the explicit Stage175 review-pending candidate artifact file set, recomputed blake3 digests, review contract, and closed benchmark flags; it does not promote the candidate to a real corpus, execute daemons, or switch default/product paths"
    );
    report["remaining_blockers"] = json!([
        "Rust production dae run command is not admitted",
        "real matched benchmark corpus is not materialized",
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([{
        "stage": "stage177",
        "target": "matched benchmark real corpus review admission queue",
        "required_output": "decide what reviewed input replaces the Stage175 review-pending candidate before any real corpus materialization"
    }]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage176/matched_benchmark_real_corpus_candidate_artifact_verifier.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage176_matched_benchmark_real_corpus_candidate_artifact_verifier.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage176-matched-benchmark-real-corpus-candidate-artifact-verifier",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage176-matched-benchmark-real-corpus-candidate-artifact-verifier --verify-candidate-root --root /tmp/dae-stage175-real-corpus-candidate-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage176 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage176 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage175 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage176",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage175",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn verify_candidate_root(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage175_root(root_path)?;
    let missing = candidate_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage176 Stage175 candidate root is missing required files: {}",
            missing.join(", ")
        ));
    }
    let manifest = read_json(root_path, "manifest.json")?;
    let digest_contract = read_json(root_path, "shared/candidate-digests.json")?;
    let review = read_json(root_path, "review/materialization-contract.json")?;
    require_bool(
        "manifest candidate review",
        &manifest["candidate_review_pending"],
        true,
    )?;
    require_bool(
        "manifest real corpus boundary",
        &manifest["real_benchmark_corpus_materialized"],
        false,
    )?;
    require_bool(
        "review candidate boundary",
        &review["candidate_review_pending"],
        true,
    )?;
    require_bool(
        "review redaction requirement",
        &review["sensitive_material_redaction_required"],
        true,
    )?;
    require_bool(
        "digest candidate boundary",
        &digest_contract["candidate_review_pending"],
        true,
    )?;
    require_bool(
        "digest real corpus boundary",
        &digest_contract["real_benchmark_corpus_materialized"],
        false,
    )?;
    let corpus = read_file(root_path, "config/corpus.candidate.dae")?;
    let outbound_matrix = read_file(root_path, "config/outbound-matrix.candidate.json")?;
    let corpus_digest = blake3::hash(corpus.as_bytes()).to_hex().to_string();
    let outbound_matrix_digest = blake3::hash(outbound_matrix.trim_end().as_bytes())
        .to_hex()
        .to_string();
    require_str(
        "candidate corpus digest",
        &digest_contract["candidate_corpus_digest"],
        &corpus_digest,
    )?;
    require_str(
        "candidate outbound matrix digest",
        &digest_contract["candidate_outbound_matrix_digest"],
        &outbound_matrix_digest,
    )?;
    Ok(json!({
        "root": root_path.display().to_string(),
        "verified_file_count": candidate_files().len(),
        "missing_files": missing,
        "candidate_corpus_digest": corpus_digest,
        "candidate_outbound_matrix_digest": outbound_matrix_digest,
        "candidate_digest_verified": true,
        "candidate_review_boundary_verified": true,
        "closed_benchmark_flags_verified": true,
        "real_benchmark_corpus_materialized": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn validate_stage175_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage176 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage175") {
        return Err("stage176 root must be a /tmp/dae-stage175* candidate root".to_string());
    }
    Ok(())
}

fn read_file(root: &Path, relative: &str) -> Result<String, String> {
    let path = root.join(relative);
    fs::read_to_string(&path).map_err(|err| {
        format!(
            "read stage176 verifier input {} failed: {err}",
            path.display()
        )
    })
}

fn read_json(root: &Path, relative: &str) -> Result<Value, String> {
    let content = read_file(root, relative)?;
    serde_json::from_str(&content)
        .map_err(|err| format!("parse stage176 verifier input {relative} failed: {err}"))
}

fn require_bool(label: &str, value: &Value, expected: bool) -> Result<(), String> {
    if value.as_bool() != Some(expected) {
        return Err(format!(
            "stage176 verifier mismatch for {label}: expected {expected}, got {value}"
        ));
    }
    Ok(())
}

fn require_str(label: &str, value: &Value, expected: &str) -> Result<(), String> {
    if value.as_str() != Some(expected) {
        return Err(format!(
            "stage176 verifier mismatch for {label}: expected {expected}, got {value}"
        ));
    }
    Ok(())
}

fn candidate_files() -> [&'static str; 5] {
    [
        "manifest.json",
        "config/corpus.candidate.dae",
        "config/outbound-matrix.candidate.json",
        "shared/candidate-digests.json",
        "review/materialization-contract.json",
    ]
}
