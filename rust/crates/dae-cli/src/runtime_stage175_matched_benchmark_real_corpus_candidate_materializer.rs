use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const CANDIDATE_CORPUS: &str = "# stage175 matched benchmark real corpus candidate dry-run\n# review_pending=true\n# replace this candidate before real benchmark corpus materialization\n";
const CANDIDATE_OUTBOUND_MATRIX: &str = r#"{"stage":"stage175","candidate_review_pending":true,"admitted_fixture_references":"record-before-real-corpus"}"#;

enum Stage175Mode<'a> {
    ReadOnly,
    MaterializeCandidateDryRun { root: &'a str },
}

pub(crate) fn run_stage175_matched_benchmark_real_corpus_candidate_materializer(
    args: &[String],
) -> RunnerOutput {
    match parse_stage175_args(args) {
        Ok(Stage175Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage175_report(None))),
        Ok(Stage175Mode::MaterializeCandidateDryRun { root }) => {
            match materialize_candidate_root(root) {
                Ok(result) => RunnerOutput::ok(format!("{}\n", stage175_report(Some(result)))),
                Err(err) => RunnerOutput::stdout_error(err),
            }
        }
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage175_args(args: &[String]) -> Result<Stage175Mode<'_>, String> {
    let mut materialize = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--materialize-candidate-dry-run" => materialize = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage175 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage175 argument: {arg}")),
        }
    }
    match (materialize, root) {
        (false, None) => Ok(Stage175Mode::ReadOnly),
        (false, Some(_)) => {
            Err("stage175 --root requires --materialize-candidate-dry-run".to_string())
        }
        (true, Some(root)) => Ok(Stage175Mode::MaterializeCandidateDryRun { root }),
        (true, None) => Err("stage175 --materialize-candidate-dry-run requires --root".to_string()),
    }
}

fn stage175_report(materialize_result: Option<Value>) -> Value {
    let materialized = materialize_result.is_some();
    let mut report = json!({
        "name": "stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run",
        "stage": "stage175",
        "prior_gate": "stage174-matched-benchmark-real-corpus-materialization-queue-gate",
        "evidence_class": "explicit-temp-root-real-corpus-candidate-materializer-dry-run",
        "read_only": !materialized,
        "materialize_candidate_dry_run": materialized,
        "blocked": true,
        "blockers": [
            "Stage175 writes a review-pending candidate and not a real benchmark corpus",
            "Rust production dae run command is not admitted",
            "Go default daemon and Rust opt-in daemon are not executed",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage175* root only"
    });
    for key in [
        "real_corpus_candidate_materializer_dry_run_available",
        "stage174_materialization_queue_carried",
        "candidate_digest_contract_available",
        "candidate_review_pending",
        "explicit_temp_root_required",
        "sensitive_material_redaction_required",
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
    report["candidate_manifest_written"] = json!(materialized);
    report["candidate_corpus_written"] = json!(materialized);
    report["candidate_outbound_matrix_written"] = json!(materialized);
    report["candidate_digest_written"] = json!(materialized);
    report["candidate_review_contract_written"] = json!(materialized);
    report["candidate_files"] = json!(candidate_files());
    report["digest_algorithm"] = json!("blake3");
    if let Some(result) = materialize_result {
        report["materialize_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage175 admits only an explicit temporary-root review-pending corpus candidate materializer dry-run with candidate config, outbound matrix, digest provenance, and review contract files; it does not materialize the real benchmark corpus, execute daemons, admit Rust production dae run, or switch default/product paths"
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
            "stage": "stage176",
            "target": "matched benchmark real corpus candidate artifact verifier",
            "required_output": "verify Stage175 candidate files, digest contract, review_pending boundary, and closed benchmark flags before materialization"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage175/matched_benchmark_real_corpus_candidate_materializer_dry_run.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage175_matched_benchmark_real_corpus_candidate_materializer_dry_run.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run --materialize-candidate-dry-run --root /tmp/dae-stage175-real-corpus-candidate-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage175 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage175 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage174 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage175",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage174",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage173",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn materialize_candidate_root(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage175_root(root_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage175 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    fs::create_dir_all(root_path).map_err(|err| format!("create stage175 root failed: {err}"))?;
    write_file(root_path, "config/corpus.candidate.dae", CANDIDATE_CORPUS)?;
    write_file(
        root_path,
        "config/outbound-matrix.candidate.json",
        &format!("{CANDIDATE_OUTBOUND_MATRIX}\n"),
    )?;
    let corpus_digest = blake3::hash(CANDIDATE_CORPUS.as_bytes())
        .to_hex()
        .to_string();
    let outbound_matrix_digest = blake3::hash(CANDIDATE_OUTBOUND_MATRIX.as_bytes())
        .to_hex()
        .to_string();
    write_json(
        root_path,
        "shared/candidate-digests.json",
        json!({
            "stage": "stage175",
            "algorithm": "blake3",
            "candidate_review_pending": true,
            "candidate_corpus_digest": corpus_digest,
            "candidate_outbound_matrix_digest": outbound_matrix_digest,
            "real_benchmark_corpus_materialized": false
        }),
    )?;
    write_json(
        root_path,
        "review/materialization-contract.json",
        json!({
            "stage": "stage175",
            "source_queue": "stage174",
            "candidate_review_pending": true,
            "sensitive_material_redaction_required": true,
            "runtime_evidence_scope": [
                "startup order",
                "reload listener reuse and BPF owner transfer",
                "DNS cache migration",
                "RuntimeOverview and cleanup"
            ],
            "real_benchmark_corpus_materialized": false
        }),
    )?;
    write_json(
        root_path,
        "manifest.json",
        json!({
            "stage": "stage175",
            "source_queue": "stage174",
            "candidate_materializer_dry_run": true,
            "candidate_review_pending": true,
            "candidate_digest_written": true,
            "real_benchmark_corpus_materialized": false,
            "go_default_daemon_executed": false,
            "rust_optin_daemon_executed": false,
            "matched_go_rust_default_daemon_benchmark_recorded": false
        }),
    )?;
    let missing = candidate_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    Ok(json!({
        "root": root_path.display().to_string(),
        "files_written_count": candidate_files().len() - missing.len(),
        "expected_file_count": candidate_files().len(),
        "missing_files": missing,
        "manifest_written": root_path.join("manifest.json").is_file(),
        "candidate_corpus_digest": corpus_digest,
        "candidate_outbound_matrix_digest": outbound_matrix_digest,
        "candidate_review_pending": true,
        "real_benchmark_corpus_materialized": false,
        "go_default_daemon_executed": false,
        "rust_optin_daemon_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn validate_stage175_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage175 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage175") {
        return Err("stage175 root must be under /tmp/dae-stage175*".to_string());
    }
    Ok(())
}

fn write_file(root: &Path, relative: &str, content: &str) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create stage175 parent {} failed: {err}", parent.display()))?;
    }
    fs::write(&path, content)
        .map_err(|err| format!("write stage175 candidate {} failed: {err}", path.display()))
}

fn write_json(root: &Path, relative: &str, value: Value) -> Result<(), String> {
    write_file(root, relative, &format!("{value}\n"))
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
