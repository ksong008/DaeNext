use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const REVIEWED_CORPUS: &str = "# stage178 matched benchmark reviewed corpus artifact dry-run\n# reviewed_corpus_artifact_dry_run=true\n# reviewed_real_corpus_ready=false\n# real_benchmark_corpus_materialized=false\n# secret_material_present=false\n";
const REVIEWED_OUTBOUND_MATRIX: &str = r#"{"stage":"stage178","reviewed_corpus_artifact_dry_run":true,"secret_material_present":false,"protocol_fixture_scope":["socks5","http","shadowsocks","trojan","vless","vmess","trojan-go","ss2022","sip003","shadowsocksr","hysteria2","tuic","juicity"],"default_switch_allowed":false}"#;

enum Stage178Mode<'a> {
    ReadOnly,
    MaterializeReviewedDryRun { root: &'a str },
}

pub(crate) fn run_stage178_matched_benchmark_reviewed_corpus_materializer(
    args: &[String],
) -> RunnerOutput {
    match parse_stage178_args(args) {
        Ok(Stage178Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage178_report(None))),
        Ok(Stage178Mode::MaterializeReviewedDryRun { root }) => {
            match materialize_reviewed_root(root) {
                Ok(result) => RunnerOutput::ok(format!("{}\n", stage178_report(Some(result)))),
                Err(err) => RunnerOutput::stdout_error(err),
            }
        }
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage178_args(args: &[String]) -> Result<Stage178Mode<'_>, String> {
    let mut materialize = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--materialize-reviewed-dry-run" => materialize = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage178 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            _ => return Err(format!("unsupported stage178 argument: {arg}")),
        }
    }
    match (materialize, root) {
        (false, None) => Ok(Stage178Mode::ReadOnly),
        (false, Some(_)) => {
            Err("stage178 --root requires --materialize-reviewed-dry-run".to_string())
        }
        (true, Some(root)) => Ok(Stage178Mode::MaterializeReviewedDryRun { root }),
        (true, None) => Err("stage178 --materialize-reviewed-dry-run requires --root".to_string()),
    }
}

fn stage178_report(materialize_result: Option<Value>) -> Value {
    let materialized = materialize_result.is_some();
    let mut report = json!({
        "name": "stage178-matched-benchmark-reviewed-corpus-materializer-dry-run",
        "stage": "stage178",
        "prior_gate": "stage177-matched-benchmark-real-corpus-review-admission-queue-gate",
        "evidence_class": "explicit-temp-root-reviewed-corpus-artifact-materializer-dry-run",
        "read_only": !materialized,
        "materialize_reviewed_dry_run": materialized,
        "blocked": true,
        "blockers": [
            "Stage178 writes only reviewed corpus dry-run artifacts and not a real benchmark corpus",
            "reviewed_real_corpus_ready remains false until a verifier and benchmark admission stage pass",
            "Rust production dae run command is not admitted",
            "Go default daemon and Rust opt-in daemon are not executed",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage178* root only"
    });
    for key in [
        "reviewed_corpus_artifact_dry_run_available",
        "stage177_review_admission_queue_carried",
        "reviewed_config_artifact_available",
        "reviewed_outbound_matrix_artifact_available",
        "reviewed_digest_contract_available",
        "review_admission_evidence_carried",
        "runtime_evidence_scope_carried",
        "command_binding_carried",
        "redaction_evidence_carried",
        "explicit_temp_root_required",
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
    report["reviewed_corpus_artifact_written"] = json!(materialized);
    report["reviewed_manifest_written"] = json!(materialized);
    report["reviewed_config_written"] = json!(materialized);
    report["reviewed_outbound_matrix_written"] = json!(materialized);
    report["reviewed_digest_written"] = json!(materialized);
    report["review_admission_evidence_written"] = json!(materialized);
    report["runtime_evidence_scope_written"] = json!(materialized);
    report["command_binding_written"] = json!(materialized);
    report["reviewed_files"] = json!(reviewed_files());
    report["digest_algorithm"] = json!("blake3");
    report["review_admission_rows_carried"] = review_admission_rows();
    report["reviewed_artifact_requirements"] = reviewed_artifact_requirements();
    if let Some(result) = materialize_result {
        report["materialize_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage178 admits only an explicit temporary-root reviewed corpus artifact dry-run that carries Stage177 review admission rows, redaction evidence, runtime evidence scope, and Stage172 command binding; it does not mark the reviewed corpus ready, materialize a real benchmark corpus, execute daemons, or switch default/product paths"
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
        "stage": "stage179",
        "target": "matched benchmark reviewed corpus artifact verifier",
        "required_output": "verify Stage178 reviewed dry-run artifact file set, digest contract, redaction evidence, runtime scope, and closed benchmark flags before any real corpus materialization"
    }]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage178/matched_benchmark_reviewed_corpus_materializer_dry_run.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage178_matched_benchmark_reviewed_corpus_materializer_dry_run.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage178-matched-benchmark-reviewed-corpus-materializer-dry-run",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage178-matched-benchmark-reviewed-corpus-materializer-dry-run --materialize-reviewed-dry-run --root /tmp/dae-stage178-reviewed-corpus-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage178 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage178 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage177 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage178",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage177",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage176",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn materialize_reviewed_root(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage178_root(root_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage178 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    fs::create_dir_all(root_path).map_err(|err| format!("create stage178 root failed: {err}"))?;
    let outbound_matrix = format!("{REVIEWED_OUTBOUND_MATRIX}\n");
    write_file(root_path, "config/corpus.reviewed.dae", REVIEWED_CORPUS)?;
    write_file(
        root_path,
        "config/outbound-matrix.reviewed.json",
        &outbound_matrix,
    )?;
    let corpus_digest = blake3::hash(REVIEWED_CORPUS.as_bytes())
        .to_hex()
        .to_string();
    let outbound_matrix_digest = blake3::hash(outbound_matrix.as_bytes())
        .to_hex()
        .to_string();
    write_json(
        root_path,
        "shared/reviewed-corpus-digests.json",
        json!({
            "stage": "stage178",
            "algorithm": "blake3",
            "reviewed_corpus_artifact_dry_run": true,
            "reviewed_real_corpus_ready": false,
            "reviewed_corpus_digest": corpus_digest,
            "reviewed_outbound_matrix_digest": outbound_matrix_digest,
            "real_benchmark_corpus_materialized": false,
            "matched_go_rust_default_daemon_benchmark_recorded": false
        }),
    )?;
    write_json(
        root_path,
        "review/review-admission-evidence.json",
        json!({
            "stage": "stage178",
            "source_review_queue": "stage177",
            "reviewed_corpus_artifact_dry_run": true,
            "reviewed_real_corpus_ready": false,
            "review_admission_rows_carried": review_admission_rows(),
            "redaction_evidence": {
                "secret_material_present": false,
                "subscription_credentials_present": false,
                "private_endpoint_material_present": false,
                "host_specific_mutable_paths_present": false
            },
            "reviewer_signoff": "dry-run-evidence-only",
            "real_benchmark_corpus_materialized": false
        }),
    )?;
    write_json(
        root_path,
        "shared/runtime-evidence-scope.json",
        json!({
            "stage": "stage178",
            "runtime_evidence_scope": runtime_evidence_scope(),
            "production_listener_bound": false,
            "production_tc_attach_smoke_passed": false,
            "ebpf_attached": false,
            "real_benchmark_corpus_materialized": false
        }),
    )?;
    write_json(
        root_path,
        "commands/stage172-binding.json",
        json!({
            "stage": "stage178",
            "source_command_capture": "stage172-matched-benchmark-command-capture-dry-run",
            "source_command_verifier": "stage173-matched-benchmark-command-capture-artifact-verifier",
            "go_default_command_template_preserved": true,
            "rust_optin_command_template_preserved": true,
            "rust_production_dae_run_command_exists": false,
            "go_default_daemon_executed": false,
            "rust_optin_daemon_executed": false
        }),
    )?;
    write_json(
        root_path,
        "manifest.json",
        json!({
            "stage": "stage178",
            "source_review_queue": "stage177",
            "reviewed_corpus_materializer_dry_run": true,
            "reviewed_corpus_artifact_dry_run": true,
            "reviewed_artifact_digest_written": true,
            "reviewed_real_corpus_ready": false,
            "real_benchmark_corpus_materialized": false,
            "go_default_daemon_executed": false,
            "rust_optin_daemon_executed": false,
            "matched_go_rust_default_daemon_benchmark_recorded": false,
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false
        }),
    )?;
    let missing = reviewed_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    Ok(json!({
        "root": root_path.display().to_string(),
        "files_written_count": reviewed_files().len() - missing.len(),
        "expected_file_count": reviewed_files().len(),
        "missing_files": missing,
        "manifest_written": root_path.join("manifest.json").is_file(),
        "reviewed_corpus_digest": corpus_digest,
        "reviewed_outbound_matrix_digest": outbound_matrix_digest,
        "reviewed_corpus_artifact_dry_run": true,
        "reviewed_real_corpus_ready": false,
        "real_benchmark_corpus_materialized": false,
        "go_default_daemon_executed": false,
        "rust_optin_daemon_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn validate_stage178_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage178 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage178") {
        return Err("stage178 root must be under /tmp/dae-stage178*".to_string());
    }
    Ok(())
}

fn write_file(root: &Path, relative: &str, content: &str) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create stage178 parent {} failed: {err}", parent.display()))?;
    }
    fs::write(&path, content).map_err(|err| {
        format!(
            "write stage178 reviewed artifact {} failed: {err}",
            path.display()
        )
    })
}

fn write_json(root: &Path, relative: &str, value: Value) -> Result<(), String> {
    write_file(root, relative, &format!("{value}\n"))
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

fn review_admission_rows() -> Value {
    json!([
        {
            "area": "reviewed config input",
            "status": "dry-run-carried",
            "evidence": "reviewed corpus artifact replaces the Stage175 review-pending candidate only inside explicit temp root",
            "boundary": "reviewed dry-run artifact is not real benchmark corpus materialization",
            "closed_flag": "real_benchmark_corpus_materialized=false"
        },
        {
            "area": "outbound matrix approval",
            "status": "dry-run-carried",
            "evidence": "reviewed outbound matrix records protocol fixture scope without switching default outbound paths",
            "boundary": "matrix approval is not default switch admission",
            "closed_flag": "default_switch_allowed=false"
        },
        {
            "area": "digest and provenance",
            "status": "dry-run-digested",
            "evidence": "blake3 reviewed corpus and outbound matrix digests are written with Stage172/173 command binding",
            "boundary": "digest provenance is not daemon benchmark execution",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "redaction evidence",
            "status": "dry-run-carried",
            "evidence": "artifact records no secrets, subscription credentials, private endpoints, or host-specific mutable paths",
            "boundary": "redaction evidence must be verified before real materialization",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        },
        {
            "area": "runtime parity scope",
            "status": "dry-run-carried",
            "evidence": "startup order, reload listener reuse, BPF owner transfer, DNS cache, RuntimeOverview, and cleanup evidence scope are carried",
            "boundary": "scope carry is not production listener or tc attach",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "reviewer sign-off",
            "status": "dry-run-carried",
            "evidence": "sign-off remains dry-run evidence only and does not make reviewed_real_corpus_ready true",
            "boundary": "a later verifier/admission stage must decide readiness",
            "closed_flag": "reviewed_real_corpus_ready=false"
        }
    ])
}

fn reviewed_artifact_requirements() -> Value {
    json!([
        "explicit /tmp/dae-stage178* root is required before any reviewed corpus artifact is written",
        "reviewed corpus and outbound matrix must be redacted and host-independent",
        "blake3 digest contract must bind the reviewed files",
        "Stage172 command capture and Stage173 verifier boundaries must be carried",
        "runtime evidence scope must include startup, reload, BPF owner, DNS cache, RuntimeOverview, and cleanup",
        "all daemon execution, benchmark, and default/product switch flags must remain false"
    ])
}

fn runtime_evidence_scope() -> Value {
    json!([
        "startup order: config parse -> bootstrap direct -> wait network -> subscription resolve -> control plane create -> listener ready",
        "reload listener reuse and BPF owner transfer: old eject -> new build -> inject -> old close -> start serve with reused listener",
        "listen_socket_map keys: key 0 TCP and key 1 UDP must be written before ready",
        "DNS cache migration only when DNS config is unchanged",
        "RuntimeOverview and cache stats must preserve WebUI/daed observation fields",
        "reload scoped UDP endpoint, anyfrom, UDP task, packet sniffer, and transport pools require cleanup"
    ])
}
