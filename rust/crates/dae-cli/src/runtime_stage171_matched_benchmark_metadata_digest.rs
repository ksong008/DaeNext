use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DRY_RUN_CORPUS: &str = "# stage171 matched benchmark corpus dry-run placeholder\n# replace with the exact benchmark corpus before daemon execution\n";
const DRY_RUN_OUTBOUND_MATRIX: &str =
    r#"{"stage":"stage171","placeholder":true,"protocol_matrix":"replace-before-benchmark"}"#;

enum Stage171Mode<'a> {
    ReadOnly,
    PopulateDryRun { root: &'a str },
}

pub(crate) fn run_stage171_matched_benchmark_metadata_digest(args: &[String]) -> RunnerOutput {
    match parse_stage171_args(args) {
        Ok(Stage171Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage171_report(None))),
        Ok(Stage171Mode::PopulateDryRun { root }) => match populate_stage171_root(root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage171_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage171_args(args: &[String]) -> Result<Stage171Mode<'_>, String> {
    let mut populate = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--populate-dry-run" => populate = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage171 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage171 argument: {arg}")),
        }
    }
    match (populate, root) {
        (false, None) => Ok(Stage171Mode::ReadOnly),
        (false, Some(_)) => Err("stage171 --root requires --populate-dry-run".to_string()),
        (true, Some(root)) => Ok(Stage171Mode::PopulateDryRun { root }),
        (true, None) => Err("stage171 --populate-dry-run requires --root".to_string()),
    }
}

fn stage171_report(populate_result: Option<Value>) -> Value {
    let populated = populate_result.is_some();
    let mut report = json!({
        "name": "stage171-matched-benchmark-metadata-corpus-digest-dry-run",
        "stage": "stage171",
        "prior_gate": "stage170-matched-benchmark-artifact-writer-dry-run",
        "evidence_class": "explicit-temp-root-host-metadata-corpus-digest-dry-run",
        "read_only": !populated,
        "populate_dry_run": populated,
        "blocked": true,
        "blockers": [
            "dry-run corpus is a placeholder and not a real daemon benchmark config",
            "Go default daemon and Rust opt-in daemon are not executed",
            "production tc/netns attach remains closed",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage171* root only"
    });
    for key in [
        "host_metadata_dry_run_available",
        "corpus_digest_dry_run_available",
        "dry_run_corpus_placeholder_recorded",
        "explicit_temp_root_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
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
    report["host_metadata_snapshot_written"] = json!(populated);
    report["corpus_digest_written"] = json!(populated);
    report["outbound_matrix_digest_written"] = json!(populated);
    report["dry_run_files"] = json!([
        "manifest.json",
        "host/metadata.json",
        "config/corpus.dae",
        "config/outbound-matrix.json",
        "shared/corpus-digests.json"
    ]);
    report["digest_algorithm"] = json!("blake3");
    if let Some(result) = populate_result {
        report["populate_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage171 populates an explicit temporary-root host metadata snapshot and dry-run corpus digest contract, but the corpus remains a placeholder and no Go/Rust daemon benchmark, production tc/netns attach, default admission, or product switch is executed"
    );
    report["remaining_blockers"] = json!([
        "real matched benchmark corpus is not materialized",
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage172",
            "target": "matched benchmark same-corpus daemon command capture dry-run",
            "required_output": "record Go default daemon and Rust opt-in daemon command capture templates against the Stage171 digest contract without running benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage171/matched_benchmark_metadata_corpus_digest_dry_run.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage171_matched_benchmark_metadata_corpus_digest_dry_run.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage171-matched-benchmark-metadata-corpus-digest-dry-run",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage171-matched-benchmark-metadata-corpus-digest-dry-run --populate-dry-run --root /tmp/dae-stage171-metadata-corpus-digest-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage171 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage171 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage170 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage171",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage170",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage169",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn populate_stage171_root(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage171_root(root_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage171 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    fs::create_dir_all(root_path).map_err(|err| format!("create stage171 root failed: {err}"))?;
    write_stage171_file(root_path, "config/corpus.dae", DRY_RUN_CORPUS)?;
    write_stage171_file(
        root_path,
        "config/outbound-matrix.json",
        &format!("{DRY_RUN_OUTBOUND_MATRIX}\n"),
    )?;
    let host_metadata = stage171_host_metadata();
    write_stage171_file(
        root_path,
        "host/metadata.json",
        &format!("{}\n", host_metadata),
    )?;
    let corpus_digest = blake3::hash(DRY_RUN_CORPUS.as_bytes()).to_hex().to_string();
    let outbound_matrix_digest = blake3::hash(DRY_RUN_OUTBOUND_MATRIX.as_bytes())
        .to_hex()
        .to_string();
    let digests = json!({
        "stage": "stage171",
        "algorithm": "blake3",
        "dry_run_corpus_placeholder": true,
        "corpus_digest": corpus_digest,
        "outbound_matrix_digest": outbound_matrix_digest,
        "real_benchmark_corpus_materialized": false
    });
    write_stage171_file(
        root_path,
        "shared/corpus-digests.json",
        &format!("{}\n", digests),
    )?;
    let manifest = json!({
        "stage": "stage171",
        "source_layout": "stage170",
        "host_metadata_snapshot_written": true,
        "corpus_digest_written": true,
        "outbound_matrix_digest_written": true,
        "dry_run_corpus_placeholder_recorded": true,
        "real_benchmark_corpus_materialized": false,
        "go_default_daemon_executed": false,
        "rust_optin_daemon_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    write_stage171_file(root_path, "manifest.json", &format!("{}\n", manifest))?;
    let expected = stage171_files();
    let missing = expected
        .iter()
        .filter(|path| !root_path.join(path).is_file())
        .copied()
        .collect::<Vec<_>>();
    Ok(json!({
        "root": root_path.display().to_string(),
        "files_written_count": expected.len() - missing.len(),
        "expected_file_count": expected.len(),
        "missing_files": missing,
        "manifest_written": root_path.join("manifest.json").is_file(),
        "host_metadata_snapshot_written": root_path.join("host/metadata.json").is_file(),
        "corpus_digest": corpus_digest,
        "outbound_matrix_digest": outbound_matrix_digest,
        "dry_run_corpus_placeholder_recorded": true,
        "real_benchmark_corpus_materialized": false,
        "go_default_daemon_executed": false,
        "rust_optin_daemon_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn validate_stage171_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage171 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage171") {
        return Err("stage171 root must be under /tmp/dae-stage171*".to_string());
    }
    Ok(())
}

fn write_stage171_file(root: &Path, relative: &str, content: &str) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create stage171 parent {} failed: {err}", parent.display()))?;
    }
    fs::write(&path, content)
        .map_err(|err| format!("write stage171 file {} failed: {err}", path.display()))
}

fn stage171_host_metadata() -> Value {
    json!({
        "stage": "stage171",
        "snapshot_class": "dry-run-host-metadata",
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "pid": std::process::id(),
        "kernel_osrelease": read_optional("/proc/sys/kernel/osrelease"),
        "kernel_version": read_optional("/proc/version"),
        "bpffs_path_exists": Path::new("/sys/fs/bpf").exists(),
        "tc_command_presence_deferred": true,
        "netns_capture_deferred": true,
        "sysctl_capture_deferred": true,
        "real_benchmark_corpus_materialized": false
    })
}

fn read_optional(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn stage171_files() -> [&'static str; 5] {
    [
        "manifest.json",
        "host/metadata.json",
        "config/corpus.dae",
        "config/outbound-matrix.json",
        "shared/corpus-digests.json",
    ]
}
