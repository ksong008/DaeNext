use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

#[derive(Clone, Copy)]
struct Stage170ArtifactFile {
    path: &'static str,
    owner: &'static str,
    content: &'static str,
}

enum Stage170Mode<'a> {
    ReadOnly,
    WriteDryRun { root: &'a str },
}

pub(crate) fn run_stage170_matched_benchmark_artifact_writer(args: &[String]) -> RunnerOutput {
    match parse_stage170_args(args) {
        Ok(Stage170Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage170_report(None))),
        Ok(Stage170Mode::WriteDryRun { root }) => match write_stage170_artifacts(root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage170_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage170_args(args: &[String]) -> Result<Stage170Mode<'_>, String> {
    let mut write_dry_run = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-dry-run" => write_dry_run = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage170 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage170 argument: {arg}")),
        }
    }
    match (write_dry_run, root) {
        (false, None) => Ok(Stage170Mode::ReadOnly),
        (false, Some(_)) => Err("stage170 --root requires --write-dry-run".to_string()),
        (true, Some(root)) => Ok(Stage170Mode::WriteDryRun { root }),
        (true, None) => Err("stage170 --write-dry-run requires --root".to_string()),
    }
}

fn stage170_report(write_result: Option<Value>) -> Value {
    let executed = write_result.is_some();
    let mut report = json!({
        "name": "stage170-matched-benchmark-artifact-writer-dry-run",
        "stage": "stage170",
        "prior_gate": "stage169-matched-benchmark-corpus-artifact-builder",
        "evidence_class": "explicit-temp-root-matched-benchmark-artifact-writer-dry-run",
        "read_only": !executed,
        "execute_builder": executed,
        "blocked": true,
        "blockers": [
            "artifact writer dry-run is not a Go/Rust daemon benchmark",
            "Go default daemon and Rust opt-in daemon are not executed",
            "production tc/netns attach remains closed",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage170* root only"
    });
    for key in [
        "artifact_writer_dry_run_available",
        "stage169_layout_reused",
        "explicit_temp_root_required",
        "cleanup_boundary_recorded",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
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
    report["dry_run_artifact_files_written"] = json!(executed);
    report["artifact_files_written_to_runtime_dir"] = json!(executed);
    report["dry_run_manifest_written"] = json!(executed);
    report["dry_run_file_count_verified"] = json!(executed);
    report["artifact_layout"] = json!(stage170_layout_json());
    report["expected_file_count"] = json!(stage170_artifact_files().len());
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage170 adds an explicit temporary-root artifact writer dry-run for the Stage169 layout; it can verify placeholder file creation, manifest presence, file count, and cleanup boundary, but it does not execute Go or Rust daemons, record matched benchmark data, admit true Rust default daemon, or switch default/product paths"
    );
    report["remaining_blockers"] = json!([
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage171",
            "target": "matched benchmark host metadata and corpus digest dry-run",
            "required_output": "populate Stage170 artifact placeholders with host metadata and shared corpus digests without running daemon benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage170/matched_benchmark_artifact_writer_dry_run.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage170_matched_benchmark_artifact_writer_dry_run.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage170-matched-benchmark-artifact-writer-dry-run",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage170-matched-benchmark-artifact-writer-dry-run --write-dry-run --root /tmp/dae-stage170-artifact-writer-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage170 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage170 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage169 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
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

fn write_stage170_artifacts(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage170_root(root_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage170 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    fs::create_dir_all(root_path).map_err(|err| format!("create stage170 root failed: {err}"))?;
    let files = stage170_artifact_files();
    let mut written = Vec::with_capacity(files.len());
    for file in &files {
        let path = root_path.join(file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create parent {} failed: {err}", parent.display()))?;
        }
        let content = stage170_file_content(file, files.len());
        fs::write(&path, content)
            .map_err(|err| format!("write stage170 artifact {} failed: {err}", path.display()))?;
        written.push(file.path);
    }
    let missing = files
        .iter()
        .filter(|file| !root_path.join(file.path).is_file())
        .map(|file| file.path)
        .collect::<Vec<_>>();
    let manifest_written = root_path.join("manifest.json").is_file();
    let file_count_verified = missing.is_empty() && written.len() == files.len();
    Ok(json!({
        "root": root_path.display().to_string(),
        "files_written_count": written.len(),
        "expected_file_count": files.len(),
        "manifest_written": manifest_written,
        "file_count_verified": file_count_verified,
        "missing_files": missing,
        "written_files": written,
        "cleanup_boundary": "caller owns explicit /tmp/dae-stage170* dry-run root cleanup; no default/product path is mutated",
        "go_default_daemon_executed": false,
        "rust_optin_daemon_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn validate_stage170_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage170 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage170") {
        return Err("stage170 root must be under /tmp/dae-stage170*".to_string());
    }
    Ok(())
}

fn stage170_file_content(file: &Stage170ArtifactFile, expected_file_count: usize) -> String {
    if file.path == "manifest.json" {
        return format!(
            "{}\n",
            json!({
                "stage": "stage170",
                "source_layout": "stage169",
                "expected_file_count": expected_file_count,
                "artifact_writer_dry_run": true,
                "go_default_daemon_executed": false,
                "rust_optin_daemon_executed": false,
                "matched_go_rust_default_daemon_benchmark_recorded": false
            })
        );
    }
    if file.path.ends_with(".jsonl") {
        return format!(
            "{}\n",
            json!({
                "stage": "stage170",
                "path": file.path,
                "owner": file.owner,
                "placeholder": true,
                "content": file.content
            })
        );
    }
    if file.path.ends_with(".json") || file.path.ends_with(".dae") {
        return format!(
            "{}\n",
            json!({
                "stage": "stage170",
                "path": file.path,
                "owner": file.owner,
                "placeholder": true,
                "content": file.content
            })
        );
    }
    format!(
        "stage=stage170\npath={}\nowner={}\nplaceholder=true\ncontent={}\n",
        file.path, file.owner, file.content
    )
}

fn stage170_layout_json() -> Vec<Value> {
    stage170_artifact_files()
        .iter()
        .map(|file| {
            json!({
                "path": file.path,
                "owner": file.owner,
                "required": true,
                "content": file.content
            })
        })
        .collect()
}

fn stage170_artifact_files() -> Vec<Stage170ArtifactFile> {
    vec![
        Stage170ArtifactFile {
            path: "manifest.json",
            owner: "shared",
            content: "run id, git revisions, config corpus digest, host metadata digest, command plan digest, and admission flags",
        },
        Stage170ArtifactFile {
            path: "config/corpus.dae",
            owner: "shared",
            content: "exact dae config used by both Go default daemon and Rust opt-in daemon",
        },
        Stage170ArtifactFile {
            path: "config/outbound-matrix.json",
            owner: "shared",
            content: "admitted outbound protocol matrix and per-protocol fixture references",
        },
        Stage170ArtifactFile {
            path: "host/metadata.json",
            owner: "shared",
            content: "kernel, bpffs, capabilities, sysctl, network namespace, tc, and clock metadata",
        },
        Stage170ArtifactFile {
            path: "go/command.log",
            owner: "go-default-daemon",
            content: "raw Go default daemon command, stdout, stderr, exit status, and timestamps",
        },
        Stage170ArtifactFile {
            path: "rust/command.log",
            owner: "rust-optin-daemon",
            content: "raw Rust opt-in daemon command, stdout, stderr, exit status, and timestamps",
        },
        Stage170ArtifactFile {
            path: "go/build.json",
            owner: "go-default-daemon",
            content: "Go daemon version, git revision, build tags, and binary digest",
        },
        Stage170ArtifactFile {
            path: "rust/build.json",
            owner: "rust-optin-daemon",
            content: "Rust daemon version, git revision, feature set, and binary digest",
        },
        Stage170ArtifactFile {
            path: "go/runtime-samples.jsonl",
            owner: "go-default-daemon",
            content: "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, DNS stats, and BPF map stats",
        },
        Stage170ArtifactFile {
            path: "rust/runtime-samples.jsonl",
            owner: "rust-optin-daemon",
            content: "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, DNS stats, and BPF map stats",
        },
        Stage170ArtifactFile {
            path: "shared/stage167-bounded-summary.json",
            owner: "shared",
            content: "bounded reload-owner/listen_socket_map benchmark summary carried only as input evidence",
        },
        Stage170ArtifactFile {
            path: "shared/reload-rollback-cleanup.json",
            owner: "shared",
            content: "reload success, invalid config rollback, listener reuse, BPF owner transfer, and scoped cleanup evidence",
        },
        Stage170ArtifactFile {
            path: "shared/bpf-map-snapshot.json",
            owner: "shared",
            content: "listen_socket_map key 0/1, pinned map compatibility, routing tuple, domain routing, and ownership snapshot requirements",
        },
        Stage170ArtifactFile {
            path: "shared/dns-cache-snapshot.json",
            owner: "shared",
            content: "DNS cache migration guard, cache hit samples, UDP/53 behavior, and domain routing bitmap ownership evidence",
        },
    ]
}
