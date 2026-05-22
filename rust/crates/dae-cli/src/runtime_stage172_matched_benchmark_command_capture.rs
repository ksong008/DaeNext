use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage172Mode<'a> {
    ReadOnly,
    WriteDryRun { root: &'a str },
}

pub(crate) fn run_stage172_matched_benchmark_command_capture(args: &[String]) -> RunnerOutput {
    match parse_stage172_args(args) {
        Ok(Stage172Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage172_report(None))),
        Ok(Stage172Mode::WriteDryRun { root }) => match write_stage172_templates(root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage172_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage172_args(args: &[String]) -> Result<Stage172Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-dry-run" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage172 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage172 argument: {arg}")),
        }
    }
    match (write, root) {
        (false, None) => Ok(Stage172Mode::ReadOnly),
        (false, Some(_)) => Err("stage172 --root requires --write-dry-run".to_string()),
        (true, Some(root)) => Ok(Stage172Mode::WriteDryRun { root }),
        (true, None) => Err("stage172 --write-dry-run requires --root".to_string()),
    }
}

fn stage172_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage172-matched-benchmark-command-capture-dry-run",
        "stage": "stage172",
        "prior_gate": "stage171-matched-benchmark-metadata-corpus-digest-dry-run",
        "evidence_class": "explicit-temp-root-same-corpus-daemon-command-capture-dry-run",
        "read_only": !written,
        "write_dry_run": written,
        "blocked": true,
        "blockers": [
            "Rust production dae run command is not admitted; only current opt-in command template is recorded",
            "Stage171 digest input is still a placeholder dry-run contract",
            "Go default daemon and Rust opt-in daemon commands are not executed",
            "default daemon and product-chain switches remain closed"
        ],
        "artifact_root_policy": "explicit /tmp/dae-stage172* root only"
    });
    for key in [
        "command_capture_dry_run_available",
        "stage171_digest_contract_required",
        "stage157_control_plane_evidence_required",
        "command_capture_symmetry_recorded",
        "explicit_temp_root_required",
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
    report["go_default_command_template_written"] = json!(written);
    report["rust_optin_command_template_written"] = json!(written);
    report["command_capture_contract_written"] = json!(written);
    report["dry_run_files"] = json!(stage172_files());
    report["go_default_command_template"] = go_command_template();
    report["rust_optin_command_template"] = rust_command_template();
    report["capture_contract"] = capture_contract();
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report["gate_decision"] = json!(
        "Stage172 records same-corpus command capture templates for preserved Go dae run and the current Rust opt-in Stage156 run-shaped identity, carries the Stage157 control-plane evidence requirement, and binds both to Stage171 digest inputs without executing daemon commands or admitting a Rust production dae run"
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
            "stage": "stage173",
            "target": "matched benchmark command capture artifact verifier",
            "required_output": "verify Stage172 Go/Rust command capture template symmetry, Stage171 digest inputs, and current Rust opt-in command blocker before any benchmark execution"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage172/matched_benchmark_command_capture_dry_run.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage172_matched_benchmark_command_capture_dry_run.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage172-matched-benchmark-command-capture-dry-run",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage172-matched-benchmark-command-capture-dry-run --write-dry-run --root /tmp/dae-stage172-command-capture-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage172 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage172 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage171 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage172",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage171",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage157",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage156",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "cmd/run.go",
        "rust/crates/dae-daemon/src/default_run_identity.rs"
    ]);
    report
}

fn write_stage172_templates(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage172_root(root_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage172 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    fs::create_dir_all(root_path).map_err(|err| format!("create stage172 root failed: {err}"))?;
    let files = [
        ("go/command-template.json", go_command_template()),
        ("rust/command-template.json", rust_command_template()),
        ("shared/command-capture-contract.json", capture_contract()),
        (
            "shared/stage171-digest-input.json",
            json!({
                "stage": "stage172",
                "required_stage171_files": [
                    "<stage171-root>/config/corpus.dae",
                    "<stage171-root>/config/outbound-matrix.json",
                    "<stage171-root>/shared/corpus-digests.json"
                ],
                "dry_run_digest_input_is_placeholder": true,
                "real_benchmark_corpus_materialized": false
            }),
        ),
        (
            "manifest.json",
            json!({
                "stage": "stage172",
                "source_digest_contract": "stage171",
                "go_default_command_template_written": true,
                "rust_optin_command_template_written": true,
                "stage157_control_plane_evidence_required": true,
                "commands_executed": false,
                "rust_production_dae_run_command_exists": false,
                "matched_go_rust_default_daemon_benchmark_recorded": false
            }),
        ),
    ];
    for (relative, value) in &files {
        write_json(root_path, relative, value)?;
    }
    let missing = files
        .iter()
        .filter(|(relative, _)| !root_path.join(relative).is_file())
        .map(|(relative, _)| *relative)
        .collect::<Vec<_>>();
    Ok(json!({
        "root": root_path.display().to_string(),
        "files_written_count": files.len() - missing.len(),
        "expected_file_count": files.len(),
        "missing_files": missing,
        "go_default_command_template_written": root_path.join("go/command-template.json").is_file(),
        "rust_optin_command_template_written": root_path.join("rust/command-template.json").is_file(),
        "command_capture_contract_written": root_path.join("shared/command-capture-contract.json").is_file(),
        "commands_executed": false,
        "rust_production_dae_run_command_exists": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn write_json(root: &Path, relative: &str, value: &Value) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create stage172 parent {} failed: {err}", parent.display()))?;
    }
    fs::write(&path, format!("{value}\n"))
        .map_err(|err| format!("write stage172 file {} failed: {err}", path.display()))
}

fn validate_stage172_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage172 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage172") {
        return Err("stage172 root must be under /tmp/dae-stage172*".to_string());
    }
    Ok(())
}

fn go_command_template() -> Value {
    json!({
        "owner": "go-default-daemon",
        "entrypoint": "dae run",
        "command": [
            "dae",
            "run",
            "--disable-timestamp",
            "--logfile",
            "<artifact-root>/go/daemon.log",
            "-c",
            "<stage171-root>/config/corpus.dae"
        ],
        "derived_from": "cmd/run.go flags and current product systemd ExecStart",
        "digest_inputs": [
            "<stage171-root>/config/corpus.dae",
            "<stage171-root>/shared/corpus-digests.json"
        ],
        "executes_now": false,
        "default_path_preserved": true
    })
}

fn rust_command_template() -> Value {
    json!({
        "owner": "rust-optin-daemon",
        "entrypoint": "dae-daemon-optin stage156-default-run-identity-admission",
        "command": [
            "cargo",
            "run",
            "--manifest-path",
            "rust/Cargo.toml",
            "-p",
            "dae-daemon",
            "--bin",
            "dae-daemon-optin",
            "--",
            "stage156-default-run-identity-admission",
            "--root",
            "<artifact-root>/rust/run-identity",
            "--config",
            "<stage171-root>/config/corpus.dae",
            "--logfile",
            "<artifact-root>/rust/daemon.log",
            "--disable-timestamp",
            "--disable-sudo"
        ],
        "derived_from": "Stage156 run-shaped opt-in Rust default identity",
        "digest_inputs": [
            "<stage171-root>/config/corpus.dae",
            "<stage171-root>/shared/corpus-digests.json"
        ],
        "stage157_control_plane_evidence_required": true,
        "rust_production_dae_run_command_exists": false,
        "executes_now": false
    })
}

fn capture_contract() -> Value {
    json!({
        "stage": "stage172",
        "same_corpus_requirements": [
            "same Stage171 config corpus path and digest contract",
            "same outbound matrix digest input",
            "raw command argv plus stdout/stderr/exit/timestamps per owner",
            "Go default baseline remains dae run",
            "Rust candidate remains opt-in until a production Rust dae run command is admitted"
        ],
        "runtime_evidence_requirements": [
            "startup and OnReady pid/progress/sdnotify",
            "reload listener reuse and rollback",
            "BPF owner transfer and listen_socket_map readiness",
            "DNS cache migration guard and RuntimeOverview samples"
        ],
        "commands_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    })
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
