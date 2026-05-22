use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const REVIEWED_CORPUS_DIGEST: &str =
    "11f6ff3348cf01a2c2482d9676ca9692f2730c427b37e647a96cbc6be4142e19";
const REVIEWED_OUTBOUND_MATRIX_DIGEST: &str =
    "2c2cfd8063500e7539be6cbc22c65207dae0d692eb68a0a5938dcb0cb82211ce";

enum Stage183Mode<'a> {
    ReadOnly,
    WriteAdmissionDryRun { root: &'a str },
}

pub(crate) fn run_stage183_corpus_command_admission_binding(args: &[String]) -> RunnerOutput {
    match parse_stage183_args(args) {
        Ok(Stage183Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage183_report(None))),
        Ok(Stage183Mode::WriteAdmissionDryRun { root }) => match write_stage183_bundle(root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage183_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage183_args(args: &[String]) -> Result<Stage183Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-admission-dry-run" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage183 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            _ => return Err(format!("unsupported stage183 argument: {arg}")),
        }
    }
    match (write, root) {
        (false, None) => Ok(Stage183Mode::ReadOnly),
        (false, Some(_)) => Err("stage183 --root requires --write-admission-dry-run".to_string()),
        (true, Some(root)) => Ok(Stage183Mode::WriteAdmissionDryRun { root }),
        (true, None) => Err("stage183 --write-admission-dry-run requires --root".to_string()),
    }
}

fn stage183_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage183-corpus-command-admission-binding-dry-run",
        "stage": "stage183",
        "prior_gate": "stage182-production-rust-daemon-admission-preflight",
        "evidence_class": "explicit-temp-root-corpus-command-admission-binding",
        "read_only": !written,
        "write_admission_dry_run": written,
        "artifact_root_policy": "explicit /tmp/dae-stage183* root only",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    });
    for key in [
        "corpus_command_admission_binding_available",
        "stage178_reviewed_artifact_carried",
        "stage179_verifier_carried",
        "stage182_preflight_carried",
        "go_rust_command_templates_bound",
        "explicit_temp_root_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    report["admission_bundle_written"] = json!(written);
    report["bundle_files"] = json!(stage183_files());
    report["reviewed_corpus_binding"] = reviewed_corpus_binding();
    report["go_default_command_template"] = go_default_command_template();
    report["rust_optin_command_template"] = rust_optin_command_template();
    report["closed_gates"] = closed_gates();
    report["gate_decision"] = json!(
        "Stage183 writes or describes a corpus plus command admission binding for the next daemon smoke. It binds Stage178/179 reviewed corpus evidence and Stage182 command preflight to Go/Rust command templates, but does not execute daemons, bind production dataplane, enable benchmark execution, or switch default/product paths"
    );
    report["next_stage"] = json!({
        "stage": "stage184",
        "target": "same-corpus daemon execution smoke",
        "required_input": "explicit Stage183 corpus-command admission bundle plus reviewed corpus materialization evidence"
    });
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage183/corpus_command_admission_binding_dry_run.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage183_corpus_command_admission_binding_dry_run.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-corpus-command-admission-dry-run",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage183 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage183 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage182 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage183",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage182",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage179",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage178",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn write_stage183_bundle(root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    validate_stage183_root(root_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage183 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    fs::create_dir_all(root_path).map_err(|err| format!("create stage183 root failed: {err}"))?;
    let files = [
        (
            "manifest.json",
            json!({
                "stage": "stage183",
                "bundle": "corpus-command-admission-binding",
                "stage178_reviewed_artifact_carried": true,
                "stage179_verifier_carried": true,
                "stage182_preflight_carried": true,
                "commands_executed": false,
                "benchmark_executable_now": false,
                "matched_go_rust_default_daemon_benchmark_recorded": false
            }),
        ),
        (
            "corpus/reviewed-corpus-binding.json",
            reviewed_corpus_binding(),
        ),
        (
            "commands/go-default-command-template.json",
            go_default_command_template(),
        ),
        (
            "commands/rust-optin-command-template.json",
            rust_optin_command_template(),
        ),
        (
            "shared/gate-summary.json",
            json!({ "closed_gates": closed_gates() }),
        ),
        (
            "next/stage184-daemon-smoke-input.json",
            json!({
                "stage": "stage183",
                "next_stage": "stage184",
                "input_bundle_ready_for_daemon_smoke": true,
                "commands_executed": false,
                "requires_reviewed_corpus_materialization": true,
                "requires_go_default_daemon": true,
                "requires_rust_optin_daemon": true,
                "benchmark_executable_now": false
            }),
        ),
    ];
    for (relative, value) in &files {
        write_json(root_path, relative, value)?;
    }
    let missing = stage183_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    Ok(json!({
        "root": root_path.display().to_string(),
        "expected_file_count": stage183_files().len(),
        "files_written_count": stage183_files().len() - missing.len(),
        "missing_files": missing,
        "admission_bundle_written": true,
        "commands_executed": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    }))
}

fn write_json(root: &Path, relative: &str, value: &Value) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create stage183 parent {} failed: {err}", parent.display()))?;
    }
    fs::write(&path, format!("{value}\n"))
        .map_err(|err| format!("write stage183 file {} failed: {err}", path.display()))
}

fn validate_stage183_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage183 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage183") {
        return Err("stage183 root must be under /tmp/dae-stage183*".to_string());
    }
    Ok(())
}

fn stage183_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "corpus/reviewed-corpus-binding.json",
        "commands/go-default-command-template.json",
        "commands/rust-optin-command-template.json",
        "shared/gate-summary.json",
        "next/stage184-daemon-smoke-input.json",
    ]
}

fn reviewed_corpus_binding() -> Value {
    json!({
        "stage": "stage183",
        "source_stage": "stage178",
        "verifier_stage": "stage179",
        "reviewed_corpus_digest": REVIEWED_CORPUS_DIGEST,
        "reviewed_outbound_matrix_digest": REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "secret_material_present": false,
        "reviewed_real_corpus_ready_for_benchmark": false,
        "bound_for_same_corpus_daemon_smoke": true
    })
}

fn go_default_command_template() -> Value {
    json!({
        "owner": "go-default-daemon",
        "entrypoint": "dae run",
        "command": [
            "dae",
            "run",
            "--disable-timestamp",
            "--logfile",
            "<stage184-root>/go/dae.log",
            "-c",
            "<stage183-root>/corpus/reviewed-corpus.dae"
        ],
        "executes_now": false,
        "default_path_preserved": true
    })
}

fn rust_optin_command_template() -> Value {
    json!({
        "owner": "rust-optin-daemon",
        "entrypoint": "dae-daemon-optin stage156-default-run-identity-admission",
        "command": [
            "dae-daemon-optin",
            "stage156-default-run-identity-admission",
            "--disable-timestamp",
            "--disable-sudo",
            "--logfile",
            "<stage184-root>/rust/dae.log",
            "-c",
            "<stage183-root>/corpus/reviewed-corpus.dae"
        ],
        "executes_now": false,
        "production_rust_dae_run_admitted": false
    })
}

fn closed_gates() -> Value {
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": "Stage184 consumes explicit Stage183 bundle and proves same-corpus daemon execution"
        },
        {
            "gate": "rust_production_command_gate",
            "status": "closed",
            "opens_after": "production-shaped Rust dae run command identity is proven beyond Stage156 opt-in"
        },
        {
            "gate": "daemon_execution_gate",
            "status": "closed",
            "opens_after": "Go default daemon and Rust opt-in daemon execute on the same reviewed corpus"
        },
        {
            "gate": "production_dataplane_gate",
            "status": "closed",
            "opens_after": "listener bind, tc attach, listen_socket_map, and eBPF evidence pass"
        },
        {
            "gate": "matched_benchmark_gate",
            "status": "closed",
            "opens_after": "benchmark readiness admission confirms Stage184-186 evidence"
        },
        {
            "gate": "default_product_switch_gate",
            "status": "closed",
            "opens_after": "matched benchmark results and default/product recertification pass"
        }
    ])
}
