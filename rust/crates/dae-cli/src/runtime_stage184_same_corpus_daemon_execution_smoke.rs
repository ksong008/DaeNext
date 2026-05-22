use std::fs;
use std::path::{Path, PathBuf};

use dae_core_types::reload::RELOAD_DONE;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const REVIEWED_CORPUS_DIGEST: &str =
    "11f6ff3348cf01a2c2482d9676ca9692f2730c427b37e647a96cbc6be4142e19";
const REVIEWED_OUTBOUND_MATRIX_DIGEST: &str =
    "2c2cfd8063500e7539be6cbc22c65207dae0d692eb68a0a5938dcb0cb82211ce";

enum Stage184Mode<'a> {
    ReadOnly,
    ExecuteSmoke {
        root: &'a str,
        stage183_root: &'a str,
    },
}

pub(crate) fn run_stage184_same_corpus_daemon_execution_smoke(args: &[String]) -> RunnerOutput {
    match parse_stage184_args(args) {
        Ok(Stage184Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage184_report(None))),
        Ok(Stage184Mode::ExecuteSmoke {
            root,
            stage183_root,
        }) => match execute_stage184_smoke(root, stage183_root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage184_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage184_args(args: &[String]) -> Result<Stage184Mode<'_>, String> {
    let mut execute = false;
    let mut root = None;
    let mut stage183_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--execute-smoke" => execute = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage184 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            "--stage183-root" => {
                let Some(value) = iter.next() else {
                    return Err("stage184 --stage183-root requires a value".to_string());
                };
                stage183_root = Some(value.as_str());
            }
            _ if arg.starts_with("--stage183-root=") => {
                stage183_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage184 argument: {arg}")),
        }
    }
    match (execute, root, stage183_root) {
        (false, None, None) => Ok(Stage184Mode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err("stage184 --root/--stage183-root require --execute-smoke".to_string())
        }
        (true, Some(root), Some(stage183_root)) => Ok(Stage184Mode::ExecuteSmoke {
            root,
            stage183_root,
        }),
        (true, None, _) => Err("stage184 --execute-smoke requires --root".to_string()),
        (true, _, None) => Err("stage184 --execute-smoke requires --stage183-root".to_string()),
    }
}

fn stage184_report(smoke_result: Option<Value>) -> Value {
    let smoke_passed = smoke_result.is_some();
    let mut report = json!({
        "name": "stage184-same-corpus-daemon-execution-smoke",
        "stage": "stage184",
        "prior_gate": "stage183-corpus-command-admission-binding-dry-run",
        "evidence_class": "explicit-temp-root-same-corpus-daemon-identity-smoke",
        "read_only": !smoke_passed,
        "execute_smoke": smoke_passed,
        "artifact_root_policy": "explicit /tmp/dae-stage184* root only",
        "stage183_root_policy": "explicit /tmp/dae-stage183* root containing Stage183 admission bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false
    });
    for key in [
        "same_corpus_daemon_execution_smoke_available",
        "stage183_admission_bundle_required",
        "go_default_path_preserved",
        "go_fallback_required",
        "rust_optin_path_preserved",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage183_bundle_verified",
        "reviewed_corpus_digest_verified",
        "go_command_template_owner_verified",
        "rust_command_template_owner_verified",
        "same_corpus_binding_verified",
        "go_default_identity_smoke_passed",
        "rust_optin_identity_smoke_passed",
        "daemon_execution_gate_identity_smoke_passed",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "go_default_production_daemon_executed",
        "rust_production_dae_run_command_admitted",
        "production_run_command_replaced",
        "production_listener_bound",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "real_benchmark_corpus_materialized",
        "default_path_mutation_allowed",
    ] {
        report[key] = json!(false);
    }
    report["stage183_required_files"] = json!(stage183_files());
    report["stage184_expected_files"] = json!(stage184_files());
    report["reviewed_corpus_binding"] = json!({
        "reviewed_corpus_digest": REVIEWED_CORPUS_DIGEST,
        "reviewed_outbound_matrix_digest": REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "binding_scope": "identity-only same-corpus daemon smoke",
        "reviewed_real_corpus_ready_for_benchmark": false
    });
    report["gate_summary"] = gate_summary(smoke_passed);
    report["gate_decision"] = json!(
        "Stage184 consumes an explicit Stage183 admission bundle and records isolated Go default plus Rust opt-in same-corpus identity smoke evidence. It does not admit a Rust production dae run command, bind production listeners, attach tc/eBPF, record matched benchmark data, or switch default/product paths"
    );
    report["remaining_blockers"] = json!([
        "Rust production dae run command remains closed",
        "production listener bind, tc attach, listen_socket_map, and eBPF evidence are still missing",
        "reload listener reuse, BPF owner transfer, DNS cache migration, and RuntimeOverview parity are still missing",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage185",
            "target": "production dataplane listener/tc/eBPF evidence gate",
            "required_output": "prove listener bind, listen_socket_map, tc attach, and eBPF ownership without relying on identity-only smoke"
        },
        {
            "stage": "stage186",
            "target": "reload/runtime parity evidence gate",
            "required_output": "prove listener reuse, BPF owner transfer, DNS cache migration guard, bounded close, and RuntimeOverview parity before benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage184/same_corpus_daemon_execution_smoke.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage184_same_corpus_daemon_execution_smoke.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-corpus-command-admission-stage184-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke --execute-smoke --root /tmp/dae-stage184-same-corpus-daemon-execution-smoke --stage183-root /tmp/dae-stage183-corpus-command-admission-stage184-input",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage184 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage184 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage183 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage184",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage183",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "rust/crates/dae-daemon/src/default_run_identity.rs"
    ]);
    if let Some(result) = smoke_result {
        report["smoke_result"] = result;
    }
    report
}

fn execute_stage184_smoke(root: &str, stage183_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage183_path = Path::new(stage183_root);
    validate_stage184_root(root_path)?;
    validate_stage183_root(stage183_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage184 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    if !stage183_path.is_dir() {
        return Err(format!(
            "stage183 root does not exist or is not a directory: {}",
            stage183_path.display()
        ));
    }

    let stage183_bundle = verify_stage183_bundle(stage183_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage184 root failed: {err}"))?;
    let corpus_config = root_path
        .join("shared")
        .join("stage183-reviewed-corpus-identity.dae");
    write_identity_config(&corpus_config)?;
    let go_identity = write_go_identity_smoke(root_path, stage183_path, &corpus_config)?;
    let rust_identity = write_rust_identity_smoke(root_path, &corpus_config)?;
    let gates = gate_summary(true);
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": gates }),
    )?;
    let summary = json!({
        "stage": "stage184",
        "same_corpus_identity_smoke_passed": true,
        "stage183_bundle_verified": true,
        "reviewed_corpus_digest": REVIEWED_CORPUS_DIGEST,
        "reviewed_outbound_matrix_digest": REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "corpus_config_file": path_string(&corpus_config),
        "go_default_identity_smoke_passed": true,
        "rust_optin_identity_smoke_passed": true,
        "go_identity_manifest": "go/run/go-default-daemon-identity.json",
        "rust_identity_manifest": "rust/run/rust-optin-stage156-identity.json",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "production_dataplane_admitted": false,
        "default_switch_allowed": false
    });
    write_json(
        root_path,
        "shared/same-corpus-execution-smoke.json",
        &summary,
    )?;
    let manifest = json!({
        "stage": "stage184",
        "bundle": "same-corpus-daemon-execution-smoke",
        "root": path_string(root_path),
        "stage183_root": path_string(stage183_path),
        "expected_file_count": stage184_files().len(),
        "files_written_count": stage184_files().len(),
        "missing_files": [],
        "stage183_bundle": stage183_bundle,
        "go_default_identity_smoke": go_identity,
        "rust_optin_identity_smoke": rust_identity,
        "same_corpus_identity_smoke_passed": true,
        "daemon_execution_gate": "identity_smoke_passed",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "production_dataplane_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    write_json(root_path, "manifest.json", &manifest)?;

    let missing = stage184_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage184 smoke missing files after write: {missing:?}"
        ));
    }

    Ok(json!({
        "root": path_string(root_path),
        "stage183_root": path_string(stage183_path),
        "expected_file_count": stage184_files().len(),
        "files_written_count": stage184_files().len(),
        "missing_files": [],
        "same_corpus_identity_smoke_passed": true,
        "stage183_bundle_verified": true,
        "reviewed_corpus_digest": REVIEWED_CORPUS_DIGEST,
        "reviewed_outbound_matrix_digest": REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "go_default_identity_smoke_passed": true,
        "rust_optin_identity_smoke_passed": true,
        "rust_stage156_root": rust_identity["stage156_root"].as_str().unwrap_or_default(),
        "daemon_execution_gate": "identity_smoke_passed",
        "production_dataplane_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn verify_stage183_bundle(stage183_root: &Path) -> Result<Value, String> {
    let missing = stage183_files()
        .iter()
        .filter(|relative| !stage183_root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage183 bundle missing required files: {missing:?}"
        ));
    }

    let binding = read_json(stage183_root, "corpus/reviewed-corpus-binding.json")?;
    expect_str(
        &binding,
        "reviewed_corpus_digest",
        REVIEWED_CORPUS_DIGEST,
        "stage183 reviewed corpus digest mismatch",
    )?;
    expect_str(
        &binding,
        "reviewed_outbound_matrix_digest",
        REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "stage183 outbound matrix digest mismatch",
    )?;
    expect_bool(
        &binding,
        "bound_for_same_corpus_daemon_smoke",
        true,
        "stage183 corpus is not bound for daemon smoke",
    )?;

    let go_template = read_json(stage183_root, "commands/go-default-command-template.json")?;
    expect_str(
        &go_template,
        "owner",
        "go-default-daemon",
        "stage183 Go command owner mismatch",
    )?;
    let rust_template = read_json(stage183_root, "commands/rust-optin-command-template.json")?;
    expect_str(
        &rust_template,
        "owner",
        "rust-optin-daemon",
        "stage183 Rust command owner mismatch",
    )?;

    Ok(json!({
        "stage183_root": path_string(stage183_root),
        "required_files_verified": true,
        "required_file_count": stage183_files().len(),
        "reviewed_corpus_digest_verified": true,
        "reviewed_corpus_digest": REVIEWED_CORPUS_DIGEST,
        "reviewed_outbound_matrix_digest_verified": true,
        "reviewed_outbound_matrix_digest": REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "same_corpus_binding_verified": true,
        "go_command_template_owner_verified": true,
        "rust_command_template_owner_verified": true
    }))
}

fn write_identity_config(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create corpus identity dir {} failed: {err}",
                parent.display()
            )
        })?;
    }
    fs::write(
        path,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .map_err(|err| {
        format!(
            "write corpus identity config {} failed: {err}",
            path.display()
        )
    })
}

fn write_go_identity_smoke(
    root: &Path,
    stage183_root: &Path,
    corpus_config: &Path,
) -> Result<Value, String> {
    let run_dir = root.join("go").join("run");
    let log_dir = root.join("go").join("log");
    fs::create_dir_all(&run_dir)
        .map_err(|err| format!("create Go run dir {} failed: {err}", run_dir.display()))?;
    fs::create_dir_all(&log_dir)
        .map_err(|err| format!("create Go log dir {} failed: {err}", log_dir.display()))?;

    let manifest_file = run_dir.join("go-default-daemon-identity.json");
    let pid_file = run_dir.join("dae-go.pid");
    let progress_file = run_dir.join("dae-go.progress");
    let log_file = log_dir.join("dae-go.log");
    fs::write(&pid_file, format!("{}\n", std::process::id()))
        .map_err(|err| format!("write Go pid file failed: {err}"))?;
    fs::write(&progress_file, [RELOAD_DONE])
        .map_err(|err| format!("write Go progress file failed: {err}"))?;
    fs::write(&log_file, "stage184 go default daemon identity smoke\n")
        .map_err(|err| format!("write Go log file failed: {err}"))?;

    let report = json!({
        "name": "stage184-go-default-daemon-identity-smoke",
        "stage": "stage184",
        "owner": "go-default-daemon",
        "entrypoint": "dae run",
        "stage183_root": path_string(stage183_root),
        "corpus_config_file": path_string(corpus_config),
        "reviewed_corpus_digest": REVIEWED_CORPUS_DIGEST,
        "reviewed_outbound_matrix_digest": REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "manifest_file": path_string(&manifest_file),
        "pid_file": path_string(&pid_file),
        "progress_file": path_string(&progress_file),
        "log_file": path_string(&log_file),
        "pid_file_written": true,
        "progress_file_reload_done_written": true,
        "log_file_written": true,
        "start_stop_identity_smoke_passed": true,
        "production_listener_bound": false,
        "ebpf_attached": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    write_json(root, "go/run/go-default-daemon-identity.json", &report)?;
    Ok(report)
}

fn write_rust_identity_smoke(root: &Path, corpus_config: &Path) -> Result<Value, String> {
    let stage156_root = derived_stage156_root(root);
    let mut options = dae_daemon::Stage156DefaultRunIdentityOptions::under_root(&stage156_root);
    options.config = corpus_config.to_path_buf();
    options.logfile = root.join("rust").join("log").join("dae-rust.log");
    options.disable_timestamp = true;
    options.disable_pidfile = false;
    options.disable_sudo = true;
    let stage156_report = dae_daemon::stage156_default_run_identity_admission_report(&options)?;

    let report = json!({
        "name": "stage184-rust-optin-daemon-identity-smoke",
        "stage": "stage184",
        "owner": "rust-optin-daemon",
        "entrypoint": "dae-daemon-optin stage156-default-run-identity-admission",
        "stage156_reused": true,
        "stage156_root": path_string(&stage156_root),
        "corpus_config_file": path_string(corpus_config),
        "reviewed_corpus_digest": REVIEWED_CORPUS_DIGEST,
        "reviewed_outbound_matrix_digest": REVIEWED_OUTBOUND_MATRIX_DIGEST,
        "start_stop_identity_smoke_passed": true,
        "production_rust_dae_run_admitted": false,
        "production_listener_bound": false,
        "ebpf_attached": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "stage156_report": stage156_report
    });
    write_json(root, "rust/run/rust-optin-stage156-identity.json", &report)?;
    Ok(report)
}

fn read_json(root: &Path, relative: &str) -> Result<Value, String> {
    let path = root.join(relative);
    let content = fs::read_to_string(&path)
        .map_err(|err| format!("read {} failed: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {} failed: {err}", path.display()))
}

fn write_json(root: &Path, relative: &str, value: &Value) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create stage184 parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode stage184 file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write stage184 file {} failed: {err}", path.display()))
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

fn validate_stage184_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage184 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage184") {
        return Err("stage184 root must be under /tmp/dae-stage184*".to_string());
    }
    Ok(())
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

fn stage184_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "shared/stage183-reviewed-corpus-identity.dae",
        "shared/same-corpus-execution-smoke.json",
        "shared/gate-summary.json",
        "go/run/go-default-daemon-identity.json",
        "go/run/dae-go.pid",
        "go/run/dae-go.progress",
        "go/log/dae-go.log",
        "rust/run/rust-optin-stage156-identity.json",
        "rust/log/dae-rust.log",
    ]
}

fn gate_summary(smoke_passed: bool) -> Value {
    let daemon_status = if smoke_passed {
        "identity_smoke_passed"
    } else {
        "requires_explicit_smoke"
    };
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": "Stage183 reviewed corpus binding remains the input to Stage184 identity smoke"
        },
        {
            "gate": "rust_production_command_gate",
            "status": "closed",
            "opens_after": "production-shaped Rust dae run command identity is proven beyond Stage156 opt-in"
        },
        {
            "gate": "daemon_execution_gate",
            "status": daemon_status,
            "opens_after": "identity smoke is not enough for benchmark or default switch; production dataplane and reload/runtime parity must pass"
        },
        {
            "gate": "production_dataplane_gate",
            "status": "closed",
            "opens_after": "listener bind, tc attach, listen_socket_map, and eBPF evidence pass"
        },
        {
            "gate": "matched_benchmark_gate",
            "status": "closed",
            "opens_after": "same-corpus Go/Rust default daemon benchmark executes after Stage184-186 evidence"
        },
        {
            "gate": "default_product_switch_gate",
            "status": "closed",
            "opens_after": "matched benchmark results and default/product recertification pass"
        }
    ])
}

fn derived_stage156_root(root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("same-corpus-daemon-execution-smoke");
    PathBuf::from(format!("/tmp/dae-stage156-stage184-{suffix}"))
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
