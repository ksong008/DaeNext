use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use super::path_string;

pub(super) fn service_contract_json(path: &Path) -> Value {
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "status": "fail",
            "path": path_string(path),
            "error": "service file could not be read",
            "service_contract_preserved": false,
        });
    };
    let exec_start_pre = text.contains("ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae");
    let exec_start =
        text.contains("ExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae");
    let exec_reload = text.contains("ExecReload=/usr/bin/dae reload $MAINPID");
    let optional_env_file = text.contains("EnvironmentFile=-/etc/default/dae");
    let uses_rust_optin = text.contains("dae-daemon-optin");
    let service_contract_preserved =
        exec_start_pre && exec_start && exec_reload && !uses_rust_optin;
    json!({
        "status": if service_contract_preserved { "pass" } else { "fail" },
        "path": path_string(path),
        "exec_start_pre_validate_preserved": exec_start_pre,
        "exec_start_go_default_run_preserved": exec_start,
        "exec_reload_pid_signal_preserved": exec_reload,
        "optional_env_file_for_backend_rollbacks": optional_env_file,
        "rust_optin_binary_referenced": uses_rust_optin,
        "service_contract_preserved": service_contract_preserved,
    })
}

pub(super) fn candidate_validate_report(
    requested: bool,
    binary_source: Option<&Path>,
    staged_config_source: Option<&Path>,
) -> Value {
    let executable = requested
        && binary_source.is_some_and(Path::is_file)
        && staged_config_source.is_some_and(Path::is_file);
    if !executable {
        return json!({
            "executed": false,
            "passed": false,
            "command": Value::Null,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": "",
        });
    }
    let binary_source = binary_source.unwrap();
    let staged_config_source = staged_config_source.unwrap();
    let command = vec![
        path_string(binary_source),
        "validate".to_owned(),
        "-c".to_owned(),
        path_string(staged_config_source),
    ];
    match run_candidate_command(
        binary_source,
        &["validate", "-c"],
        Some(staged_config_source),
    ) {
        Ok(output) => json!({
            "executed": true,
            "passed": output.status.success(),
            "command": command,
            "exit_code": output.status.code(),
            "stdout": bounded_command_output(&output.stdout),
            "stderr": bounded_command_output(&output.stderr),
        }),
        Err(err) => json!({
            "executed": true,
            "passed": false,
            "command": command,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": err.to_string(),
        }),
    }
}

pub(super) fn candidate_service_contract_report(
    requested: bool,
    binary_source: Option<&Path>,
) -> Value {
    let executable = requested && binary_source.is_some_and(Path::is_file);
    if !executable {
        return json!({
            "executed": false,
            "passed": false,
            "command": Value::Null,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": "",
            "resident_run_service_contract_ready": false,
            "reload_command_service_contract_ready": false,
            "resident_production_dataplane_ready": false,
            "resident_default_daemon_switch_ready": false,
            "resident_dataplane_default_switch_ready": false,
            "resident_dataplane_env": Value::Null,
            "resident_dataplane_env_enabled": false,
            "default_path_switch_blocker": Value::Null,
            "reload_failure_rollback_supported": false,
            "invalid_runtime_config_rejected_before_current_swap": false,
            "reload_start_failure_attempts_previous_runtime_restore": false,
        });
    }
    let binary_source = binary_source.unwrap();
    let command = vec![path_string(binary_source), "service-contract".to_owned()];
    match run_candidate_command(binary_source, &["service-contract"], None) {
        Ok(output) => {
            let stdout = bounded_command_output(&output.stdout);
            let capability = serde_json::from_slice::<Value>(&output.stdout).unwrap_or(Value::Null);
            let resident_run_ready = capability["resident_run_service_contract_ready"]
                .as_bool()
                .unwrap_or(false);
            let reload_ready = capability["reload_command_service_contract_ready"]
                .as_bool()
                .unwrap_or(false);
            let resident_production_dataplane_ready =
                capability["resident_production_dataplane_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_default_daemon_switch_declared =
                capability["resident_default_daemon_switch_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_dataplane_default_switch_ready =
                capability["resident_dataplane_default_switch_ready"]
                    .as_bool()
                    .unwrap_or(resident_default_daemon_switch_declared);
            let resident_dataplane_env = capability["resident_dataplane_env"]
                .as_str()
                .map(str::to_owned);
            let resident_dataplane_env_enabled = capability["resident_dataplane_env_enabled"]
                .as_bool()
                .unwrap_or(resident_dataplane_default_switch_ready);
            let default_path_switch_blocker = capability["default_path_switch_blocker"].clone();
            let reload_failure_rollback_supported = capability["reload_failure_rollback_supported"]
                .as_bool()
                .unwrap_or(false);
            let invalid_runtime_config_rejected_before_current_swap =
                capability["invalid_runtime_config_rejected_before_current_swap"]
                    .as_bool()
                    .unwrap_or(false);
            let reload_start_failure_attempts_previous_runtime_restore =
                capability["reload_start_failure_attempts_previous_runtime_restore"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_default_daemon_switch_ready = output.status.success()
                && resident_run_ready
                && reload_ready
                && resident_production_dataplane_ready
                && resident_default_daemon_switch_declared
                && reload_failure_rollback_supported
                && invalid_runtime_config_rejected_before_current_swap
                && reload_start_failure_attempts_previous_runtime_restore;
            json!({
                "executed": true,
                "passed": output.status.success()
                    && resident_run_ready
                    && reload_ready
                    && reload_failure_rollback_supported
                    && invalid_runtime_config_rejected_before_current_swap
                    && reload_start_failure_attempts_previous_runtime_restore,
                "command": command,
                "exit_code": output.status.code(),
                "stdout": stdout,
                "stderr": bounded_command_output(&output.stderr),
                "resident_run_service_contract_ready": output.status.success() && resident_run_ready,
                "reload_command_service_contract_ready": output.status.success() && reload_ready,
                "resident_production_dataplane_ready": output.status.success() && resident_production_dataplane_ready,
                "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
                "resident_dataplane_default_switch_ready": output.status.success() && resident_dataplane_default_switch_ready,
                "resident_dataplane_env": resident_dataplane_env,
                "resident_dataplane_env_enabled": output.status.success() && resident_dataplane_env_enabled,
                "default_path_switch_blocker": default_path_switch_blocker,
                "reload_failure_rollback_supported": output.status.success() && reload_failure_rollback_supported,
                "invalid_runtime_config_rejected_before_current_swap": output.status.success() && invalid_runtime_config_rejected_before_current_swap,
                "reload_start_failure_attempts_previous_runtime_restore": output.status.success() && reload_start_failure_attempts_previous_runtime_restore,
                "capability": capability,
            })
        }
        Err(err) => json!({
            "executed": true,
            "passed": false,
            "command": command,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": err.to_string(),
            "resident_run_service_contract_ready": false,
            "reload_command_service_contract_ready": false,
            "resident_production_dataplane_ready": false,
            "resident_default_daemon_switch_ready": false,
            "resident_dataplane_default_switch_ready": false,
            "resident_dataplane_env": Value::Null,
            "resident_dataplane_env_enabled": false,
            "default_path_switch_blocker": Value::Null,
            "reload_failure_rollback_supported": false,
            "invalid_runtime_config_rejected_before_current_swap": false,
            "reload_start_failure_attempts_previous_runtime_restore": false,
        }),
    }
}

fn run_candidate_command(
    binary_source: &Path,
    args: &[&str],
    path_arg: Option<&Path>,
) -> io::Result<Output> {
    const MAX_ATTEMPTS: usize = 20;
    for attempt in 0..MAX_ATTEMPTS {
        let mut command = Command::new(binary_source);
        command.args(args);
        if let Some(path_arg) = path_arg {
            command.arg(path_arg);
        }
        match command.output() {
            Err(err) if err.raw_os_error() == Some(libc::ETXTBSY) && attempt + 1 < MAX_ATTEMPTS => {
                thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
    unreachable!("candidate command retry loop always returns")
}

fn bounded_command_output(bytes: &[u8]) -> String {
    const MAX_OUTPUT_BYTES: usize = 4000;
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT_BYTES)]).into_owned()
}
