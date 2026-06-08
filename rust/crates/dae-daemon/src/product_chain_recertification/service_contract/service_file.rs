pub(super) fn service_contract_json(path: &Path) -> Value {
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "status": "fail",
            "path": path_string(path),
            "error": "service file could not be read",
            "service_contract_preserved": false,
        });
    };
    let dae_exec_start_pre =
        text.contains("ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae");
    let dae_exec_start =
        text.contains("ExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae");
    let dae_exec_reload = text.contains("ExecReload=/usr/bin/dae reload $MAINPID");
    let dae_optional_env_file = text.contains("EnvironmentFile=-/etc/default/dae");
    let uses_rust_optin = text.contains("dae-daemon-optin");
    let dae_service_contract_preserved =
        dae_exec_start_pre && dae_exec_start && dae_exec_reload && !uses_rust_optin;
    let daed_exec_start_pre = text.contains("ExecStartPre=/usr/bin/daed validate -c /etc/daed/")
        || text.contains("ExecStartPre=/usr/bin/daed validate -c /etc/daed");
    let daed_exec_start = text.contains("ExecStart=/usr/bin/daed run -c /etc/daed/")
        || text.contains("ExecStart=/usr/bin/daed run -c /etc/daed");
    let daed_exec_reload_signal = text.contains("ExecReload=/bin/kill -HUP $MAINPID");
    let daed_type_simple = text.contains("Type=simple");
    let daed_user_root = text.contains("User=root");
    let daed_optional_env_file = text.contains("EnvironmentFile=-/etc/default/daed");
    let daed_service_contract_preserved = daed_exec_start_pre
        && daed_exec_start
        && daed_exec_reload_signal
        && daed_type_simple
        && daed_user_root;
    let service_contract_preserved =
        dae_service_contract_preserved || daed_service_contract_preserved;
    let service_contract_kind = if daed_service_contract_preserved {
        "daed"
    } else if dae_service_contract_preserved {
        "dae"
    } else {
        "unknown"
    };
    json!({
        "status": if service_contract_preserved { "pass" } else { "fail" },
        "path": path_string(path),
        "service_contract_kind": service_contract_kind,
        "exec_start_pre_validate_preserved": dae_exec_start_pre,
        "exec_start_go_default_run_preserved": dae_exec_start,
        "exec_reload_pid_signal_preserved": dae_exec_reload,
        "optional_env_file_for_backend_rollbacks": dae_optional_env_file,
        "rust_optin_binary_referenced": uses_rust_optin,
        "dae_service_contract_preserved": dae_service_contract_preserved,
        "daed_exec_start_pre_validate_preserved": daed_exec_start_pre,
        "daed_exec_start_run_config_dir_preserved": daed_exec_start,
        "daed_exec_reload_hup_preserved": daed_exec_reload_signal,
        "daed_type_simple_preserved": daed_type_simple,
        "daed_user_root_preserved": daed_user_root,
        "daed_optional_env_file_for_runtime_rollbacks": daed_optional_env_file,
        "daed_service_contract_preserved": daed_service_contract_preserved,
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
