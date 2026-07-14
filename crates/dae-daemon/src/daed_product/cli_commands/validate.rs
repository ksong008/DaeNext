use super::*;
pub(crate) fn run_validate_command(args: &[String]) -> DaedProductOutput {
    let options = match parse_validate_args(args) {
        Ok(parsed) => parsed,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match validate_product_config_path_with_state(
        &options.path,
        options.runtime,
        options.state.as_deref(),
    ) {
        Ok(report) if options.json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(_) => DaedProductOutput::ok(String::new()),
        Err(err) => DaedProductOutput::error(format!("validate failed: {err}")),
    }
}

pub(crate) struct ValidateOptions {
    pub(crate) path: PathBuf,
    pub(crate) state: Option<PathBuf>,
    pub(crate) json_output: bool,
    pub(crate) runtime: bool,
}

pub(crate) fn parse_validate_args(args: &[String]) -> Result<ValidateOptions, String> {
    let mut config = None;
    let mut state = None;
    let mut json_output = false;
    let mut runtime = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return Err("missing validate --config value".to_owned());
                };
                config = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--config=") => {
                config = arg.split_once('=').map(|(_, value)| PathBuf::from(value));
            }
            "--state" => {
                let Some(value) = iter.next() else {
                    return Err("missing validate --state value".to_owned());
                };
                state = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--state=") => {
                state = arg.split_once('=').map(|(_, value)| PathBuf::from(value));
            }
            "--json" => json_output = true,
            "--runtime" => runtime = true,
            other => return Err(format!("unsupported validate argument: {other}")),
        }
    }
    Ok(ValidateOptions {
        path: config.ok_or_else(|| "validate requires -c/--config".to_owned())?,
        state,
        json_output,
        runtime,
    })
}

#[cfg(test)]
pub(crate) fn validate_product_config_path(path: &Path, runtime: bool) -> Result<Value, String> {
    validate_product_config_path_with_state(path, runtime, None)
}

pub(crate) fn validate_product_config_path_with_state(
    path: &Path,
    runtime: bool,
    state_override: Option<&Path>,
) -> Result<Value, String> {
    if path.is_file() {
        if runtime {
            return Err("runtime validation requires a daed config directory".to_owned());
        }
        if state_override.is_some() {
            return Err("validate --state requires a daed config directory".to_owned());
        }
        let entries = validate_config_file(path)?;
        return Ok(json!({
            "status": "pass",
            "kind": "dae-config-file",
            "path": path_string(path),
            "entries": entries,
            "readOnly": true,
            "mutationExecuted": false,
        }));
    }
    if path.is_dir() {
        return validate_product_config_dir_with_state(path, runtime, state_override);
    }
    Err(format!(
        "config path is neither file nor directory: {}",
        path_string(path)
    ))
}

pub(crate) fn validate_product_config_dir_with_state(
    config_dir: &Path,
    runtime: bool,
    state_override: Option<&Path>,
) -> Result<Value, String> {
    let state = state_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| config_dir.join("daed.db"));
    let state_present = state.is_file();
    let mut tables = Vec::new();
    let mut schema_ready = false;
    let mut user_count = Value::Null;
    let mut schema_version = Value::Null;
    let mut state_connection = None;
    if state_present {
        let conn = open_state_connection_read_only(&state)
            .map_err(|err| format!("failed to open state read-only: {err}"))?;
        let snapshot = inspect_state_connection_read_only(&conn, runtime)
            .map_err(|err| format!("state integrity validation failed: {err}"))?;
        tables = snapshot.tables;
        schema_ready = snapshot.schema_current;
        user_count = json!(snapshot.user_count);
        schema_version = json!(snapshot.schema_version);
        state_connection = Some(conn);
    }
    if runtime && !state_present {
        return Err(format!(
            "runtime validation requires state db: {}",
            path_string(&state)
        ));
    }
    let mut report = json!({
        "status": "pass",
        "kind": "daed-config-dir",
        "path": path_string(config_dir),
        "state": path_string(&state),
        "stateExplicit": state_override.is_some(),
        "statePresent": state_present,
        "stateSchemaReady": schema_ready,
        "stateMigrationRequired": state_present && !schema_ready,
        "stateSchemaVersion": schema_version,
        "stateSupportedSchemaVersion": STATE_SCHEMA_VERSION,
        "stateQuickCheck": if state_present { Value::String("ok".to_owned()) } else { Value::Null },
        "freshInstallStateOptional": !state_present,
        "userCount": user_count,
        "tables": tables,
        "primaryStateStore": PRIMARY_STATE_STORE,
        "legacyImportStateStore": LEGACY_IMPORT_STATE_STORE,
        "rustDaedWritesWingDbByDefault": false,
        "readOnly": true,
        "mutationExecuted": false,
    });
    if runtime {
        let conn = state_connection.as_ref().ok_or_else(|| {
            format!(
                "runtime validation requires state db: {}",
                path_string(&state)
            )
        })?;
        let plan = prepare_runtime_materialization_plan_with_connection(conn)
            .map_err(|err| format!("runtime materialization validation failed: {err}"))?;
        build_runtime_config_from_content(&plan.content)
            .map_err(|err| format!("runtime config validation failed: {err}"))?;
        if let Value::Object(map) = &mut report {
            map.insert(
                "runtimeValidation".to_owned(),
                plan.report(Some(config_dir), false),
            );
        }
    }
    Ok(report)
}
