use super::*;
pub(crate) fn run_validate_command(args: &[String]) -> DaedProductOutput {
    let options = match parse_validate_args(args) {
        Ok(parsed) => parsed,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match validate_product_config_path(&options.path, options.runtime) {
        Ok(report) if options.json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(_) => DaedProductOutput::ok(String::new()),
        Err(err) => DaedProductOutput::error(format!("validate failed: {err}")),
    }
}

pub(crate) struct ValidateOptions {
    path: PathBuf,
    json_output: bool,
    runtime: bool,
}

pub(crate) fn parse_validate_args(args: &[String]) -> Result<ValidateOptions, String> {
    let mut config = None;
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
            "--json" => json_output = true,
            "--runtime" => runtime = true,
            other => return Err(format!("unsupported validate argument: {other}")),
        }
    }
    Ok(ValidateOptions {
        path: config.ok_or_else(|| "validate requires -c/--config".to_owned())?,
        json_output,
        runtime,
    })
}

pub(crate) fn validate_product_config_path(path: &Path, runtime: bool) -> Result<Value, String> {
    if path.is_file() {
        if runtime {
            return Err("runtime validation requires a daed config directory".to_owned());
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
        return validate_product_config_dir(path, runtime);
    }
    Err(format!(
        "config path is neither file nor directory: {}",
        path_string(path)
    ))
}

pub(crate) fn validate_product_config_dir(
    config_dir: &Path,
    runtime: bool,
) -> Result<Value, String> {
    let state = config_dir.join("daed.db");
    let state_present = state.is_file();
    let mut tables = Vec::new();
    let mut schema_ready = false;
    let mut user_count = Value::Null;
    if state_present {
        let conn = Connection::open_with_flags(&state, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|err| format!("failed to open state read-only: {err}"))?;
        tables = list_tables(&conn).map_err(|err| format!("failed to list state tables: {err}"))?;
        schema_ready = tables.iter().any(|name| name == "daed_product_metadata")
            && tables.iter().any(|name| name == "daed_schema_migrations")
            && tables.iter().any(|name| name == "users");
        if !schema_ready {
            return Err(format!(
                "state schema is not ready for read-only validation: {}",
                path_string(&state)
            ));
        }
        let users = conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
            .map_err(|err| format!("failed to count users: {err}"))?;
        user_count = json!(users);
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
        "statePresent": state_present,
        "stateSchemaReady": schema_ready,
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
        let plan = prepare_runtime_materialization_plan(&state)
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
