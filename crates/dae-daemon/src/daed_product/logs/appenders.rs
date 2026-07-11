use super::*;
pub(crate) fn append_log_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
) -> io::Result<()> {
    append_log_fields_for_config(config_dir, state, level, message, BTreeMap::new())
}

pub(crate) fn append_lifecycle_log_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
) -> io::Result<()> {
    append_lifecycle_log_fields_for_config(config_dir, state, level, message, BTreeMap::new())
}

pub(crate) fn append_log_fields_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
    fields: BTreeMap<String, String>,
) -> io::Result<()> {
    append_log_fields_for_config_with_policy(config_dir, state, level, message, fields, true)
}

pub(crate) fn append_lifecycle_log_fields_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
    mut fields: BTreeMap<String, String>,
) -> io::Result<()> {
    let kind = startup_reload_lifecycle_log_kind(message);
    if let Some(kind) = kind {
        fields
            .entry("lifecycle".to_owned())
            .or_insert_with(|| kind.to_owned());
    }
    append_log_fields_for_config_with_policy(
        config_dir,
        state,
        level,
        message,
        fields,
        kind.is_none(),
    )
}

pub(crate) fn append_startup_step_completed_for_config(
    config_dir: &Path,
    state: &Path,
    step: &str,
    started_at: Instant,
    _fields: BTreeMap<String, String>,
) -> io::Result<()> {
    let mut fields = BTreeMap::new();
    fields.insert("step".to_owned(), step.to_owned());
    fields.insert("elapsed".to_owned(), format!("{:?}", started_at.elapsed()));
    append_lifecycle_log_fields_for_config(
        config_dir,
        state,
        "info",
        "[Startup] step completed",
        fields,
    )
}

pub(crate) fn append_startup_step_failed_for_config(
    config_dir: &Path,
    state: &Path,
    step: &str,
    started_at: Instant,
    error: &str,
    mut fields: BTreeMap<String, String>,
) -> io::Result<()> {
    fields.insert("step".to_owned(), step.to_owned());
    fields.insert("elapsed".to_owned(), format!("{:?}", started_at.elapsed()));
    fields.insert("error".to_owned(), error.to_owned());
    append_lifecycle_log_fields_for_config(
        config_dir,
        state,
        "warn",
        "[Startup] step failed",
        fields,
    )
}

pub(crate) fn append_startup_runtime_evidence_logs_for_config(
    config_dir: &Path,
    state: &Path,
    report: &Value,
) -> io::Result<()> {
    let evidence = report
        .get("residentStartupEvidence")
        .or_else(|| report.get("startupEvidence"))
        .unwrap_or(&Value::Null);
    let bpf_loader = evidence.get("bpfLoader").filter(|value| !value.is_null());
    if let Some(loader) = bpf_loader {
        append_lifecycle_log_for_config(
            config_dir,
            state,
            "info",
            "The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure.",
        )?;
        let mut fields = BTreeMap::new();
        insert_json_log_field(&mut fields, "object_source", loader.get("objectSource"));
        insert_json_log_field(
            &mut fields,
            "default_object_source",
            loader.get("defaultObjectSource"),
        );
        insert_json_log_field(
            &mut fields,
            "kernel_ebpf_program_rewrite",
            loader.get("kernelEbpfProgramRewrite"),
        );
        append_lifecycle_log_fields_for_config(
            config_dir,
            state,
            "info",
            "Rust/Aya BPF loader loaded",
            fields,
        )?;
    }

    if let Some(loaded) = evidence.get("loadedEbpf").filter(|loaded| {
        json_scalar_to_u64(loaded.get("programCount")).unwrap_or(0) > 0
            || json_scalar_to_u64(loaded.get("mapCount")).unwrap_or(0) > 0
    }) {
        let mut fields = BTreeMap::new();
        insert_json_log_field(&mut fields, "program_count", loaded.get("programCount"));
        insert_json_log_field(&mut fields, "map_count", loaded.get("mapCount"));
        append_lifecycle_log_fields_for_config(
            config_dir,
            state,
            "info",
            "Loaded eBPF programs and maps",
            fields,
        )?;
    }

    if let Some(bindings) = evidence.get("bindings").and_then(Value::as_array) {
        for binding in bindings {
            let Some(program) = binding.get("programName").and_then(Value::as_str) else {
                continue;
            };
            let Some(interface) = binding.get("interface").and_then(Value::as_str) else {
                continue;
            };
            let backend = binding.get("backend").and_then(Value::as_str);
            let mut fields = BTreeMap::new();
            insert_json_log_field(&mut fields, "role", binding.get("role"));
            insert_json_log_field(&mut fields, "direction", binding.get("direction"));
            insert_json_log_field(&mut fields, "priority", binding.get("priority"));
            insert_json_log_field(&mut fields, "handle", binding.get("handle"));
            let message = if let Some(backend) = backend {
                format!("Bind {program} via Rust/Aya {backend} on {interface}")
            } else {
                format!("Bind {program} via Rust/Aya on {interface}")
            };
            append_lifecycle_log_fields_for_config(config_dir, state, "info", &message, fields)?;
        }
    }

    if let Some(routing_sets) = evidence.get("routingMatchSets").and_then(Value::as_array) {
        for routing in routing_sets {
            let Some(len) = json_scalar_to_string(routing.get("len")) else {
                continue;
            };
            let Some(max_entries) = json_scalar_to_string(routing.get("maxEntries")) else {
                continue;
            };
            let mut fields = BTreeMap::new();
            insert_json_log_field(&mut fields, "interface", routing.get("interface"));
            insert_json_log_field(&mut fields, "map", routing.get("mapName"));
            insert_json_log_field(&mut fields, "map_id", routing.get("mapId"));
            append_lifecycle_log_fields_for_config(
                config_dir,
                state,
                "info",
                &format!("Routing match set len: {len}/{max_entries}"),
                fields,
            )?;
        }
    }

    Ok(())
}

pub(crate) fn insert_json_log_field(
    fields: &mut BTreeMap<String, String>,
    key: &str,
    value: Option<&Value>,
) {
    if let Some(value) = json_scalar_to_string(value) {
        fields.insert(key.to_owned(), value);
    }
}

pub(crate) fn json_scalar_to_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(crate) fn json_scalar_to_u64(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

pub(crate) fn append_log_fields_for_config_with_policy(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
    fields: BTreeMap<String, String>,
    respect_runtime_log_level: bool,
) -> io::Result<()> {
    let Some(level) = normalize_log_level_name(level) else {
        return Ok(());
    };
    if let Some(runtime) = product_log_runtime_for(config_dir) {
        return runtime.append(level, message, fields, respect_runtime_log_level);
    }
    if respect_runtime_log_level {
        let runtime_level = current_runtime_log_level(state)?;
        if !log_level_enabled(&level, &runtime_level) {
            return Ok(());
        }
    }
    #[cfg(test)]
    observe_log_settings_read(state);
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let (max_entries, max_bytes) = log_settings_tuple(&conn)?;
    let log_file = product_log_file(config_dir);
    ensure_log_dir(config_dir)?;
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    let id = next_log_id(&log_file)?;
    let line = encode_log_entry_line(id, &level, message, fields)?;
    append_log_line(&log_file, &line)?;
    prune_log_file_if_needed(&log_file, max_entries, max_bytes, id)?;
    Ok(())
}

pub(crate) fn append_startup_reclaim_decision_log_for_config(
    config_dir: &Path,
    state: &Path,
    _report: &Value,
    force: bool,
) -> io::Result<()> {
    let mut fields = BTreeMap::new();
    fields.insert("force".to_owned(), force.to_string());
    fields.insert(
        "allocator_profile".to_owned(),
        allocator_profile().to_owned(),
    );
    append_lifecycle_log_fields_for_config(
        config_dir,
        state,
        "info",
        "[Startup] post-startup gc decision",
        fields,
    )
}
