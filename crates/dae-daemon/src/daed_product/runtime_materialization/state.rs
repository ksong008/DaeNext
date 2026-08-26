use super::*;

pub(in crate::daed_product) fn general_state_report(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let runtime_state = runtime.summary();
    let running = runtime_state["running"].as_bool().unwrap_or(false);
    let selected_config_id = selected_id(&conn, SectionKind::Config)?;
    let selected_dns_id = selected_id(&conn, SectionKind::Dns)?;
    let selected_routing_id = selected_id(&conn, SectionKind::Routing)?;
    let runtime_revision = runtime_revision_report_from_connection(&conn, runtime, &runtime_state)?;
    let modified = running
        && !runtime_revision["desiredMatchesActive"]
            .as_bool()
            .unwrap_or(false);
    Ok(json!({
        "running": running,
        "modified": modified,
        "version": crate::version::version_from_env(),
        "netnsLinkMode": runtime_state["netnsLinkMode"].clone(),
        "attachBackend": runtime_state["attachBackend"].clone(),
        "runtime": runtime_state,
        "runtimeRevision": runtime_revision,
        "updatedAt": now_text(),
        "state": path_string(state),
        "selected": {
            "configId": selected_config_id,
            "dnsId": selected_dns_id,
            "routingId": selected_routing_id,
        },
        "counts": {
            "configs": count_table(&conn, "configs")?,
            "dns": count_table(&conn, "dns")?,
            "routings": count_table(&conn, "routings")?,
            "groups": count_table(&conn, "groups")?,
            "nodes": count_table(&conn, "nodes")?,
            "subscriptions": count_table(&conn, "subscriptions")?,
            "logs": count_log_file_entries(config_dir)?,
        }
    }))
}

pub(in crate::daed_product) fn runtime_revision_report(
    state: &Path,
    runtime: &ProductRuntimeManager,
    runtime_state: &Value,
) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    runtime_revision_report_from_connection(&conn, runtime, runtime_state)
}

fn runtime_revision_report_from_connection(
    conn: &Connection,
    runtime: &ProductRuntimeManager,
    runtime_state: &Value,
) -> io::Result<Value> {
    let desired_external_revision = current_runtime_external_input_version(conn)?;
    let active_fingerprint =
        metadata_value_from_connection(conn, RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY)?;
    let desired_plan = active_fingerprint
        .as_ref()
        .map(|_| prepare_runtime_materialization_plan_with_connection(conn))
        .transpose()?;
    let desired = match desired_plan.as_ref() {
        Some(plan) => json!({
            "config": {"id": plan.config_id, "version": plan.config_version},
            "dns": {"id": plan.dns_id, "version": plan.dns_version},
            "routing": {"id": plan.routing_id, "version": plan.routing_version},
            "groupVersionSum": plan.group_version_sum,
            "groupIds": plan.group_ids,
            "externalInputVersion": desired_external_revision,
            "activeFingerprint": plan.active_fingerprint.as_str(),
        }),
        None => json!({
            "config": section_revision_value(selected_section_state(conn, SectionKind::Config)?),
            "dns": section_revision_value(selected_section_state(conn, SectionKind::Dns)?),
            "routing": section_revision_value(selected_section_state(conn, SectionKind::Routing)?),
            "groupVersionSum": group_version_sum(conn)?,
            "groupIds": group_ids_text(conn)?,
            "externalInputVersion": desired_external_revision,
            "activeFingerprint": Value::Null,
        }),
    };
    let active_state = running_runtime_state(conn)?;
    let active = active_state
        .as_ref()
        .map(|state| active_runtime_revision_value(state, active_fingerprint.as_deref()))
        .unwrap_or(Value::Null);
    let running = runtime_state["running"].as_bool().unwrap_or(false);
    let desired_matches_active = active_state.as_ref().is_some_and(|active| {
        desired_plan
            .as_ref()
            .zip(active_fingerprint.as_deref())
            .map_or_else(
                || active_runtime_revision_matches(active, &desired),
                |(plan, active_fingerprint)| plan.active_fingerprint.as_str() == active_fingerprint,
            )
    });
    let runtime_product_generation = runtime_state["activeGeneration"].as_str();
    let identity = compare_runtime_activation_identity(
        conn,
        runtime,
        runtime_product_generation.map(str::to_owned),
    )?;
    let activation_identity_consistent =
        !running || (identity.product_generation_matches && identity.probe_generation_matches);

    Ok(json!({
        "desired": desired,
        "active": active,
        "desiredMatchesActive": desired_matches_active,
        "pending": running && !desired_matches_active,
        "activeProductGeneration": runtime_product_generation,
        "persistedProductGeneration": identity.persisted_product_generation,
        "activeResidentProbeGeneration": identity.runtime_probe_generation,
        "persistedResidentProbeGeneration": identity.persisted_probe_generation,
        "productGenerationMatches": if running { json!(identity.product_generation_matches) } else { Value::Null },
        "probeGenerationMatches": identity.probe_generation_matches,
        "activationIdentityConsistent": activation_identity_consistent,
    }))
}

pub(in crate::daed_product) fn runtime_activation_identity_consistent(
    state: &Path,
    runtime: &ProductRuntimeManager,
) -> io::Result<bool> {
    let conn = open_state_connection(state)?;
    let identity =
        compare_runtime_activation_identity(&conn, runtime, runtime.active_generation())?;
    Ok(identity.product_generation_matches && identity.probe_generation_matches)
}

struct RuntimeActivationIdentityComparison {
    persisted_product_generation: Option<String>,
    runtime_probe_generation: Option<u64>,
    persisted_probe_generation: Option<u64>,
    product_generation_matches: bool,
    probe_generation_matches: bool,
}

fn compare_runtime_activation_identity(
    conn: &Connection,
    runtime: &ProductRuntimeManager,
    runtime_product_generation: Option<String>,
) -> io::Result<RuntimeActivationIdentityComparison> {
    let persisted_product_generation =
        metadata_value_from_connection(conn, RUNTIME_GENERATION_METADATA_KEY)?;
    let runtime_probe_generation = runtime.current_probe_generation();
    let persisted_probe_generation =
        metadata_value_from_connection(conn, RUNTIME_PROBE_GENERATION_METADATA_KEY)?
            .map(|value| {
                value.parse::<u64>().map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid persisted runtime probe generation {value:?}: {err}"),
                    )
                })
            })
            .transpose()?;
    let product_generation_matches = runtime_product_generation
        .as_deref()
        .zip(persisted_product_generation.as_deref())
        .is_some_and(|(runtime, persisted)| runtime == persisted);
    let probe_generation_matches = runtime_probe_generation == persisted_probe_generation;
    Ok(RuntimeActivationIdentityComparison {
        persisted_product_generation,
        runtime_probe_generation,
        persisted_probe_generation,
        product_generation_matches,
        probe_generation_matches,
    })
}

fn section_revision_value(section: Option<RuntimeSectionState>) -> Value {
    section
        .map(|section| json!({"id": section.id, "version": section.version}))
        .unwrap_or(Value::Null)
}

fn active_runtime_revision_value(
    active: &RunningRuntimeState,
    active_fingerprint: Option<&str>,
) -> Value {
    json!({
        "config": {"id": active.config_id, "version": active.config_version},
        "dns": {"id": active.dns_id, "version": active.dns_version},
        "routing": {"id": active.routing_id, "version": active.routing_version},
        "groupVersionSum": active.group_version_sum,
        "groupIds": active.group_ids,
        "externalInputVersion": active.external_input_version,
        "activeFingerprint": active_fingerprint,
    })
}

fn active_runtime_revision_matches(active: &RunningRuntimeState, desired: &Value) -> bool {
    desired["config"]["id"].as_i64() == active.config_id
        && desired["config"]["version"].as_i64() == Some(active.config_version)
        && desired["dns"]["id"].as_i64() == active.dns_id
        && desired["dns"]["version"].as_i64() == Some(active.dns_version)
        && desired["routing"]["id"].as_i64() == active.routing_id
        && desired["routing"]["version"].as_i64() == Some(active.routing_version)
        && desired["groupVersionSum"].as_i64() == Some(active.group_version_sum)
        && desired["groupIds"].as_str() == Some(active.group_ids.as_str())
        && desired["externalInputVersion"].as_i64() == Some(active.external_input_version)
}

fn metadata_value_from_connection(conn: &Connection, key: &str) -> io::Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM daed_product_metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub(in crate::daed_product) fn runtime_modified(
    conn: &Connection,
    running: bool,
) -> io::Result<bool> {
    if !running {
        return Ok(false);
    }
    if let Some(active_fingerprint) =
        metadata_value_from_connection(conn, RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY)?
    {
        let desired = prepare_runtime_materialization_plan_with_connection(conn)?;
        return Ok(desired.active_fingerprint.as_str() != active_fingerprint);
    }
    legacy_runtime_modified(conn)
}

pub(super) fn runtime_modified_with_prepared_plan(
    conn: &Connection,
    running: bool,
    plan: &RuntimeMaterializationPlan,
) -> io::Result<bool> {
    if !running {
        return Ok(false);
    }
    if let Some(active_fingerprint) =
        metadata_value_from_connection(conn, RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY)?
    {
        return Ok(plan.active_fingerprint.as_str() != active_fingerprint);
    }
    legacy_runtime_modified(conn)
}

fn legacy_runtime_modified(conn: &Connection) -> io::Result<bool> {
    let Some(config) = selected_section_state(conn, SectionKind::Config)? else {
        return Ok(true);
    };
    let Some(dns) = selected_section_state(conn, SectionKind::Dns)? else {
        return Ok(true);
    };
    let Some(routing) = selected_section_state(conn, SectionKind::Routing)? else {
        return Ok(true);
    };
    let Some(running_state) = running_runtime_state(conn)? else {
        return Ok(true);
    };

    Ok(running_state.config_id != Some(config.id)
        || running_state.config_version != config.version
        || running_state.dns_id != Some(dns.id)
        || running_state.dns_version != dns.version
        || running_state.routing_id != Some(routing.id)
        || running_state.routing_version != routing.version
        || running_state.group_version_sum != group_version_sum(conn)?
        || running_state.group_ids != group_ids_text(conn)?
        || running_state.external_input_version != current_runtime_external_input_version(conn)?)
}

pub(in crate::daed_product) fn mark_runtime_process_stopped(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    tx.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES('runtime_running', 'false')",
        [],
    )
    .map_err(sqlite_io_error)?;
    tx.execute(
        "DELETE FROM daed_product_metadata WHERE key = ?1",
        params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
    )
    .map_err(sqlite_io_error)?;
    tx.commit().map_err(sqlite_io_error)
}
