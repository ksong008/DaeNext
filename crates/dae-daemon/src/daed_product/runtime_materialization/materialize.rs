use super::*;

pub(in crate::daed_product) fn build_runtime_config_from_content(
    content: &str,
) -> Result<Config, String> {
    let sections = parse_config(content).map_err(|err| err.to_string())?;
    build_config(&sections).map_err(|err| err.to_string())
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct RuntimeMaterializationPlan {
    pub(in crate::daed_product) content: String,
    pub(in crate::daed_product) generated_at: String,
    pub(in crate::daed_product) config_id: i64,
    pub(in crate::daed_product) config_version: i64,
    pub(in crate::daed_product) dns_id: i64,
    pub(in crate::daed_product) dns_version: i64,
    pub(in crate::daed_product) routing_id: i64,
    pub(in crate::daed_product) routing_version: i64,
    pub(in crate::daed_product) group_version_sum: i64,
    pub(in crate::daed_product) group_ids: String,
    pub(in crate::daed_product) external_input_version: i64,
    pub(in crate::daed_product) active_fingerprint: ActiveRuntimeFingerprint,
    pub(in crate::daed_product) group_count: usize,
    pub(in crate::daed_product) node_count: usize,
    pub(in crate::daed_product) timings: RuntimeMaterializationTimings,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::daed_product) struct RuntimeMaterializationTimings {
    pub(in crate::daed_product) snapshot_ns: u64,
    pub(in crate::daed_product) dependency_resolution_ns: u64,
    pub(in crate::daed_product) render_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::daed_product) struct ActiveRuntimeFingerprint(String);

impl ActiveRuntimeFingerprint {
    pub(in crate::daed_product) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(in crate::daed_product) fn materialize_runtime(
    state: &Path,
    config_dir: Option<&Path>,
    dry: bool,
) -> io::Result<Value> {
    let plan = prepare_runtime_materialization_plan(state)?;
    if dry {
        Ok(plan.report(config_dir, true))
    } else {
        apply_runtime_materialization_plan(state, config_dir, &plan)
    }
}

pub(in crate::daed_product) fn prepare_runtime_materialization_plan(
    state: &Path,
) -> io::Result<RuntimeMaterializationPlan> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    prepare_runtime_materialization_plan_with_connection(&conn)
}

pub(in crate::daed_product) fn prepare_runtime_materialization_plan_with_modified_state(
    state: &Path,
    running: bool,
) -> io::Result<(RuntimeMaterializationPlan, bool)> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let snapshot = conn.unchecked_transaction().map_err(sqlite_io_error)?;
    let started = Instant::now();
    let mut plan = prepare_runtime_materialization_plan_from_snapshot(&snapshot)?;
    let modified = runtime_modified_with_prepared_plan(&snapshot, running, &plan)?;
    snapshot.commit().map_err(sqlite_io_error)?;
    plan.timings.snapshot_ns = elapsed_nanos(started);
    Ok((plan, modified))
}

pub(in crate::daed_product) fn prepare_runtime_materialization_plan_with_connection(
    conn: &Connection,
) -> io::Result<RuntimeMaterializationPlan> {
    let started = Instant::now();
    let snapshot = conn.unchecked_transaction().map_err(sqlite_io_error)?;
    let mut plan = prepare_runtime_materialization_plan_from_snapshot(&snapshot)?;
    snapshot.commit().map_err(sqlite_io_error)?;
    plan.timings.snapshot_ns = elapsed_nanos(started);
    Ok(plan)
}

pub(super) fn prepare_runtime_materialization_plan_from_snapshot(
    conn: &Connection,
) -> io::Result<RuntimeMaterializationPlan> {
    let config = required_selected_section_raw(conn, SectionKind::Config)?;
    let dns = required_selected_section_raw(conn, SectionKind::Dns)?;
    let routing = required_selected_section_raw(conn, SectionKind::Routing)?;
    let dependency_started = Instant::now();
    let active = load_active_runtime_resources(conn, &routing.2)?;
    let dependency_resolution_ns = elapsed_nanos(dependency_started);
    let generated_at = now_text();
    let group_ids = active
        .group_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let external_input_version = current_runtime_external_input_version(conn)?;
    let geodata_input_version = current_runtime_geodata_input_version(conn)?;
    let render_started = Instant::now();
    let active_fingerprint = active_runtime_fingerprint(
        &config,
        &dns,
        &routing,
        &active.groups,
        &active.nodes,
        geodata_input_version,
    )?;
    let content = render_generated_config(
        &generated_at,
        Some(&config),
        Some(&dns),
        Some(&routing),
        &active.groups,
        &active.nodes,
    )?;
    let render_ns = elapsed_nanos(render_started);
    Ok(RuntimeMaterializationPlan {
        content,
        generated_at,
        config_id: config.0,
        config_version: config.3,
        dns_id: dns.0,
        dns_version: dns.3,
        routing_id: routing.0,
        routing_version: routing.3,
        group_version_sum: active.group_version_sum,
        group_ids,
        external_input_version,
        active_fingerprint,
        group_count: active.groups["items"].as_array().map(Vec::len).unwrap_or(0),
        node_count: active.nodes["items"].as_array().map(Vec::len).unwrap_or(0),
        timings: RuntimeMaterializationTimings {
            snapshot_ns: 0,
            dependency_resolution_ns,
            render_ns,
        },
    })
}

fn active_runtime_fingerprint(
    config: &(i64, String, String, i64),
    dns: &(i64, String, String, i64),
    routing: &(i64, String, String, i64),
    groups: &Value,
    nodes: &Value,
    geodata_input_version: i64,
) -> io::Result<ActiveRuntimeFingerprint> {
    let mut hasher = Sha256::new();
    for value in [&config.2, &dns.2, &routing.2] {
        update_fingerprint_part(&mut hasher, value.as_bytes());
    }
    let groups = normalized_fingerprint_groups(groups);
    let nodes = normalized_fingerprint_nodes(nodes);
    let groups = serde_json::to_vec(&groups).map_err(io::Error::other)?;
    let nodes = serde_json::to_vec(&nodes).map_err(io::Error::other)?;
    update_fingerprint_part(&mut hasher, &groups);
    update_fingerprint_part(&mut hasher, &nodes);
    update_fingerprint_part(&mut hasher, &geodata_input_version.to_le_bytes());
    Ok(ActiveRuntimeFingerprint(format!(
        "sha256:{}",
        hex_encode(&hasher.finalize())
    )))
}

fn normalized_fingerprint_groups(groups: &Value) -> Value {
    let items = groups["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|group| {
            let node_tags = runtime_group_node_tags(group)
                .into_iter()
                .map(RuntimeNodeTag::into_string)
                .collect::<Vec<_>>();
            json!({
                "name": group.get("name").and_then(Value::as_str).unwrap_or(""),
                "policy": render_group_policy(group),
                "nodeTags": node_tags,
            })
        })
        .collect::<Vec<_>>();
    json!(items)
}

fn normalized_fingerprint_nodes(nodes: &Value) -> Value {
    let items = nodes["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|node| {
            json!({
                "runtimeTag": runtime_node_tag(node).into_string(),
                "link": node.get("link").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect::<Vec<_>>();
    json!(items)
}

fn update_fingerprint_part(hasher: &mut Sha256, value: &[u8]) {
    Digest::update(hasher, (value.len() as u64).to_le_bytes());
    Digest::update(hasher, value);
}

pub(in crate::daed_product) fn apply_runtime_materialization_plan(
    state: &Path,
    config_dir: Option<&Path>,
    plan: &RuntimeMaterializationPlan,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let output_path = config_dir.map(|dir| dir.join("runtime").join("generated.dae"));
    if let Some(path) = &output_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &plan.content)?;
        set_private_runtime_file_permissions(path)?;
        set_metadata(state, "last_generated_config_path", &path_string(path))?;
    }
    set_metadata(state, "last_materialized_at", &plan.generated_at)?;
    conn.execute("DELETE FROM systems", [])
        .map_err(sqlite_io_error)?;
    conn.execute(
        "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids, running_config_id, running_dns_id, running_routing_id, running_external_input_version)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            1_i64,
            plan.config_version,
            plan.dns_version,
            plan.routing_version,
            plan.group_version_sum,
            plan.group_ids,
            plan.config_id,
            plan.dns_id,
            plan.routing_id,
            plan.external_input_version,
        ],
    )
    .map_err(sqlite_io_error)?;
    set_metadata(state, "runtime_running", "true")?;
    set_metadata(
        state,
        RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY,
        plan.active_fingerprint.as_str(),
    )?;
    Ok(plan.report(config_dir, false))
}

impl RuntimeMaterializationPlan {
    pub(in crate::daed_product) fn report(&self, config_dir: Option<&Path>, dry: bool) -> Value {
        let output_path = config_dir.map(|dir| dir.join("runtime").join("generated.dae"));
        let mut report = Map::new();
        report.insert("filename".to_owned(), json!("generated.dae"));
        report.insert(
            "path".to_owned(),
            json!(output_path.as_ref().map(|path| path_string(path))),
        );
        report.insert("bytes".to_owned(), json!(self.content.len()));
        report.insert("contentIncluded".to_owned(), json!(dry));
        if dry {
            report.insert("content".to_owned(), json!(self.content));
        }
        report.insert("generatedAt".to_owned(), json!(self.generated_at));
        report.insert(
            "selected".to_owned(),
            json!({
                "configId": self.config_id,
                "dnsId": self.dns_id,
                "routingId": self.routing_id,
            }),
        );
        report.insert("groups".to_owned(), json!(self.group_count));
        report.insert("nodes".to_owned(), json!(self.node_count));
        report.insert(
            "activeFingerprint".to_owned(),
            json!(self.active_fingerprint.as_str()),
        );
        report.insert(
            "timings".to_owned(),
            json!({
                "snapshotNs": self.timings.snapshot_ns,
                "dependencyResolutionNs": self.timings.dependency_resolution_ns,
                "renderNs": self.timings.render_ns,
            }),
        );
        Value::Object(report)
    }
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn required_selected_section_raw(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<(i64, String, String, i64)> {
    selected_section_raw(conn, kind)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no selected {} resource", kind.table()),
        )
    })
}
