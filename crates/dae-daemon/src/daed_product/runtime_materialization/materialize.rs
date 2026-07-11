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
    pub(in crate::daed_product) group_count: usize,
    pub(in crate::daed_product) node_count: usize,
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
    let config = required_selected_section_raw(&conn, SectionKind::Config)?;
    let dns = required_selected_section_raw(&conn, SectionKind::Dns)?;
    let routing = required_selected_section_raw(&conn, SectionKind::Routing)?;
    let groups = list_groups_value(state)?;
    let nodes = list_all_nodes_value(state)?;
    let generated_at = now_text();
    let group_version_sum = group_version_sum(&conn)?;
    let group_ids = group_ids_text(&conn)?;
    let external_input_version = current_runtime_external_input_version(&conn)?;
    let content = render_generated_config(
        &generated_at,
        Some(&config),
        Some(&dns),
        Some(&routing),
        &groups,
        &nodes,
    )?;
    Ok(RuntimeMaterializationPlan {
        content,
        generated_at,
        config_id: config.0,
        config_version: config.3,
        dns_id: dns.0,
        dns_version: dns.3,
        routing_id: routing.0,
        routing_version: routing.3,
        group_version_sum,
        group_ids,
        external_input_version,
        group_count: groups["items"].as_array().map(Vec::len).unwrap_or(0),
        node_count: nodes["items"].as_array().map(Vec::len).unwrap_or(0),
    })
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
        Value::Object(report)
    }
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
