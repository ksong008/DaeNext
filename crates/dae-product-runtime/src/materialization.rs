use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

use dae_config::Config;
use dae_config::parser::parse_config;
use dae_config::schema::build_config;
use dae_product_core::{
    RuntimeNodeTag, SectionKind, hex_encode, path_string, product_now_text as now_text,
    runtime_node_tag,
};
use dae_product_persistence::{
    RuntimeDesiredStateRevision, current_runtime_external_input_version,
    current_runtime_geodata_input_version, ensure_state_schema, open_state_connection,
    selected_section_raw, set_metadata, set_private_runtime_file_permissions, sqlite_io_error,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    display_global_config_text, load_active_runtime_resources, render_group_policy,
    render_runtime_config, runtime_group_node_tags,
};

pub const RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY: &str = "runtime_active_fingerprint";

pub fn build_runtime_config_from_content(content: &str) -> Result<Config, String> {
    let sections = parse_config(content).map_err(|err| err.to_string())?;
    build_config(&sections).map_err(|err| err.to_string())
}

#[derive(Clone, Debug)]
pub struct RuntimeMaterializationPlan {
    pub content: String,
    pub generated_at: String,
    pub config_id: i64,
    pub config_version: i64,
    pub dns_id: i64,
    pub dns_version: i64,
    pub routing_id: i64,
    pub routing_version: i64,
    pub group_version_sum: i64,
    pub group_ids: String,
    pub external_input_version: i64,
    pub geodata_input_version: i64,
    pub active_fingerprint: ActiveRuntimeFingerprint,
    pub group_count: usize,
    pub node_count: usize,
    pub timings: RuntimeMaterializationTimings,
}

impl RuntimeMaterializationPlan {
    pub fn desired_state_revision(&self) -> RuntimeDesiredStateRevision {
        RuntimeDesiredStateRevision::new(
            self.config_id,
            self.config_version,
            self.dns_id,
            self.dns_version,
            self.routing_id,
            self.routing_version,
            self.group_version_sum,
            self.group_ids.clone(),
            self.external_input_version,
            self.geodata_input_version,
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeMaterializationTimings {
    pub snapshot_ns: u64,
    pub dependency_resolution_ns: u64,
    pub render_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveRuntimeFingerprint(String);

impl ActiveRuntimeFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub fn for_test(value: &str) -> Self {
        Self(value.to_owned())
    }
}

pub fn materialize_runtime(
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

pub fn prepare_runtime_materialization_plan(
    state: &Path,
) -> io::Result<RuntimeMaterializationPlan> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    prepare_runtime_materialization_plan_with_connection(&conn)
}

pub fn prepare_runtime_materialization_plan_with_modified_state(
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

pub fn prepare_runtime_materialization_plan_with_connection(
    conn: &Connection,
) -> io::Result<RuntimeMaterializationPlan> {
    let started = Instant::now();
    let snapshot = conn.unchecked_transaction().map_err(sqlite_io_error)?;
    let mut plan = prepare_runtime_materialization_plan_from_snapshot(&snapshot)?;
    snapshot.commit().map_err(sqlite_io_error)?;
    plan.timings.snapshot_ns = elapsed_nanos(started);
    Ok(plan)
}

pub fn prepare_runtime_materialization_plan_from_snapshot(
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
        geodata_input_version,
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

pub fn apply_runtime_materialization_plan(
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
    pub fn report(&self, config_dir: Option<&Path>, dry: bool) -> Value {
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
            "geodataInputVersion".to_owned(),
            json!(self.geodata_input_version),
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

pub fn render_generated_config(
    generated_at: &str,
    config: Option<&(i64, String, String, i64)>,
    dns: Option<&(i64, String, String, i64)>,
    routing: Option<&(i64, String, String, i64)>,
    groups: &Value,
    nodes: &Value,
) -> io::Result<String> {
    render_runtime_config(
        generated_at,
        config.map(|(_, _, raw, _)| display_global_config_text(raw)),
        dns.map(|(_, _, raw, _)| raw.as_str()),
        routing.map(|(_, _, raw, _)| raw.as_str()),
        groups,
        nodes,
    )
}

pub fn runtime_modified(conn: &Connection, running: bool) -> io::Result<bool> {
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

pub fn runtime_modified_with_prepared_plan(
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

fn metadata_value_from_connection(conn: &Connection, key: &str) -> io::Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM daed_product_metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn legacy_runtime_modified(conn: &Connection) -> io::Result<bool> {
    let Some(config) = dae_product_persistence::selected_section_state(conn, SectionKind::Config)?
    else {
        return Ok(true);
    };
    let Some(dns) = dae_product_persistence::selected_section_state(conn, SectionKind::Dns)? else {
        return Ok(true);
    };
    let Some(routing) =
        dae_product_persistence::selected_section_state(conn, SectionKind::Routing)?
    else {
        return Ok(true);
    };
    let Some(running_state) = dae_product_persistence::running_runtime_state(conn)? else {
        return Ok(true);
    };

    Ok(running_state.config_id != Some(config.id)
        || running_state.config_version != config.version
        || running_state.dns_id != Some(dns.id)
        || running_state.dns_version != dns.version
        || running_state.routing_id != Some(routing.id)
        || running_state.routing_version != routing.version
        || running_state.group_version_sum != dae_product_persistence::group_version_sum(conn)?
        || running_state.group_ids != dae_product_persistence::group_ids_text(conn)?
        || running_state.external_input_version != current_runtime_external_input_version(conn)?)
}
