use super::sections::ImportedSection;
use super::*;
use rusqlite::Transaction;

pub(super) fn validate_imported_materialization(
    tx: &Transaction<'_>,
    config: &ImportedSection,
    dns: &ImportedSection,
    routing: &ImportedSection,
) -> io::Result<()> {
    let nodes = all_nodes_value(tx)?;
    let groups = all_groups_value(tx)?;
    let config_tuple = (
        config.id,
        config.name.clone(),
        config.value.clone(),
        config.version,
    );
    let dns_tuple = (dns.id, dns.name.clone(), dns.value.clone(), dns.version);
    let routing_tuple = (
        routing.id,
        routing.name.clone(),
        routing.value.clone(),
        routing.version,
    );
    let content = render_generated_config(
        &now_text(),
        Some(&config_tuple),
        Some(&dns_tuple),
        Some(&routing_tuple),
        &groups,
        &nodes,
    )?;
    build_runtime_config_from_content(&content)
        .map_err(|err| invalid_dae_file(format!("validate imported materialization: {err}")))?;
    Ok(())
}

fn all_nodes_value(conn: &Connection) -> io::Result<Value> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

fn all_groups_value(conn: &Connection) -> io::Result<Value> {
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    let mut items = Vec::new();
    for id in ids {
        if let Some(group) = get_group_value_with_conn(conn, id)? {
            items.push(group);
        }
    }
    Ok(json!({"items": items}))
}
