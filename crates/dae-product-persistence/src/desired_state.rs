use std::io;

use dae_product_core::{
    SectionKind, product_referenced_group_names_from_routing, product_render_routing_section,
};
use rusqlite::Connection;

use crate::{
    current_runtime_external_input_version, current_runtime_geodata_input_version,
    selected_section_raw,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDesiredStateRevision {
    config_id: i64,
    config_version: i64,
    dns_id: i64,
    dns_version: i64,
    routing_id: i64,
    routing_version: i64,
    group_version_sum: i64,
    group_ids: String,
    external_input_version: i64,
    geodata_input_version: i64,
}

impl RuntimeDesiredStateRevision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config_id: i64,
        config_version: i64,
        dns_id: i64,
        dns_version: i64,
        routing_id: i64,
        routing_version: i64,
        group_version_sum: i64,
        group_ids: String,
        external_input_version: i64,
        geodata_input_version: i64,
    ) -> Self {
        Self {
            config_id,
            config_version,
            dns_id,
            dns_version,
            routing_id,
            routing_version,
            group_version_sum,
            group_ids,
            external_input_version,
            geodata_input_version,
        }
    }
}

pub fn runtime_desired_state_revision_from_connection(
    connection: &Connection,
) -> io::Result<RuntimeDesiredStateRevision> {
    let config = required_selected_section_raw(connection, SectionKind::Config)?;
    let dns = required_selected_section_raw(connection, SectionKind::Dns)?;
    let routing = required_selected_section_raw(connection, SectionKind::Routing)?;
    let routing_text = product_render_routing_section(
        (!routing.2.trim().is_empty()).then_some(routing.2.as_str()),
    );
    let referenced_groups =
        product_referenced_group_names_from_routing(&routing_text).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "selected routing could not be parsed while resolving runtime groups",
            )
        })?;
    let (group_ids, group_version_sum) = group_revision(connection, &referenced_groups)?;
    Ok(RuntimeDesiredStateRevision::new(
        config.0,
        config.3,
        dns.0,
        dns.3,
        routing.0,
        routing.3,
        group_version_sum,
        group_ids
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(","),
        current_runtime_external_input_version(connection)?,
        current_runtime_geodata_input_version(connection)?,
    ))
}

fn required_selected_section_raw(
    connection: &Connection,
    kind: SectionKind,
) -> io::Result<(i64, String, String, i64)> {
    selected_section_raw(connection, kind)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no selected {} resource", kind.table()),
        )
    })
}

fn group_revision(
    connection: &Connection,
    names: &std::collections::BTreeSet<String>,
) -> io::Result<(Vec<i64>, i64)> {
    if names.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let placeholders = std::iter::repeat_n("?", names.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT id, version FROM groups WHERE name IN ({placeholders}) ORDER BY id");
    let mut statement = connection.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(names.iter()), |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(sqlite_io_error)?;
    let mut group_ids = Vec::with_capacity(names.len());
    let mut group_version_sum = 0_i64;
    for row in rows {
        let (id, version) = row.map_err(sqlite_io_error)?;
        group_ids.push(id);
        group_version_sum = group_version_sum.saturating_add(version);
    }
    Ok((group_ids, group_version_sum))
}

fn sqlite_io_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error.to_string())
}
