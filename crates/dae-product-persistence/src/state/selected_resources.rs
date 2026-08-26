use std::io;

use dae_product_core::SectionKind;
use rusqlite::{Connection, OptionalExtension};

use super::sqlite_io_error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSectionState {
    pub id: i64,
    pub version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningRuntimeState {
    pub config_id: Option<i64>,
    pub config_version: i64,
    pub dns_id: Option<i64>,
    pub dns_version: i64,
    pub routing_id: Option<i64>,
    pub routing_version: i64,
    pub group_version_sum: i64,
    pub group_ids: String,
    pub external_input_version: i64,
}

pub fn selected_section_raw(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<(i64, String, String, i64)>> {
    let sql = format!(
        "SELECT id, name, {}, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

pub fn selected_id(conn: &Connection, kind: SectionKind) -> io::Result<Option<i64>> {
    let sql = format!(
        "SELECT id FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)
}

pub fn group_version_sum(conn: &Connection) -> io::Result<i64> {
    conn.query_row("SELECT COALESCE(SUM(version), 0) FROM groups", [], |row| {
        row.get(0)
    })
    .map_err(sqlite_io_error)
}

pub fn group_ids_text(conn: &Connection) -> io::Result<String> {
    let mut statement = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?.to_string());
    }
    Ok(ids.join(","))
}

pub fn selected_section_state(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<RuntimeSectionState>> {
    let sql = format!(
        "SELECT id, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok(RuntimeSectionState {
            id: row.get(0)?,
            version: row.get(1)?,
        })
    })
    .optional()
    .map_err(sqlite_io_error)
}

pub fn running_runtime_state(conn: &Connection) -> io::Result<Option<RunningRuntimeState>> {
    conn.query_row(
        "SELECT running_config_id, running_config_version,
                running_dns_id, running_dns_version,
                running_routing_id, running_routing_version,
                running_group_version_sum, running_group_ids,
                running_external_input_version
         FROM systems
         WHERE running != 0
         ORDER BY id
         LIMIT 1",
        [],
        |row| {
            Ok(RunningRuntimeState {
                config_id: row.get(0)?,
                config_version: row.get(1)?,
                dns_id: row.get(2)?,
                dns_version: row.get(3)?,
                routing_id: row.get(4)?,
                routing_version: row.get(5)?,
                group_version_sum: row.get(6)?,
                group_ids: row.get(7)?,
                external_input_version: row.get(8)?,
            })
        },
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub fn running_section_references_id(
    conn: &Connection,
    kind: SectionKind,
    id: i64,
) -> io::Result<bool> {
    let Some(running_state) = running_runtime_state(conn)? else {
        return Ok(false);
    };
    let running_id = match kind {
        SectionKind::Config => running_state.config_id,
        SectionKind::Dns => running_state.dns_id,
        SectionKind::Routing => running_state.routing_id,
    };
    Ok(running_id == Some(id))
}

pub fn running_group_references_id(conn: &Connection, group_id: i64) -> io::Result<bool> {
    let Some(running_state) = running_runtime_state(conn)? else {
        return Ok(false);
    };
    Ok(running_state
        .group_ids
        .split(',')
        .filter_map(|value| value.trim().parse::<i64>().ok())
        .any(|id| id == group_id))
}
