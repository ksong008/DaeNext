use std::io;
use std::path::Path;

use dae_product_core::SectionKind;
use dae_product_http::{HttpRequest, HttpResponse, json_body};
use dae_product_persistence::{ensure_state_schema, open_state_connection, sqlite_io_error};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};

use crate::sections::get_section;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileSelection {
    pub config_id: i64,
    pub dns_id: i64,
    pub routing_id: i64,
}

impl ProfileSelection {
    fn entries(self) -> [(SectionKind, i64); 3] {
        [
            (SectionKind::Config, self.config_id),
            (SectionKind::Dns, self.dns_id),
            (SectionKind::Routing, self.routing_id),
        ]
    }

    fn response(self) -> Value {
        json!({
            "selected": {
                "configId": self.config_id,
                "dnsId": self.dns_id,
                "routingId": self.routing_id,
            }
        })
    }
}

pub fn select_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    match select_section_transactionally(state, kind, id) {
        Ok(()) => get_section(state, kind, id),
        Err(err) => selection_error_response(err),
    }
}

pub fn api_select_profile(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let selection = match profile_selection_from_body(&body) {
        Ok(selection) => selection,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match select_profile_transactionally(state, selection) {
        Ok(()) => HttpResponse::json(200, selection.response()),
        Err(err) => selection_error_response(err),
    }
}

pub fn select_section_transactionally(state: &Path, kind: SectionKind, id: i64) -> io::Result<()> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    ensure_selection_target_exists(&tx, kind, id)?;
    apply_selection(&tx, kind, id)?;
    tx.commit().map_err(sqlite_io_error)
}

pub fn select_profile_transactionally(state: &Path, selection: ProfileSelection) -> io::Result<()> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    for (kind, id) in selection.entries() {
        ensure_selection_target_exists(&tx, kind, id)?;
    }
    for (kind, id) in selection.entries() {
        apply_selection(&tx, kind, id)?;
    }
    tx.commit().map_err(sqlite_io_error)
}

fn ensure_selection_target_exists(conn: &Connection, kind: SectionKind, id: i64) -> io::Result<()> {
    let sql = format!("SELECT 1 FROM {} WHERE id = ?1", kind.table());
    let exists = conn
        .query_row(&sql, params![id], |_| Ok(()))
        .optional()
        .map_err(sqlite_io_error)?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} resource {id} not found", kind.table()),
        ))
    }
}

fn apply_selection(conn: &Connection, kind: SectionKind, id: i64) -> io::Result<()> {
    let clear = format!("UPDATE {} SET selected = 0", kind.table());
    let set = format!(
        "UPDATE {} SET selected = 1, version = version + 1 WHERE id = ?1",
        kind.table()
    );
    conn.execute(&clear, []).map_err(sqlite_io_error)?;
    let updated = conn.execute(&set, params![id]).map_err(sqlite_io_error)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} resource {id} not found", kind.table()),
        ))
    }
}

fn profile_selection_from_body(body: &Value) -> Result<ProfileSelection, String> {
    Ok(ProfileSelection {
        config_id: profile_resource_id(body, "configId")?,
        dns_id: profile_resource_id(body, "dnsId")?,
        routing_id: profile_resource_id(body, "routingId")?,
    })
}

fn profile_resource_id(body: &Value, key: &str) -> Result<i64, String> {
    let value = body.get(key).ok_or_else(|| format!("{key} is required"))?;
    let id = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()))
        .filter(|id| *id > 0)
        .ok_or_else(|| format!("{key} must be a positive integer"))?;
    Ok(id)
}

fn selection_error_response(err: io::Error) -> HttpResponse {
    let status = match err.kind() {
        io::ErrorKind::NotFound => 404,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => 400,
        _ => 500,
    };
    HttpResponse::json(status, json!({"error": err.to_string()}))
}
