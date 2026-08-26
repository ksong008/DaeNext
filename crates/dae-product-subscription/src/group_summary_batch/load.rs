use super::*;
use std::collections::HashMap;

use crate::{sqlite_io_error, subscription_node_row_value};

pub(super) struct GroupSummaryDataset {
    pub(super) groups: Vec<GroupSummaryRow>,
    pub(super) policy_params: HashMap<i64, Vec<Value>>,
    pub(super) direct_candidates: HashMap<i64, Vec<GroupCandidateRow>>,
    pub(super) bindings: HashMap<i64, Vec<SubscriptionBindingRow>>,
    pub(super) subscription_candidates: HashMap<i64, Vec<GroupCandidateRow>>,
}

pub(super) struct GroupSummaryRow {
    pub(super) id: i64,
    pub(super) name: String,
    pub(super) policy: String,
    pub(super) version: i64,
}

pub(super) struct SubscriptionBindingRow {
    pub(super) subscription_id: i64,
    pub(super) updated_at: String,
    pub(super) link: String,
    pub(super) status: String,
    pub(super) info: String,
    pub(super) tag: Option<String>,
    pub(super) name_filter_regex: Option<String>,
}

impl GroupSummaryDataset {
    pub(super) fn load(conn: &Connection) -> io::Result<Self> {
        Ok(Self {
            groups: load_groups(conn)?,
            policy_params: load_policy_params(conn)?,
            direct_candidates: load_direct_candidates(conn)?,
            bindings: load_subscription_bindings(conn)?,
            subscription_candidates: load_subscription_candidates(conn)?,
        })
    }
}

fn load_groups(conn: &Connection) -> io::Result<Vec<GroupSummaryRow>> {
    let mut stmt = conn
        .prepare("SELECT id, name, policy, version FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(GroupSummaryRow {
                id: row.get(0)?,
                name: row.get(1)?,
                policy: row.get(2)?,
                version: row.get(3)?,
            })
        })
        .map_err(sqlite_io_error)?;
    collect_summary_rows(rows)
}

fn load_policy_params(conn: &Connection) -> io::Result<HashMap<i64, Vec<Value>>> {
    let mut stmt = conn
        .prepare("SELECT group_id, key, value FROM group_policy_params ORDER BY group_id, id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                json!({
                    "key": row.get::<_, String>(1)?,
                    "val": row.get::<_, String>(2)?,
                }),
            ))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn load_direct_candidates(conn: &Connection) -> io::Result<HashMap<i64, Vec<GroupCandidateRow>>> {
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id,
                    gn.group_id, l.latency_ms, COALESCE(l.alive, 0)
             FROM group_nodes gn
             JOIN nodes n ON n.id = gn.node_id
             LEFT JOIN node_latency_results l ON l.node_id = n.id
             ORDER BY gn.group_id, n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(7)?,
                GroupCandidateRow {
                    node: subscription_node_row_value(row)?,
                    latency_ms: row.get(8)?,
                    alive: row.get::<_, i64>(9)? != 0,
                },
            ))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn load_subscription_bindings(
    conn: &Connection,
) -> io::Result<HashMap<i64, Vec<SubscriptionBindingRow>>> {
    let mut stmt = conn
        .prepare(
            "SELECT gs.group_id, s.id, s.updated_at, s.link, s.status, s.info, s.tag,
                    gs.name_filter_regex
             FROM group_subscriptions gs
             JOIN subscriptions s ON s.id = gs.subscription_id
             ORDER BY gs.group_id, s.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                SubscriptionBindingRow {
                    subscription_id: row.get(1)?,
                    updated_at: row.get(2)?,
                    link: row.get(3)?,
                    status: row.get(4)?,
                    info: row.get(5)?,
                    tag: row.get(6)?,
                    name_filter_regex: row.get(7)?,
                },
            ))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn load_subscription_candidates(
    conn: &Connection,
) -> io::Result<HashMap<i64, Vec<GroupCandidateRow>>> {
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id,
                    l.latency_ms, COALESCE(l.alive, 0)
             FROM nodes n
             JOIN (
                 SELECT DISTINCT subscription_id FROM group_subscriptions
             ) used ON used.subscription_id = n.subscription_id
             LEFT JOIN node_latency_results l ON l.node_id = n.id
             ORDER BY n.subscription_id, n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            let subscription_id = row.get::<_, i64>(6)?;
            Ok((
                subscription_id,
                GroupCandidateRow {
                    node: subscription_node_row_value(row)?,
                    latency_ms: row.get(7)?,
                    alive: row.get::<_, i64>(8)? != 0,
                },
            ))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn collect_summary_rows<T>(rows: impl Iterator<Item = rusqlite::Result<T>>) -> io::Result<Vec<T>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

fn collect_grouped_rows<T>(
    rows: impl Iterator<Item = rusqlite::Result<(i64, T)>>,
) -> io::Result<HashMap<i64, Vec<T>>> {
    let mut out = HashMap::<i64, Vec<T>>::new();
    for row in rows {
        let (key, value) = row.map_err(sqlite_io_error)?;
        out.entry(key).or_default().push(value);
    }
    Ok(out)
}
