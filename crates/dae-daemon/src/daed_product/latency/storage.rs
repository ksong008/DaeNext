use super::super::*;
use super::*;

#[derive(Clone, Debug)]
pub(crate) struct NodeLatencyWrite {
    pub(in crate::daed_product) node_id: i64,
    pub(in crate::daed_product) node_link: String,
    pub(in crate::daed_product) probe_generation: Option<u64>,
    pub(in crate::daed_product) latency_ms: Option<i64>,
    pub(in crate::daed_product) alive: bool,
    pub(in crate::daed_product) tested_at: String,
    pub(in crate::daed_product) message: Option<String>,
}

#[derive(Debug)]
pub(crate) struct RuntimeNodeLatencyIndex<'a> {
    nodes: &'a [LatencyProbeNode],
    nodes_by_link_hash: HashMap<String, Vec<usize>>,
}

impl<'a> RuntimeNodeLatencyIndex<'a> {
    pub(crate) fn new(nodes: &'a [LatencyProbeNode]) -> Self {
        let mut nodes_by_link_hash = HashMap::<String, Vec<usize>>::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            nodes_by_link_hash
                .entry(runtime_link_hash(&node.link))
                .or_default()
                .push(index);
        }
        Self {
            nodes,
            nodes_by_link_hash,
        }
    }

    pub(crate) fn results_for_snapshots(
        &self,
        snapshots: &[Value],
    ) -> (Vec<NodeLatencyWrite>, HashSet<i64>) {
        let mut results = Vec::with_capacity(snapshots.len().min(self.nodes.len()));
        let mut tested_ids = HashSet::with_capacity(self.nodes.len().min(snapshots.len()));
        for snapshot in snapshots {
            if !runtime_latency_snapshot_has_result(snapshot) {
                continue;
            }
            let Some(link_hash) = runtime_latency_snapshot_link_hash(snapshot) else {
                continue;
            };
            let Some(matched_nodes) = self.nodes_by_link_hash.get(link_hash) else {
                continue;
            };
            let checked_at = snapshot
                .get("checkedAtUnix")
                .and_then(Value::as_i64)
                .filter(|checked_at| *checked_at > 0)
                .map(|checked_at| iso8601_utc(checked_at as u64))
                .unwrap_or_else(now_text);
            let latency_ms = snapshot.get("latencyMs").and_then(Value::as_i64);
            let alive = snapshot
                .get("alive")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let message = snapshot
                .get("message")
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
                .map(str::to_owned);
            let probe_generation = snapshot.get("reloadGeneration").and_then(Value::as_u64);
            for &node_index in matched_nodes {
                let node = &self.nodes[node_index];
                tested_ids.insert(node.id);
                results.push(NodeLatencyWrite {
                    node_id: node.id,
                    node_link: node.link.clone(),
                    probe_generation,
                    latency_ms,
                    alive,
                    tested_at: checked_at.clone(),
                    message: if alive { None } else { message.clone() },
                });
            }
        }
        (results, tested_ids)
    }
}

pub(crate) fn stored_successful_node_latency_seed_snapshots(
    state: &Path,
) -> io::Result<Vec<Value>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    stored_successful_node_latency_seed_snapshots_from_conn(&conn)
}

pub(crate) fn stored_successful_node_latency_seed_snapshots_from_conn(
    conn: &Connection,
) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT n.name, n.link, l.latency_ms, l.tested_at
             FROM nodes n
             JOIN node_latency_results l ON l.node_id = n.id
             WHERE COALESCE(l.alive, 0) != 0 AND l.latency_ms IS NOT NULL
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            let display_name = row.get::<_, String>(0)?;
            let link = row.get::<_, String>(1)?;
            let latency_ms = row.get::<_, i64>(2)?;
            let tested_at = row.get::<_, String>(3)?;
            let link_hash = runtime_link_hash(&link);
            let execution_identity = runtime_execution_identity(&link);
            let display_name = if display_name.is_empty() {
                node_name_from_link(&link)
            } else {
                display_name
            };
            Ok(json!({
                "name": display_name,
                "displayName": display_name,
                "linkHash": link_hash,
                "executionIdentity": execution_identity,
                "linkIdentity": runtime_link_identity_value(
                    &display_name,
                    &link_hash,
                    &runtime_redacted_link_source(&link),
                ),
                "latencyMs": latency_ms,
                "alive": true,
                "checkedAtUnix": parse_runtime_latency_seed_time(&tested_at).unwrap_or(0),
                "message": format!("{latency_ms}ms"),
                "scope": "proxy-tcp-check",
                "seedSource": "database",
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut snapshots = Vec::new();
    for row in rows {
        snapshots.push(row.map_err(sqlite_io_error)?);
    }
    Ok(snapshots)
}

#[cfg(test)]
pub(crate) fn runtime_node_latency_results_for_nodes(
    nodes: &[LatencyProbeNode],
    snapshots: &[Value],
) -> (Vec<NodeLatencyWrite>, HashSet<i64>) {
    RuntimeNodeLatencyIndex::new(nodes).results_for_snapshots(snapshots)
}

pub(crate) fn runtime_latency_snapshot_link_hash(snapshot: &Value) -> Option<&str> {
    snapshot
        .get("linkHash")
        .and_then(Value::as_str)
        .or_else(|| {
            snapshot
                .pointer("/linkIdentity/linkHash")
                .and_then(Value::as_str)
        })
}

pub(crate) fn runtime_latency_snapshot_has_result(snapshot: &Value) -> bool {
    let latency = snapshot.get("latencyMs").and_then(Value::as_i64);
    let checked_at = snapshot
        .get("checkedAtUnix")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let message = snapshot
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("");
    latency.is_some() || checked_at > 0 || message != "no latency result"
}

pub(crate) fn store_node_latency_result(
    conn: &Connection,
    result: &NodeLatencyWrite,
) -> io::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?4)",
        params![
            result.node_id,
            result.latency_ms,
            result.alive as i64,
            result.tested_at,
            result.message
        ],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

pub(crate) fn native_probe_unavailable_results(
    nodes: &[LatencyProbeNode],
    tested_at: &str,
    probe_generation: Option<u64>,
) -> Vec<NodeLatencyWrite> {
    nodes
        .iter()
        .map(|node| NodeLatencyWrite {
            node_id: node.id,
            node_link: node.link.clone(),
            probe_generation,
            latency_ms: None,
            alive: false,
            tested_at: tested_at.to_owned(),
            message: Some(
                "native outbound probe unavailable; materialize/reload Rust runtime before testing this node"
                    .to_owned(),
            ),
        })
        .collect()
}

pub(crate) fn all_node_ids(conn: &Connection) -> io::Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT id FROM nodes ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    Ok(ids)
}

fn parse_runtime_latency_seed_time(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    if raw.len() != 20 || !raw.ends_with('Z') {
        return None;
    }
    let year = raw.get(0..4)?.parse::<i64>().ok()?;
    let month = raw.get(5..7)?.parse::<i64>().ok()?;
    let day = raw.get(8..10)?.parse::<i64>().ok()?;
    let hour = raw.get(11..13)?.parse::<i64>().ok()?;
    let minute = raw.get(14..16)?.parse::<i64>().ok()?;
    let second = raw.get(17..19)?.parse::<i64>().ok()?;
    if raw.as_bytes().get(4) != Some(&b'-')
        || raw.as_bytes().get(7) != Some(&b'-')
        || raw.as_bytes().get(10) != Some(&b'T')
        || raw.as_bytes().get(13) != Some(&b':')
        || raw.as_bytes().get(16) != Some(&b':')
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let days = runtime_latency_seed_days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn runtime_latency_seed_days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}
