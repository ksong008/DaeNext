fn list_node_latencies_value(state: &Path, runtime: &ProductRuntimeManager) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    sync_runtime_node_latency_results(&conn, runtime)?;
    let mut stmt = conn
        .prepare(
            "SELECT n.id, l.latency_ms, COALESCE(l.alive, 0), COALESCE(l.tested_at, ''), l.message
             FROM nodes n
             LEFT JOIN node_latency_results l ON l.node_id = n.id
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            let latency_ms = row.get::<_, Option<i64>>(1)?;
            let alive = row.get::<_, i64>(2)? != 0;
            let message = if alive && latency_ms.is_some() {
                None
            } else {
                row.get::<_, Option<String>>(4)?
                    .filter(|value| !value.is_empty())
            };
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "latencyMs": latency_ms,
                "alive": alive,
                "testedAt": row.get::<_, String>(3)?,
                "message": message,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

fn update_node_latencies(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    ids: &[i64],
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let target_ids = if ids.is_empty() {
        all_node_ids(&conn)?
    } else {
        ids.to_vec()
    };
    let mut nodes = Vec::new();
    for id in target_ids {
        let node: Option<(i64, String, String)> = conn
            .query_row(
                "SELECT id, link, address FROM nodes WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_io_error)?;
        if let Some(node) = node {
            nodes.push(node);
        }
    }

    let links = nodes
        .iter()
        .map(|(_, link, _)| link.clone())
        .collect::<Vec<_>>();
    let runtime_snapshots = runtime.probe_node_latencies(&links);
    let (runtime_results, runtime_tested_ids) =
        runtime_node_latency_results_for_nodes(&nodes, &runtime_snapshots);
    for result in &runtime_results {
        store_node_latency_result(&conn, result)?;
    }

    let tested_at = now_text();
    let fallback_nodes = nodes
        .iter()
        .filter(|(id, _, _)| !runtime_tested_ids.contains(id))
        .cloned()
        .collect::<Vec<_>>();
    for result in native_probe_unavailable_results(&fallback_nodes, &tested_at) {
        store_node_latency_result(&conn, &result)?;
    }
    append_log_for_config(
        config_dir,
        state,
        "info",
        "node latency probe updated by Rust daed",
    )?;
    list_node_latencies_value(state, runtime)
}

fn fake_runtime_probe_node_latencies(links: &[String]) -> Vec<Value> {
    links
        .iter()
        .filter(|link| !link.is_empty())
        .map(|link| fake_runtime_tcp_latency_snapshot(link))
        .collect()
}

fn fake_runtime_tcp_latency_snapshot(link: &str) -> Value {
    let checked_at = unix_now() as i64;
    let started = Instant::now();
    let probe = fake_runtime_tcp_connect(link);
    let latency_ms = probe
        .as_ref()
        .ok()
        .map(|_| started.elapsed().as_millis() as i64);
    let display_name = node_name_from_link(link);
    let link_hash = runtime_link_hash(link);
    let redacted_source = runtime_redacted_link_source(link);
    json!({
        "name": display_name.as_str(),
        "displayName": display_name.as_str(),
        "linkHash": link_hash.as_str(),
        "linkIdentity": runtime_link_identity_value(&display_name, &link_hash, &redacted_source),
        "latencyMs": latency_ms,
        "alive": latency_ms.is_some(),
        "checkedAtUnix": checked_at,
        "message": probe.err(),
        "scope": "fake-runtime-tcp-check",
    })
}

fn fake_runtime_tcp_connect(link: &str) -> Result<(), String> {
    let url = url::Url::parse(link).map_err(|err| format!("parse node link: {err}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "node link does not contain a host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "node link does not contain a port".to_owned())?;
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|err| format!("resolve node endpoint: {err}"))?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(_) => return Ok(()),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error
        .map(|err| format!("connect node endpoint: {err}"))
        .unwrap_or_else(|| "node endpoint resolved to no socket addresses".to_owned()))
}

fn node_name_from_link(link: &str) -> String {
    url::Url::parse(link)
        .ok()
        .and_then(|url| url.fragment().map(str::to_owned))
        .filter(|fragment| !fragment.is_empty())
        .unwrap_or_default()
}

fn runtime_link_identity_value(
    display_name: &str,
    link_hash: &str,
    redacted_source: &str,
) -> Value {
    json!({
        "schemaVersion": 1,
        "displayName": display_name,
        "linkHash": link_hash,
        "redactedSource": redacted_source,
    })
}

fn runtime_link_hash(link: &str) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(link.as_bytes())))
}

fn runtime_redacted_link_source(link: &str) -> String {
    let Ok(url) = url::Url::parse(link) else {
        return "link:<redacted>".to_owned();
    };
    let mut value = format!("{}:<redacted>", url.scheme());
    if let Some(fragment) = url.fragment().filter(|fragment| !fragment.is_empty()) {
        value.push('#');
        value.push_str(fragment);
    }
    value
}

#[derive(Clone, Debug)]
struct NodeLatencyWrite {
    node_id: i64,
    latency_ms: Option<i64>,
    alive: bool,
    tested_at: String,
    message: Option<String>,
}

fn sync_runtime_node_latency_results(
    conn: &Connection,
    runtime: &ProductRuntimeManager,
) -> io::Result<()> {
    let snapshots = runtime.snapshot_node_latencies();
    let nodes = all_latency_probe_nodes(conn)?;
    let (results, _) = runtime_node_latency_results_for_nodes(&nodes, &snapshots);
    for result in &results {
        store_node_latency_result(conn, result)?;
    }
    Ok(())
}

fn runtime_node_latency_results_for_nodes(
    nodes: &[(i64, String, String)],
    snapshots: &[Value],
) -> (Vec<NodeLatencyWrite>, HashSet<i64>) {
    let mut results = Vec::new();
    let mut tested_ids = HashSet::new();
    let mut node_ids_by_link_hash = BTreeMap::<String, Vec<i64>>::new();
    for (id, node_link, _) in nodes {
        node_ids_by_link_hash
            .entry(runtime_link_hash(node_link))
            .or_default()
            .push(*id);
    }
    for snapshot in snapshots {
        if !runtime_latency_snapshot_has_result(snapshot) {
            continue;
        }
        let Some(link_hash) = runtime_latency_snapshot_link_hash(snapshot) else {
            continue;
        };
        let matched_ids = node_ids_by_link_hash
            .get(link_hash)
            .cloned()
            .unwrap_or_default();
        if matched_ids.is_empty() {
            continue;
        }
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
        for node_id in matched_ids {
            tested_ids.insert(node_id);
            results.push(NodeLatencyWrite {
                node_id,
                latency_ms,
                alive,
                tested_at: checked_at.clone(),
                message: if latency_ms.is_some() {
                    None
                } else {
                    message.clone()
                },
            });
        }
    }
    (results, tested_ids)
}

fn runtime_latency_snapshot_link_hash(snapshot: &Value) -> Option<&str> {
    snapshot
        .get("linkHash")
        .and_then(Value::as_str)
        .or_else(|| {
            snapshot
                .pointer("/linkIdentity/linkHash")
                .and_then(Value::as_str)
        })
}

fn runtime_latency_snapshot_has_result(snapshot: &Value) -> bool {
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

fn store_node_latency_result(conn: &Connection, result: &NodeLatencyWrite) -> io::Result<()> {
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

fn native_probe_unavailable_results(
    nodes: &[(i64, String, String)],
    tested_at: &str,
) -> Vec<NodeLatencyWrite> {
    nodes
        .iter()
        .map(|(id, _, _)| NodeLatencyWrite {
            node_id: *id,
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

fn all_latency_probe_nodes(conn: &Connection) -> io::Result<Vec<(i64, String, String)>> {
    let mut stmt = conn
        .prepare("SELECT id, link, address FROM nodes ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut nodes = Vec::new();
    for row in rows {
        nodes.push(row.map_err(sqlite_io_error)?);
    }
    Ok(nodes)
}

fn all_node_ids(conn: &Connection) -> io::Result<Vec<i64>> {
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
