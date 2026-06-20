use super::*;

#[derive(Debug, Default)]
pub(crate) struct LatencyJobManager {
    next_id: AtomicU64,
    current: Mutex<Option<LatencyJobRecord>>,
}

#[derive(Clone, Debug)]
pub(crate) struct LatencyJobRecord {
    id: u64,
    status: &'static str,
    total: usize,
    completed: usize,
    succeeded: usize,
    failed: usize,
    queued_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    message: Option<String>,
}

impl LatencyJobManager {
    pub(crate) fn start_or_current(&self, total: usize) -> io::Result<(LatencyJobRecord, bool)> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("latency job manager lock poisoned"))?;
        if let Some(job) = current.as_ref()
            && matches!(job.status, "queued" | "running")
        {
            return Ok((job.clone(), false));
        }
        let id = self
            .next_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let job = LatencyJobRecord {
            id,
            status: "queued",
            total,
            completed: 0,
            succeeded: 0,
            failed: 0,
            queued_at: now_text(),
            started_at: None,
            finished_at: None,
            message: None,
        };
        *current = Some(job.clone());
        Ok((job, true))
    }

    pub(crate) fn current_value(&self) -> Value {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.clone())
            .map(|job| job.to_value())
            .unwrap_or(Value::Null)
    }

    pub(crate) fn is_active(&self) -> bool {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.as_ref().map(|job| job.is_active()))
            .unwrap_or(false)
    }

    fn mark_running(&self, id: u64) {
        self.update_job(id, |job| {
            job.status = "running";
            job.started_at = Some(now_text());
            job.message = Some("manual latency probe running".to_owned());
        });
    }

    fn mark_finished(&self, id: u64, completed: usize, succeeded: usize, failed: usize) {
        self.update_job(id, |job| {
            job.status = "finished";
            job.completed = completed;
            job.succeeded = succeeded;
            job.failed = failed;
            job.finished_at = Some(now_text());
            job.message = Some("manual latency probe finished".to_owned());
        });
    }

    fn mark_progress(&self, id: u64, completed: usize, succeeded: usize, failed: usize) {
        self.update_job(id, |job| {
            if job.is_active() {
                job.status = "running";
                job.completed = completed.min(job.total);
                job.succeeded = succeeded.min(job.completed);
                job.failed = failed.min(job.completed.saturating_sub(job.succeeded));
                job.message = Some(format!(
                    "manual latency probe running ({}/{})",
                    job.completed, job.total
                ));
            }
        });
    }

    fn mark_failed(&self, id: u64, message: String) {
        self.update_job(id, |job| {
            job.status = "failed";
            job.finished_at = Some(now_text());
            job.message = Some(message);
        });
    }

    fn update_job(&self, id: u64, update: impl FnOnce(&mut LatencyJobRecord)) {
        let Ok(mut current) = self.current.lock() else {
            return;
        };
        let Some(job) = current.as_mut().filter(|job| job.id == id) else {
            return;
        };
        update(job);
    }
}

impl LatencyJobRecord {
    fn is_active(&self) -> bool {
        matches!(self.status, "queued" | "running")
    }

    pub(crate) fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "status": self.status,
            "total": self.total,
            "completed": self.completed,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "queuedAt": self.queued_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "message": self.message,
        })
    }
}

pub(crate) fn list_node_latencies_value(
    state: &Path,
    runtime: &ProductRuntimeManager,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    sync_runtime_node_latency_results(&conn, runtime)?;
    list_stored_node_latencies_from_conn(&conn)
}

pub(crate) fn list_stored_node_latencies_value(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    list_stored_node_latencies_from_conn(&conn)
}

fn list_stored_node_latencies_from_conn(conn: &Connection) -> io::Result<Value> {
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

pub(crate) fn enqueue_node_latency_job(
    state: &Path,
    config_dir: &Path,
    runtime: Arc<ProductRuntimeManager>,
    jobs: Arc<LatencyJobManager>,
    ids: &[i64],
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let nodes = latency_probe_nodes_for_ids(&conn, ids)?;
    let (job, should_spawn) = jobs.start_or_current(nodes.len())?;
    if should_spawn {
        let state = state.to_path_buf();
        let config_dir = config_dir.to_path_buf();
        let runtime_for_thread = Arc::clone(&runtime);
        let jobs_for_thread = Arc::clone(&jobs);
        let spawn_result = thread::Builder::new()
            .name(format!("daed-latency-job-{}", job.id))
            .spawn(move || {
                run_node_latency_job(
                    job.id,
                    state,
                    config_dir,
                    runtime_for_thread,
                    jobs_for_thread,
                    nodes,
                );
            });
        if let Err(err) = spawn_result {
            jobs.mark_failed(job.id, format!("spawn manual latency probe job: {err}"));
            return Err(io::Error::other(format!(
                "spawn manual latency probe job: {err}"
            )));
        }
    }
    let mut value = list_stored_node_latencies_value(state)?;
    value["job"] = job.to_value();
    Ok(value)
}

fn run_node_latency_job(
    job_id: u64,
    state: PathBuf,
    config_dir: PathBuf,
    runtime: Arc<ProductRuntimeManager>,
    jobs: Arc<LatencyJobManager>,
    nodes: Vec<(i64, String, String)>,
) {
    jobs.mark_running(job_id);
    match run_node_latency_job_inner(job_id, &state, &config_dir, &runtime, &jobs, &nodes) {
        Ok((completed, succeeded, failed)) => {
            jobs.mark_finished(job_id, completed, succeeded, failed);
        }
        Err(err) => jobs.mark_failed(job_id, err.to_string()),
    }
    drop(nodes);
    drop(runtime);
    drop(jobs);
    drop(config_dir);
    drop(state);
    let _ = allocator_reclaim(AllocatorReclaimReason::ManualLatencyProbe);
}

fn run_node_latency_job_inner(
    job_id: u64,
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    jobs: &LatencyJobManager,
    nodes: &[(i64, String, String)],
) -> io::Result<(usize, usize, usize)> {
    let mut conn = open_state_connection(state)?;
    let mut completed = 0usize;
    let mut succeeded = 0usize;

    if let Some(handle) = runtime.node_latency_probe_handle() {
        let chunk_size = handle.probe_concurrency().max(1);
        for link_chunk in latency_probe_link_chunks(nodes, chunk_size) {
            let chunk_nodes = latency_probe_nodes_for_links(nodes, &link_chunk);
            let runtime_snapshots = handle.probe_node_latencies(&link_chunk);
            let results =
                node_latency_results_for_runtime_snapshots(&chunk_nodes, &runtime_snapshots);
            write_node_latency_results(&mut conn, &results)?;
            completed = completed.saturating_add(results.len());
            succeeded =
                succeeded.saturating_add(results.iter().filter(|result| result.alive).count());
            jobs.mark_progress(
                job_id,
                completed,
                succeeded,
                completed.saturating_sub(succeeded),
            );
        }
    } else if !nodes.is_empty() {
        let tested_at = now_text();
        let results = native_probe_unavailable_results(nodes, &tested_at);
        write_node_latency_results(&mut conn, &results)?;
        completed = results.len();
        succeeded = results.iter().filter(|result| result.alive).count();
        jobs.mark_progress(
            job_id,
            completed,
            succeeded,
            completed.saturating_sub(succeeded),
        );
    }

    append_log_for_config(
        config_dir,
        state,
        "info",
        "node latency probe updated by Rust daed",
    )?;
    Ok((completed, succeeded, completed.saturating_sub(succeeded)))
}

pub(crate) fn latency_probe_link_chunks(
    nodes: &[(i64, String, String)],
    chunk_size: usize,
) -> Vec<Vec<String>> {
    let mut seen = HashSet::with_capacity(nodes.len());
    let mut links = Vec::with_capacity(nodes.len());
    for (_, link, _) in nodes {
        if seen.insert(link.as_str()) {
            links.push(link.clone());
        }
    }
    links
        .chunks(chunk_size.max(1))
        .map(|chunk| chunk.to_vec())
        .collect()
}

pub(crate) fn latency_probe_nodes_for_links(
    nodes: &[(i64, String, String)],
    links: &[String],
) -> Vec<(i64, String, String)> {
    let link_set = links.iter().map(String::as_str).collect::<HashSet<_>>();
    nodes
        .iter()
        .filter(|(_, link, _)| link_set.contains(link.as_str()))
        .cloned()
        .collect()
}

fn node_latency_results_for_runtime_snapshots(
    nodes: &[(i64, String, String)],
    runtime_snapshots: &[Value],
) -> Vec<NodeLatencyWrite> {
    let (runtime_results, runtime_tested_ids) =
        runtime_node_latency_results_for_nodes(nodes, runtime_snapshots);
    let tested_at = now_text();
    let fallback_nodes = nodes
        .iter()
        .filter(|(id, _, _)| !runtime_tested_ids.contains(id))
        .cloned()
        .collect::<Vec<_>>();
    let mut results = runtime_results;
    results.extend(native_probe_unavailable_results(
        &fallback_nodes,
        &tested_at,
    ));
    results
}

fn write_node_latency_results(
    conn: &mut Connection,
    results: &[NodeLatencyWrite],
) -> io::Result<()> {
    let tx = conn.transaction().map_err(sqlite_io_error)?;
    for result in results {
        store_node_latency_result(&tx, result)?;
    }
    tx.commit().map_err(sqlite_io_error)
}

pub(crate) fn current_node_latency_job_value(jobs: &LatencyJobManager) -> Value {
    json!({"job": jobs.current_value()})
}

pub(crate) fn add_node_latency_job_value(value: &mut Value, jobs: &LatencyJobManager) {
    value["job"] = jobs.current_value();
}

pub(crate) fn latency_probe_nodes_for_ids(
    conn: &Connection,
    ids: &[i64],
) -> io::Result<Vec<(i64, String, String)>> {
    let target_ids = if ids.is_empty() {
        all_node_ids(conn)?
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
    Ok(nodes)
}

pub(crate) fn fake_runtime_probe_node_latencies(links: &[String]) -> Vec<Value> {
    links
        .iter()
        .filter(|link| !link.is_empty())
        .map(|link| fake_runtime_tcp_latency_snapshot(link))
        .collect()
}

pub(crate) fn fake_runtime_tcp_latency_snapshot(link: &str) -> Value {
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

pub(crate) fn fake_runtime_tcp_connect(link: &str) -> Result<(), String> {
    let url = url::Url::parse(link).map_err(|err| format!("parse node link: {err}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "node link does not contain a host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "node link does not contain a port".to_owned())?;
    let mut last_error = None;
    for addr in resolve_tcp_addrs(host, port, Duration::from_millis(500))
        .map_err(|err| format!("resolve node endpoint: {err}"))?
    {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(_) => return Ok(()),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error
        .map(|err| format!("connect node endpoint: {err}"))
        .unwrap_or_else(|| "node endpoint resolved to no socket addresses".to_owned()))
}

pub(crate) fn node_name_from_link(link: &str) -> String {
    url::Url::parse(link)
        .ok()
        .and_then(|url| url.fragment().map(str::to_owned))
        .filter(|fragment| !fragment.is_empty())
        .unwrap_or_default()
}

pub(crate) fn runtime_link_identity_value(
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

pub(crate) fn runtime_link_hash(link: &str) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(link.as_bytes())))
}

pub(crate) fn runtime_redacted_link_source(link: &str) -> String {
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
pub(crate) struct NodeLatencyWrite {
    pub(super) node_id: i64,
    pub(super) latency_ms: Option<i64>,
    pub(super) alive: bool,
    pub(super) tested_at: String,
    pub(super) message: Option<String>,
}

pub(crate) fn sync_runtime_node_latency_results(
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

pub(crate) fn runtime_node_latency_results_for_nodes(
    nodes: &[(i64, String, String)],
    snapshots: &[Value],
) -> (Vec<NodeLatencyWrite>, HashSet<i64>) {
    let mut results = Vec::with_capacity(snapshots.len().min(nodes.len()));
    let mut tested_ids = HashSet::with_capacity(nodes.len().min(snapshots.len()));
    let mut node_ids_by_link_hash = HashMap::<String, Vec<i64>>::with_capacity(nodes.len());
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
        let Some(matched_ids) = node_ids_by_link_hash.get(link_hash) else {
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
        for &node_id in matched_ids {
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

pub(crate) fn all_latency_probe_nodes(conn: &Connection) -> io::Result<Vec<(i64, String, String)>> {
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
