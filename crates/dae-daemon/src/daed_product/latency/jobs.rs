use super::super::*;
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
    drop(conn);
    let (job, should_spawn) = jobs.start_or_current(nodes.len())?;
    let mut value = list_stored_node_latencies_value(state)?;
    value["job"] = job.to_value();
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_node_latency_job_inner(job_id, &state, &config_dir, &runtime, &jobs, &nodes)
    }));
    match result {
        Ok(Ok((completed, succeeded, failed))) => {
            jobs.mark_finished(job_id, completed, succeeded, failed);
        }
        Ok(Err(err)) => jobs.mark_failed(job_id, err.to_string()),
        Err(payload) => jobs.mark_failed(
            job_id,
            format!(
                "manual latency probe panicked: {}",
                panic_payload_message(payload.as_ref())
            ),
        ),
    }
    drop(nodes);
    drop(runtime);
    drop(jobs);
    drop(config_dir);
    drop(state);
    let _ = allocator_reclaim(AllocatorReclaimReason::ManualLatencyProbe);
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic payload".to_owned()
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
        let generation = handle.probe_generation();
        let chunk_size = handle
            .probe_batch_size(latency_probe_unique_link_count(nodes))
            .max(1);
        for link_chunk in latency_probe_link_chunks(nodes, chunk_size) {
            let chunk_nodes = latency_probe_nodes_for_links(nodes, &link_chunk);
            let chunk_nodes = current_latency_probe_nodes(&conn, &chunk_nodes)?;
            if chunk_nodes.is_empty() {
                continue;
            }
            let link_chunk = latency_probe_unique_links(&chunk_nodes);
            let mut write_error = None;
            let mut emitted_snapshots = Vec::<Value>::new();
            handle.probe_node_latencies_streaming_without_group_update(
                &link_chunk,
                |runtime_snapshots| {
                    if let Some(generation) = generation
                        && runtime.current_probe_generation() != Some(generation)
                    {
                        return;
                    }
                    if write_error.is_some() {
                        return;
                    }
                    emitted_snapshots.extend_from_slice(runtime_snapshots);
                    let results = node_latency_results_for_runtime_snapshots_only(
                        &chunk_nodes,
                        runtime_snapshots,
                    );
                    if results.is_empty() {
                        return;
                    }
                    match write_node_latency_results(&mut conn, &results) {
                        Ok((written, alive)) => {
                            if written == 0 {
                                return;
                            }
                            handle.apply_latency_probe_snapshots_to_groups(runtime_snapshots);
                            completed = completed.saturating_add(written);
                            succeeded = succeeded.saturating_add(alive);
                            jobs.mark_progress(
                                job_id,
                                completed,
                                succeeded,
                                completed.saturating_sub(succeeded),
                            );
                        }
                        Err(err) => write_error = Some(err),
                    }
                },
            );
            if let Some(err) = write_error {
                return Err(err);
            }
            if let Some(generation) = generation
                && runtime.current_probe_generation() != Some(generation)
            {
                let failures = latency_probe_failure_snapshots_for_unseen_links(
                    &link_chunk,
                    generation,
                    "manual latency probe result discarded",
                    "resident runtime generation changed while latency probe was running",
                    &emitted_snapshots,
                );
                if failures.is_empty() {
                    continue;
                }
                let results = node_latency_results_for_runtime_snapshots(&chunk_nodes, &failures);
                let (written, alive) = write_node_latency_results(&mut conn, &results)?;
                if written != 0 {
                    completed = completed.saturating_add(written);
                    succeeded = succeeded.saturating_add(alive);
                    jobs.mark_progress(
                        job_id,
                        completed,
                        succeeded,
                        completed.saturating_sub(succeeded),
                    );
                }
            }
        }
    } else if !nodes.is_empty() {
        let nodes = current_latency_probe_nodes(&conn, nodes)?;
        let tested_at = now_text();
        let results = native_probe_unavailable_results(&nodes, &tested_at);
        let (written, alive) = write_node_latency_results(&mut conn, &results)?;
        if written != 0 {
            completed = written;
            succeeded = alive;
            jobs.mark_progress(
                job_id,
                completed,
                succeeded,
                completed.saturating_sub(succeeded),
            );
        }
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
    latency_probe_unique_links(nodes)
        .chunks(chunk_size.max(1))
        .map(|chunk| chunk.to_vec())
        .collect()
}

pub(crate) fn latency_probe_unique_link_count(nodes: &[(i64, String, String)]) -> usize {
    latency_probe_unique_links(nodes).len()
}

fn latency_probe_unique_links(nodes: &[(i64, String, String)]) -> Vec<String> {
    let mut seen = HashSet::with_capacity(nodes.len());
    let mut links = Vec::with_capacity(nodes.len());
    for (_, link, _) in nodes {
        if seen.insert(link.as_str()) {
            links.push(link.clone());
        }
    }
    links
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

pub(crate) fn node_latency_results_for_runtime_snapshots_only(
    nodes: &[(i64, String, String)],
    runtime_snapshots: &[Value],
) -> Vec<NodeLatencyWrite> {
    runtime_node_latency_results_for_nodes(nodes, runtime_snapshots).0
}

fn write_node_latency_results(
    conn: &mut Connection,
    results: &[NodeLatencyWrite],
) -> io::Result<(usize, usize)> {
    let tx = conn.transaction().map_err(sqlite_io_error)?;
    let mut written = 0_usize;
    let mut alive = 0_usize;
    for result in results {
        if !node_latency_result_target_exists(&tx, result.node_id, &result.node_link)? {
            continue;
        }
        store_node_latency_result(&tx, result)?;
        written = written.saturating_add(1);
        if result.alive {
            alive = alive.saturating_add(1);
        }
    }
    tx.commit().map_err(sqlite_io_error)?;
    Ok((written, alive))
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

fn current_latency_probe_nodes(
    conn: &Connection,
    nodes: &[(i64, String, String)],
) -> io::Result<Vec<(i64, String, String)>> {
    let mut current = Vec::with_capacity(nodes.len());
    for (id, link, address) in nodes {
        if latency_probe_node_identity_exists(conn, *id, link)? {
            current.push((*id, link.clone(), address.clone()));
        }
    }
    Ok(current)
}

fn latency_probe_node_identity_exists(conn: &Connection, id: i64, link: &str) -> io::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM nodes WHERE id = ?1 AND link = ?2",
        params![id, link],
        |_| Ok(()),
    )
    .optional()
    .map(|value| value.is_some())
    .map_err(sqlite_io_error)
}

fn node_latency_result_target_exists(
    conn: &Connection,
    node_id: i64,
    node_link: &str,
) -> io::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM nodes WHERE id = ?1 AND link = ?2",
        params![node_id, node_link],
        |_| Ok(()),
    )
    .optional()
    .map(|value| value.is_some())
    .map_err(sqlite_io_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state(name: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("daed-product-latency-{name}-{}", fastrand::u64(..)));
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("state.db");
        ensure_state_schema(&state).unwrap();
        (dir, state)
    }

    fn insert_latency_probe_node(conn: &Connection, id: i64, link: &str) {
        let parsed = parse_node_link(link, Some(&format!("node-{id}")));
        conn.execute(
            "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                id,
                link,
                parsed.name,
                parsed.address,
                parsed.protocol,
                format!("node-{id}")
            ],
        )
        .unwrap();
    }

    #[test]
    fn panic_payload_message_preserves_string_payloads() {
        let literal = "latency panic literal";
        let owned = "latency panic string".to_owned();

        assert_eq!(panic_payload_message(&literal), literal);
        assert_eq!(panic_payload_message(&owned), owned);
    }

    #[test]
    fn current_latency_probe_nodes_skip_deleted_or_changed_nodes() {
        let (dir, state) = temp_state("current-nodes");
        let conn = open_state_connection(&state).unwrap();
        insert_latency_probe_node(&conn, 1, "socks://127.0.0.1:1080#one");
        insert_latency_probe_node(&conn, 2, "socks://127.0.0.1:1081#two");
        conn.execute(
            "UPDATE nodes SET link = ?1 WHERE id = ?2",
            params!["socks://127.0.0.1:2081#two", 2_i64],
        )
        .unwrap();
        conn.execute("DELETE FROM nodes WHERE id = ?1", params![1_i64])
            .unwrap();

        let nodes = vec![
            (
                1_i64,
                "socks://127.0.0.1:1080#one".to_owned(),
                "127.0.0.1".to_owned(),
            ),
            (
                2_i64,
                "socks://127.0.0.1:1081#two".to_owned(),
                "127.0.0.1".to_owned(),
            ),
        ];

        let current = current_latency_probe_nodes(&conn, &nodes).unwrap();

        assert!(current.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_node_latency_results_skips_deleted_or_changed_nodes() {
        let (dir, state) = temp_state("write-current");
        let mut conn = open_state_connection(&state).unwrap();
        insert_latency_probe_node(&conn, 1, "socks://127.0.0.1:1080#one");
        insert_latency_probe_node(&conn, 3, "socks://127.0.0.1:1082#three");
        conn.execute(
            "UPDATE nodes SET link = ?1 WHERE id = ?2",
            params!["socks://127.0.0.1:2082#three", 3_i64],
        )
        .unwrap();
        let results = vec![
            NodeLatencyWrite {
                node_id: 1,
                node_link: "socks://127.0.0.1:1080#one".to_owned(),
                latency_ms: Some(11),
                alive: true,
                tested_at: "2026-06-29T00:00:00Z".to_owned(),
                message: None,
            },
            NodeLatencyWrite {
                node_id: 2,
                node_link: "socks://127.0.0.1:1081#two".to_owned(),
                latency_ms: Some(22),
                alive: true,
                tested_at: "2026-06-29T00:00:00Z".to_owned(),
                message: None,
            },
            NodeLatencyWrite {
                node_id: 3,
                node_link: "socks://127.0.0.1:1082#three".to_owned(),
                latency_ms: Some(33),
                alive: true,
                tested_at: "2026-06-29T00:00:00Z".to_owned(),
                message: None,
            },
        ];

        let (written, alive) = write_node_latency_results(&mut conn, &results).unwrap();

        assert_eq!((written, alive), (1, 1));
        let orphan_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM node_latency_results WHERE node_id IN (?1, ?2)",
                params![2_i64, 3_i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphan_rows, 0);
        fs::remove_dir_all(dir).unwrap();
    }
}
