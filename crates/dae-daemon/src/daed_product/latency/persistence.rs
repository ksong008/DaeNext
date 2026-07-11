use super::super::*;
use super::*;

pub(super) const NODE_LATENCY_DB_WRITE_BATCH_SIZE: usize = 128;

#[derive(Debug, Default)]
pub(super) struct LatencyPersistenceQueue {
    pending: Mutex<BTreeMap<(i64, String), NodeLatencyWrite>>,
}

#[derive(Debug, Default)]
pub(super) struct LatencyPersistenceFlush {
    pub(super) pending: usize,
    pub(super) error: Option<String>,
}

impl LatencyPersistenceQueue {
    pub(super) fn queue(&self, results: &[NodeLatencyWrite]) -> io::Result<usize> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("latency persistence queue lock poisoned"))?;
        for result in results {
            pending.insert((result.node_id, result.node_link.clone()), result.clone());
        }
        Ok(pending.len())
    }

    pub(super) fn flush(&self, state: &Path) -> LatencyPersistenceFlush {
        let queued = match self.take_pending() {
            Ok(queued) => queued,
            Err(err) => {
                return LatencyPersistenceFlush {
                    pending: self.pending_count(),
                    error: Some(err.to_string()),
                };
            }
        };
        if queued.is_empty() {
            return LatencyPersistenceFlush::default();
        }
        let results = queued.values().cloned().collect::<Vec<_>>();
        let result = open_state_connection(state)
            .and_then(|mut conn| write_node_latency_results(&mut conn, &results));
        match result {
            Ok(_) => LatencyPersistenceFlush {
                pending: self.pending_count(),
                error: None,
            },
            Err(err) => {
                self.restore_pending(queued);
                LatencyPersistenceFlush {
                    pending: self.pending_count(),
                    error: Some(err.to_string()),
                }
            }
        }
    }

    pub(super) fn pending_count(&self) -> usize {
        self.pending
            .lock()
            .map(|pending| pending.len())
            .unwrap_or(0)
    }

    fn take_pending(&self) -> io::Result<BTreeMap<(i64, String), NodeLatencyWrite>> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("latency persistence queue lock poisoned"))?;
        Ok(std::mem::take(&mut *pending))
    }

    fn restore_pending(&self, queued: BTreeMap<(i64, String), NodeLatencyWrite>) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        for (key, result) in queued {
            pending.entry(key).or_insert(result);
        }
    }
}

pub(super) fn write_node_latency_results(
    conn: &mut Connection,
    results: &[NodeLatencyWrite],
) -> io::Result<(usize, usize)> {
    let mut written = 0_usize;
    let mut alive = 0_usize;
    for chunk in results.chunks(NODE_LATENCY_DB_WRITE_BATCH_SIZE) {
        let (chunk_written, chunk_alive) = write_node_latency_results_chunk(conn, chunk)?;
        written = written.saturating_add(chunk_written);
        alive = alive.saturating_add(chunk_alive);
        if chunk_written != 0 {
            thread::yield_now();
        }
    }
    Ok((written, alive))
}

fn write_node_latency_results_chunk(
    conn: &mut Connection,
    results: &[NodeLatencyWrite],
) -> io::Result<(usize, usize)> {
    let tx = conn.transaction().map_err(sqlite_io_error)?;
    let mut written = 0_usize;
    let mut alive = 0_usize;
    for result in results {
        if node_latency_result_target_exists(&tx, result.node_id, &result.node_link)? {
            store_node_latency_result(&tx, result)?;
            written = written.saturating_add(1);
            if result.alive {
                alive = alive.saturating_add(1);
            }
        }
    }
    tx.commit().map_err(sqlite_io_error)?;
    Ok((written, alive))
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
    use super::super::super::tests::support::FreshProductState;
    use super::*;

    #[test]
    fn persistence_failure_keeps_results_pending_until_a_later_flush() {
        let fixture = FreshProductState::new("latency-persistence-pending");
        let conn = fixture.connection();
        conn.execute(
            "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(1, 'socks://127.0.0.1:1080#one', 'one', '127.0.0.1', 'socks', NULL, NULL)",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_latency_persistence
             BEFORE INSERT ON node_latency_results
             BEGIN
                 SELECT RAISE(ABORT, 'injected latency persistence failure');
             END;",
        )
        .unwrap();
        drop(conn);

        let queue = LatencyPersistenceQueue::default();
        queue
            .queue(&[NodeLatencyWrite {
                node_id: 1,
                node_link: "socks://127.0.0.1:1080#one".to_owned(),
                latency_ms: Some(11),
                alive: true,
                tested_at: "now".to_owned(),
                message: None,
            }])
            .unwrap();
        let failed = queue.flush(fixture.state());
        assert_eq!(failed.pending, 1);
        assert!(
            failed
                .error
                .unwrap()
                .contains("injected latency persistence failure")
        );

        fixture
            .connection()
            .execute("DROP TRIGGER reject_latency_persistence", [])
            .unwrap();
        let flushed = queue.flush(fixture.state());
        assert_eq!(flushed.pending, 0);
        assert!(flushed.error.is_none());
        assert_eq!(
            fixture
                .connection()
                .query_row(
                    "SELECT latency_ms FROM node_latency_results WHERE node_id = 1",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            11
        );
    }
}
