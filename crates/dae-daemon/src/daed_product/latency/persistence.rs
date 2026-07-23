use super::super::*;
use super::*;

pub(super) const NODE_LATENCY_DB_WRITE_BATCH_SIZE: usize = 128;

#[derive(Debug, Default)]
pub(super) struct LatencyPersistenceQueue {
    pending: Mutex<BTreeMap<i64, NodeLatencyWrite>>,
}

#[derive(Debug, Default)]
pub(super) struct LatencyPersistenceFlush {
    pub(super) pending: usize,
    pub(super) error: Option<String>,
}

impl LatencyPersistenceQueue {
    pub(super) fn queue(&self, results: &[NodeLatencyWrite]) -> io::Result<usize> {
        if results
            .iter()
            .any(|result| result.desired_state_revision.is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "selected-state latency results cannot enter the retry queue",
            ));
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("latency persistence queue lock poisoned"))?;
        for result in results {
            pending.insert(result.node_id, result.clone());
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
        let results = queued.into_values().collect::<Vec<_>>();
        let result = open_state_connection(state)
            .and_then(|mut conn| write_node_latency_results(&mut conn, &results));
        match result {
            Ok(_) => LatencyPersistenceFlush {
                pending: self.pending_count(),
                error: None,
            },
            Err(err) => {
                self.restore_pending(results);
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

    fn take_pending(&self) -> io::Result<BTreeMap<i64, NodeLatencyWrite>> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("latency persistence queue lock poisoned"))?;
        Ok(std::mem::take(&mut *pending))
    }

    fn restore_pending(&self, queued: Vec<NodeLatencyWrite>) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        for result in queued {
            pending.entry(result.node_id).or_insert(result);
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
    let active_probe_generation = active_runtime_probe_generation(&tx)?;
    let current_desired_state_revision = results
        .iter()
        .any(|result| result.desired_state_revision.is_some())
        .then(|| runtime_desired_state_revision_from_connection(&tx))
        .transpose()?;
    let mut written = 0_usize;
    let mut alive = 0_usize;
    for result in results {
        if latency_result_fence_is_current(
            result,
            active_probe_generation,
            current_desired_state_revision.as_ref(),
        ) && node_latency_result_target_exists(&tx, result.node_id, &result.node_link)?
        {
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

fn active_runtime_probe_generation(conn: &Connection) -> io::Result<Option<u64>> {
    let value = conn
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?;
    value
        .map(|value| {
            value.parse::<u64>().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid active runtime probe generation {value:?}: {err}"),
                )
            })
        })
        .transpose()
}

fn probe_generation_is_current(write: Option<u64>, active: Option<u64>) -> bool {
    write == active
}

fn latency_result_fence_is_current(
    result: &NodeLatencyWrite,
    active_probe_generation: Option<u64>,
    current_desired_state_revision: Option<&RuntimeDesiredStateRevision>,
) -> bool {
    match result.desired_state_revision.as_deref() {
        Some(desired_state_revision) => {
            result.probe_generation.is_none()
                && active_probe_generation.is_none()
                && current_desired_state_revision == Some(desired_state_revision)
        }
        None => probe_generation_is_current(result.probe_generation, active_probe_generation),
    }
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
    fn persistence_queue_keeps_only_the_latest_result_for_each_node() {
        let queue = LatencyPersistenceQueue::default();
        queue
            .queue(&[
                NodeLatencyWrite {
                    node_id: 7,
                    node_link: "socks://127.0.0.1:1080#old".to_owned(),
                    probe_generation: Some(1),
                    desired_state_revision: None,
                    latency_ms: Some(100),
                    alive: true,
                    tested_at: "old".to_owned(),
                    message: None,
                },
                NodeLatencyWrite {
                    node_id: 7,
                    node_link: "socks://127.0.0.1:1081#new".to_owned(),
                    probe_generation: Some(2),
                    desired_state_revision: None,
                    latency_ms: Some(20),
                    alive: true,
                    tested_at: "new".to_owned(),
                    message: None,
                },
            ])
            .unwrap();

        let pending = queue.take_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[&7].node_link, "socks://127.0.0.1:1081#new");
        assert_eq!(pending[&7].latency_ms, Some(20));
    }

    #[test]
    fn selected_state_results_cannot_outlive_their_job_in_the_retry_queue() {
        let fixture = FreshProductState::new("latency-persistence-selected-queue");
        fixture.seed_selected_resources();
        let revision = Arc::new(
            runtime_desired_state_revision_from_connection(&fixture.connection()).unwrap(),
        );
        let queue = LatencyPersistenceQueue::default();
        let error = queue
            .queue(&[NodeLatencyWrite {
                node_id: 1,
                node_link: "socks://127.0.0.1:1080#one".to_owned(),
                probe_generation: None,
                desired_state_revision: Some(revision),
                latency_ms: Some(11),
                alive: true,
                tested_at: "2026-07-23T00:00:00Z".to_owned(),
                message: None,
            }])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(queue.pending_count(), 0);
    }

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
                probe_generation: None,
                desired_state_revision: None,
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

    #[test]
    fn stale_probe_generation_is_discarded_without_becoming_pending_again() {
        let fixture = FreshProductState::new("latency-persistence-generation");
        let conn = fixture.connection();
        conn.execute(
            "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(1, 'socks://127.0.0.1:1080#one', 'one', '127.0.0.1', 'socks', NULL, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, '2')",
            params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
        )
        .unwrap();
        drop(conn);
        let queue = LatencyPersistenceQueue::default();
        queue
            .queue(&[NodeLatencyWrite {
                node_id: 1,
                node_link: "socks://127.0.0.1:1080#one".to_owned(),
                probe_generation: Some(1),
                desired_state_revision: None,
                latency_ms: Some(11),
                alive: true,
                tested_at: "2026-07-13T00:00:00Z".to_owned(),
                message: None,
            }])
            .unwrap();

        let stale = queue.flush(fixture.state());

        assert_eq!(stale.pending, 0);
        assert!(stale.error.is_none());
        assert_eq!(
            fixture
                .connection()
                .query_row("SELECT COUNT(*) FROM node_latency_results", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );

        queue
            .queue(&[NodeLatencyWrite {
                node_id: 1,
                node_link: "socks://127.0.0.1:1080#one".to_owned(),
                probe_generation: Some(2),
                desired_state_revision: None,
                latency_ms: Some(22),
                alive: true,
                tested_at: "2026-07-13T00:00:01Z".to_owned(),
                message: None,
            }])
            .unwrap();
        let current = queue.flush(fixture.state());
        assert_eq!(current.pending, 0);
        assert!(current.error.is_none());
        assert_eq!(
            fixture
                .connection()
                .query_row(
                    "SELECT latency_ms FROM node_latency_results WHERE node_id = 1",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            22
        );
    }

    #[test]
    fn selected_state_results_require_stopped_runtime_and_matching_revision() {
        let fixture = FreshProductState::new("latency-persistence-selected-state");
        fixture.seed_selected_resources();
        let mut conn = fixture.connection();
        conn.execute(
            "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(1, 'socks://127.0.0.1:1080#one', 'one', '127.0.0.1', 'socks', NULL, NULL)",
            [],
        )
        .unwrap();
        let revision = Arc::new(runtime_desired_state_revision_from_connection(&conn).unwrap());
        let result = |latency_ms| NodeLatencyWrite {
            node_id: 1,
            node_link: "socks://127.0.0.1:1080#one".to_owned(),
            probe_generation: None,
            desired_state_revision: Some(Arc::clone(&revision)),
            latency_ms: Some(latency_ms),
            alive: true,
            tested_at: "2026-07-23T00:00:00Z".to_owned(),
            message: None,
        };

        assert_eq!(
            write_node_latency_results(&mut conn, &[result(11)]).unwrap(),
            (1, 1)
        );
        conn.execute(
            "UPDATE dns SET version = version + 1 WHERE selected = 1",
            [],
        )
        .unwrap();
        assert_eq!(
            write_node_latency_results(&mut conn, &[result(22)]).unwrap(),
            (0, 0)
        );
        assert_eq!(
            conn.query_row(
                "SELECT latency_ms FROM node_latency_results WHERE node_id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            11
        );

        let current_revision =
            Arc::new(runtime_desired_state_revision_from_connection(&conn).unwrap());
        conn.execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, '9')",
            params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
        )
        .unwrap();
        let running_result = NodeLatencyWrite {
            desired_state_revision: Some(current_revision),
            ..result(33)
        };
        assert_eq!(
            write_node_latency_results(&mut conn, &[running_result]).unwrap(),
            (0, 0)
        );
    }

    #[test]
    fn queued_write_becomes_stale_while_database_is_busy_and_is_not_retried_forever() {
        let fixture = FreshProductState::new("latency-persistence-stale-retry");
        let conn = fixture.connection();
        conn.execute(
            "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(1, 'socks://127.0.0.1:1080#one', 'one', '127.0.0.1', 'socks', NULL, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, '1')",
            params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_generation_latency
             BEFORE INSERT ON node_latency_results
             BEGIN
                 SELECT RAISE(ABORT, 'injected generation write failure');
             END;",
        )
        .unwrap();
        drop(conn);
        let queue = LatencyPersistenceQueue::default();
        queue
            .queue(&[NodeLatencyWrite {
                node_id: 1,
                node_link: "socks://127.0.0.1:1080#one".to_owned(),
                probe_generation: Some(1),
                desired_state_revision: None,
                latency_ms: Some(11),
                alive: true,
                tested_at: "2026-07-13T00:00:00Z".to_owned(),
                message: None,
            }])
            .unwrap();
        assert_eq!(queue.flush(fixture.state()).pending, 1);

        let conn = fixture.connection();
        conn.execute("DROP TRIGGER reject_generation_latency", [])
            .unwrap();
        conn.execute(
            "UPDATE daed_product_metadata SET value = '2' WHERE key = ?1",
            params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
        )
        .unwrap();
        drop(conn);

        let flush = queue.flush(fixture.state());
        assert_eq!(flush.pending, 0);
        assert!(flush.error.is_none());
        assert_eq!(
            fixture
                .connection()
                .query_row("SELECT COUNT(*) FROM node_latency_results", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }
}
