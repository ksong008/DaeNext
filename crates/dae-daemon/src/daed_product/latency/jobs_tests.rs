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
            parsed.display_name,
            parsed.address,
            parsed.protocol,
            format!("node-{id}")
        ],
    )
    .unwrap();
}

#[test]
fn selector_application_survives_latency_persistence_failure() {
    let (dir, state) = temp_state("selector-before-persistence");
    let conn = open_state_connection(&state).unwrap();
    insert_latency_probe_node(&conn, 1, "socks://127.0.0.1:1080#one");
    conn.execute_batch(
        "CREATE TRIGGER reject_latency_persistence
         BEFORE INSERT ON node_latency_results
         BEGIN
             SELECT RAISE(ABORT, 'injected latency persistence failure');
         END;",
    )
    .unwrap();
    drop(conn);
    let jobs = LatencyJobManager::default();
    let applied = std::sync::atomic::AtomicBool::new(false);
    let results = vec![NodeLatencyWrite {
        node_id: 1,
        node_link: "socks://127.0.0.1:1080#one".to_owned(),
        probe_generation: None,
        desired_state_revision: None,
        latency_ms: Some(9),
        alive: true,
        tested_at: "now".to_owned(),
        message: None,
    }];

    let counts = apply_and_persist_runtime_latency_results(
        &jobs,
        1,
        &LatencyJobCancellation::new(1),
        &state,
        &[json!({"alive": true, "latencyMs": 9})],
        &results,
        |_| applied.store(true, Ordering::Release),
    );

    assert_eq!(counts, (1, 1));
    assert!(applied.load(Ordering::Acquire));
    assert_eq!(jobs.persistence.pending_count(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cancelled_latency_job_does_not_apply_or_persist_new_results() {
    let (dir, state) = temp_state("cancelled-before-apply");
    let conn = open_state_connection(&state).unwrap();
    insert_latency_probe_node(&conn, 1, "socks://127.0.0.1:1080#one");
    drop(conn);
    let jobs = LatencyJobManager::default();
    let (job, _) = jobs.start_or_current(1).unwrap();
    let cancellation = job.cancellation();
    jobs.request_cancel(job.id()).unwrap();
    let applied = std::sync::atomic::AtomicBool::new(false);
    let results = vec![NodeLatencyWrite {
        node_id: 1,
        node_link: "socks://127.0.0.1:1080#one".to_owned(),
        probe_generation: None,
        desired_state_revision: None,
        latency_ms: Some(9),
        alive: true,
        tested_at: "now".to_owned(),
        message: None,
    }];

    let counts = apply_and_persist_runtime_latency_results(
        &jobs,
        job.id(),
        &cancellation,
        &state,
        &[json!({"alive": true, "latencyMs": 9})],
        &results,
        |_| applied.store(true, Ordering::Release),
    );

    assert_eq!(counts, (0, 0));
    assert!(!applied.load(Ordering::Acquire));
    assert_eq!(jobs.persistence.pending_count(), 0);
    assert_eq!(
        list_stored_node_latencies_value(&state).unwrap()["items"][0]["testedAt"].as_str(),
        Some("")
    );
    fs::remove_dir_all(dir).unwrap();
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
        LatencyProbeNode::new(1, "socks://127.0.0.1:1080#one".to_owned()),
        LatencyProbeNode::new(2, "socks://127.0.0.1:1081#two".to_owned()),
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
            probe_generation: None,
            desired_state_revision: None,
            latency_ms: Some(11),
            alive: true,
            tested_at: "2026-06-29T00:00:00Z".to_owned(),
            message: None,
        },
        NodeLatencyWrite {
            node_id: 2,
            node_link: "socks://127.0.0.1:1081#two".to_owned(),
            probe_generation: None,
            desired_state_revision: None,
            latency_ms: Some(22),
            alive: true,
            tested_at: "2026-06-29T00:00:00Z".to_owned(),
            message: None,
        },
        NodeLatencyWrite {
            node_id: 3,
            node_link: "socks://127.0.0.1:1082#three".to_owned(),
            probe_generation: None,
            desired_state_revision: None,
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

#[test]
fn write_node_latency_results_batches_large_sets() {
    let (dir, state) = temp_state("write-batched");
    let mut conn = open_state_connection(&state).unwrap();
    let total = NODE_LATENCY_DB_WRITE_BATCH_SIZE + 7;
    let changed_node_id = i64::try_from(total).unwrap();
    let mut results = Vec::with_capacity(total);
    for id in 1..=changed_node_id {
        let link = format!("socks://127.0.0.1:{}#node-{id}", 10_000_i64 + id);
        insert_latency_probe_node(&conn, id, &link);
        results.push(NodeLatencyWrite {
            node_id: id,
            node_link: link,
            probe_generation: None,
            desired_state_revision: None,
            latency_ms: Some(id),
            alive: true,
            tested_at: "2026-07-10T00:00:00Z".to_owned(),
            message: None,
        });
    }
    conn.execute(
        "UPDATE nodes SET link = ?1 WHERE id = ?2",
        params!["socks://127.0.0.1:29999#changed-node", changed_node_id],
    )
    .unwrap();

    let (written, alive) = write_node_latency_results(&mut conn, &results).unwrap();

    assert_eq!((written, alive), (total - 1, total - 1));
    let stored_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM node_latency_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stored_rows, i64::try_from(total - 1).unwrap());
    fs::remove_dir_all(dir).unwrap();
}
