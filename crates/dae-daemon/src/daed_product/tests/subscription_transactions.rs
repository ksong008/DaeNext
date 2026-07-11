use super::support::FreshProductState;
use super::*;

fn seed_subscription(fixture: &FreshProductState) {
    fixture
        .connection()
        .execute(
            "INSERT INTO subscriptions(
                id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy
             ) VALUES(7, 'old-time', 'https://example.invalid/old', ?1, 1, 'old-status', 'old-info', 'old-tag', 0)",
            params![DEFAULT_SUBSCRIPTION_CRON_EXP],
        )
        .unwrap();
}

fn reject_external_input_bump(fixture: &FreshProductState) {
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_external_input_bump
            BEFORE INSERT ON daed_product_metadata
            WHEN NEW.key = 'runtime_external_input_version'
            BEGIN
                SELECT RAISE(ABORT, 'injected external input bump failure');
            END;
            "#,
        )
        .unwrap();
}

#[test]
fn subscription_refresh_rolls_back_node_swap_when_external_input_bump_fails() {
    let fixture = FreshProductState::new("subscription-refresh-bump-transaction");
    seed_subscription(&fixture);
    reject_external_input_bump(&fixture);

    let error = apply_subscription_refresh_result(
        fixture.state(),
        7,
        "new-time",
        &["socks://127.0.0.1:1080#new-node".to_owned()],
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected external input bump failure")
    );
    let conn = fixture.connection();
    assert_eq!(count_nodes_for_subscription(&conn, 7).unwrap(), 0);
    assert_eq!(
        conn.query_row("SELECT status FROM subscriptions WHERE id = 7", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "old-status"
    );
    assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 0);
}

#[test]
fn subscription_delete_rolls_back_when_external_input_bump_fails() {
    let fixture = FreshProductState::new("subscription-delete-bump-transaction");
    seed_subscription(&fixture);
    replace_subscription_nodes(
        &fixture.connection(),
        7,
        &["socks://127.0.0.1:1080#old-node".to_owned()],
    )
    .unwrap();
    reject_external_input_bump(&fixture);

    let error = delete_subscription(fixture.state(), 7).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected external input bump failure")
    );
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM subscriptions WHERE id = 7",
            [],
            |row| { row.get::<_, i64>(0) }
        )
        .unwrap(),
        1
    );
    assert_eq!(count_nodes_for_subscription(&conn, 7).unwrap(), 1);
    assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 0);
}

#[test]
fn subscription_field_save_is_atomic() {
    let fixture = FreshProductState::new("subscription-field-transaction");
    seed_subscription(&fixture);
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_subscription_proxy_update
            BEFORE UPDATE OF use_proxy ON subscriptions
            WHEN NEW.id = 7
            BEGIN
                SELECT RAISE(ABORT, 'injected subscription field failure');
            END;
            "#,
        )
        .unwrap();
    let request = HttpRequest {
        method: "PATCH".to_owned(),
        path: "/api/subscriptions/7".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"link":"https://example.invalid/new","tag":"new-tag","cronExp":"15 * * * *","cronEnable":false,"useProxy":true}"#.to_vec(),
    };

    let response = update_subscription(fixture.state(), &request, 7);

    assert_eq!(response.status, 400);
    let subscription = get_subscription_value(fixture.state(), 7).unwrap().unwrap();
    assert_eq!(subscription["link"], json!("https://example.invalid/old"));
    assert_eq!(subscription["tag"], json!("old-tag"));
    assert_eq!(
        subscription["cronExp"],
        json!(DEFAULT_SUBSCRIPTION_CRON_EXP)
    );
    assert_eq!(subscription["cronEnable"], json!(true));
    assert_eq!(subscription["useProxy"], json!(false));
}

#[test]
fn removed_subscription_nodes_invalidate_live_group_bindings() {
    let fixture = FreshProductState::new("subscription-live-group-binding");
    seed_subscription(&fixture);
    apply_subscription_refresh_result(
        fixture.state(),
        7,
        "first-refresh",
        &["socks://127.0.0.1:1080#live-node".to_owned()],
    )
    .unwrap();
    let conn = fixture.connection();
    let node_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, 'live-group', 'min', 0)",
        [],
    )
    .unwrap();
    apply_group_node_ids(&conn, 9, &[node_id], true).unwrap();
    conn.execute(
        "INSERT INTO node_latency_results(
            node_id, latency_ms, alive, tested_at, message, updated_at
         ) VALUES(?1, 12, 1, 'now', NULL, 'now')",
        params![node_id],
    )
    .unwrap();
    let binding: (String, Option<i64>) = conn
        .query_row(
            "SELECT binding_mode, source_subscription_id
             FROM group_nodes WHERE group_id = 9 AND node_id = ?1",
            params![node_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(binding, ("subscription".to_owned(), Some(7)));
    drop(conn);

    let (changed, _) =
        apply_subscription_refresh_result(fixture.state(), 7, "second-refresh", &[]).unwrap();
    assert!(changed);
    let conn = fixture.connection();
    assert_eq!(count_nodes_for_subscription(&conn, 7).unwrap(), 0);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM group_nodes WHERE group_id = 9",
            [],
            |row| { row.get::<_, i64>(0) }
        )
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![node_id],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
}

#[test]
fn large_subscription_refresh_keeps_concurrent_reads_available_when_enabled() {
    if std::env::var_os("DAE_RUN_SUBSCRIPTION_PRESSURE_FIXTURE").is_none() {
        return;
    }

    let fixture = FreshProductState::new("subscription-refresh-pressure");
    seed_subscription(&fixture);
    let links = (0..30_000)
        .map(|index| format!("socks://127.0.0.1:{}#node-{index}", 10_000 + index))
        .collect::<Vec<_>>();
    let state = fixture.state().to_path_buf();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let read_errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let read_count = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let state = state.clone();
        let done = Arc::clone(&done);
        let read_errors = Arc::clone(&read_errors);
        let read_count = Arc::clone(&read_count);
        readers.push(thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let result = open_state_connection(&state).and_then(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get::<_, i64>(0))
                        .map_err(sqlite_io_error)
                });
                match result {
                    Ok(_) => {
                        read_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        read_errors.lock().unwrap().push(err.to_string());
                        break;
                    }
                }
            }
        }));
    }
    let write_errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut writers = Vec::new();
    for index in 0..8 {
        let state = state.clone();
        let write_errors = Arc::clone(&write_errors);
        writers.push(thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let result = open_state_connection(&state).and_then(|conn| {
                conn.execute(
                    "INSERT INTO configs(name, global, selected, version) VALUES(?1, 'global {}', 0, 0)",
                    params![format!("pressure-writer-{index}")],
                )
                .map(|_| ())
                .map_err(sqlite_io_error)
            });
            if let Err(err) = result {
                write_errors.lock().unwrap().push(err.to_string());
            }
        }));
    }

    let started = Instant::now();
    let (_, results) =
        apply_subscription_refresh_result(&state, 7, "pressure-time", &links).unwrap();
    let elapsed = started.elapsed();
    done.store(true, Ordering::Release);
    for reader in readers {
        reader.join().unwrap();
    }
    for writer in writers {
        writer.join().unwrap();
    }

    assert_eq!(results.len(), links.len());
    assert_eq!(
        count_nodes_for_subscription(&fixture.connection(), 7).unwrap(),
        30_000
    );
    assert!(read_errors.lock().unwrap().is_empty());
    assert!(write_errors.lock().unwrap().is_empty());
    assert!(read_count.load(Ordering::Relaxed) > 0);
    eprintln!(
        "subscription_pressure nodes={} elapsed_ms={} concurrent_reads={} concurrent_writes={}",
        links.len(),
        elapsed.as_millis(),
        read_count.load(Ordering::Relaxed),
        8
    );
}
