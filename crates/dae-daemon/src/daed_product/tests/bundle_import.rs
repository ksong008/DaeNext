use super::support::FreshProductState;
use super::*;

fn insert_fixture_user(fixture: &FreshProductState, storage: &str) -> UserRecord {
    let conn = fixture.connection();
    conn.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage)
         VALUES('bundle-user', 'hash', 'secret', ?1)",
        params![storage],
    )
    .unwrap();
    load_user_by_id(fixture.state(), conn.last_insert_rowid())
        .unwrap()
        .unwrap()
}

fn read_request_bytes(raw: Vec<u8>) -> io::Result<HttpRequest> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let writer = thread::spawn(move || -> io::Result<()> {
        let mut stream = TcpStream::connect(address)?;
        stream.write_all(&raw)?;
        stream.shutdown(std::net::Shutdown::Write)
    });
    let (mut stream, _) = listener.accept()?;
    let request = read_http_request(&mut stream);
    writer
        .join()
        .map_err(|_| io::Error::other("bundle request writer panicked"))??;
    request.map_err(io::Error::other)
}

fn json_put_request(path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

#[test]
fn bundle_import_validation_failure_does_not_mutate_database_or_storage() {
    let fixture = FreshProductState::new("bundle-validation-rollback");
    fixture.seed_selected_resources();
    let user = insert_fixture_user(&fixture, r#"{"mode":"rule","defaultConfigID":"1"}"#);
    let mut bundle = export_bundle(fixture.state(), &user).unwrap();
    bundle["selected"]["configId"] = json!(999);
    let before_global: String = fixture
        .connection()
        .query_row("SELECT global FROM configs WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();

    let error = import_bundle(fixture.state(), fixture.root(), &bundle, &user).unwrap_err();

    assert!(error.to_string().contains("references missing id 999"));
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row("SELECT global FROM configs WHERE id = 1", [], |row| row
            .get::<_, String>(
            0
        ))
        .unwrap(),
        before_global
    );
    assert_eq!(
        conn.query_row(
            "SELECT json_storage FROM users WHERE id = ?1",
            params![user.id],
            |row| { row.get::<_, String>(0) }
        )
        .unwrap(),
        user.json_storage
    );
}

#[test]
fn bundle_import_user_storage_failure_rolls_back_resource_replacement() {
    let fixture = FreshProductState::new("bundle-storage-rollback");
    fixture.seed_selected_resources();
    let user = insert_fixture_user(&fixture, r#"{"mode":"rule"}"#);
    let mut bundle = export_bundle(fixture.state(), &user).unwrap();
    bundle["configs"][0]["global"] = json!("global { log_level: debug }");
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_bundle_user_storage
            BEFORE UPDATE OF json_storage ON users
            BEGIN
                SELECT RAISE(ABORT, 'injected bundle user storage failure');
            END;
            "#,
        )
        .unwrap();

    let error = import_bundle(fixture.state(), fixture.root(), &bundle, &user).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected bundle user storage failure")
    );
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row("SELECT global FROM configs WHERE id = 1", [], |row| row
            .get::<_, String>(
            0
        ))
        .unwrap(),
        "global {}"
    );
    assert_eq!(
        conn.query_row(
            "SELECT json_storage FROM users WHERE id = ?1",
            params![user.id],
            |row| { row.get::<_, String>(0) }
        )
        .unwrap(),
        user.json_storage
    );
}

#[test]
fn exported_bundle_larger_than_default_request_limit_round_trips_through_import_endpoint() {
    let source = FreshProductState::new("large-bundle-source");
    source.seed_selected_resources();
    let source_user = insert_fixture_user(&source, r#"{"mode":"rule"}"#);
    let large_info = "x".repeat(MAX_BODY_BYTES + (64 << 10));
    source
        .connection()
        .execute(
            "INSERT INTO subscriptions(
                id, updated_at, link, cron_exp, cron_enable, status, info, use_proxy
             ) VALUES(1, 'now', 'https://example.invalid/subscription', ?1, 1, 'fetched', ?2, 0)",
            params![DEFAULT_SUBSCRIPTION_CRON_EXP, large_info],
        )
        .unwrap();
    let bundle = export_bundle(source.state(), &source_user).unwrap();
    let body = serde_json::to_vec(&bundle).unwrap();
    assert!(body.len() > MAX_BODY_BYTES);
    assert!(body.len() < MAX_BUNDLE_BODY_BYTES);

    let request = read_request_bytes(json_put_request(DAE_BUNDLE_IMPORT_PATH, &body)).unwrap();
    assert_eq!(request.body.len(), body.len());
    let parsed = json_body(&request).unwrap();

    let generic_error =
        read_request_bytes(json_put_request("/api/user/me/storage", &body)).unwrap_err();
    assert!(generic_error.to_string().contains("body is too large"));

    let target = FreshProductState::new("large-bundle-target");
    let target_user = insert_fixture_user(&target, r#"{"mode":"direct"}"#);
    let outcome = import_bundle(target.state(), target.root(), &parsed, &target_user).unwrap();
    assert!(outcome.imported);
    assert_eq!(
        target
            .connection()
            .query_row(
                "SELECT LENGTH(info) FROM subscriptions WHERE id = 1",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
        i64::try_from(large_info.len()).unwrap()
    );
}

#[test]
fn bundle_null_defaults_clear_previous_user_defaults() {
    let fixture = FreshProductState::new("bundle-null-defaults");
    fixture.seed_selected_resources();
    let user = insert_fixture_user(
        &fixture,
        r#"{"mode":"rule","defaultConfigID":"8","defaultDNSID":"9","defaultRoutingID":"10","defaultGroupID":"11"}"#,
    );
    let mut bundle = export_bundle(fixture.state(), &user).unwrap();
    bundle["defaults"] = json!({
        "configId": null,
        "dnsId": null,
        "routingId": null,
        "groupId": null,
    });

    import_bundle(fixture.state(), fixture.root(), &bundle, &user).unwrap();

    let storage: String = fixture
        .connection()
        .query_row(
            "SELECT json_storage FROM users WHERE id = ?1",
            params![user.id],
            |row| row.get(0),
        )
        .unwrap();
    let storage: Value = serde_json::from_str(&storage).unwrap();
    for key in [
        "defaultConfigID",
        "defaultDNSID",
        "defaultRoutingID",
        "defaultGroupID",
    ] {
        assert_eq!(storage[key], json!(""));
    }
}

#[test]
fn bundle_group_sort_state_round_trips_as_structured_data() {
    let source = FreshProductState::new("bundle-group-sort-source");
    source.seed_selected_resources();
    let group_sort_state = json!({
        "version": 1,
        "groupSortableKeys": ["2", "1"],
        "groupSortOrders": {
            "1": {"nodes": ["9", "8"], "subscriptions": ["3"]}
        }
    });
    let source_storage = json!({
        "mode": "rule",
        "groupSortStateV1": group_sort_state.to_string(),
    })
    .to_string();
    let source_user = insert_fixture_user(&source, &source_storage);

    let bundle = export_bundle(source.state(), &source_user).unwrap();
    assert_eq!(bundle["groupSortState"], group_sort_state);

    let target = FreshProductState::new("bundle-group-sort-target");
    let target_user = insert_fixture_user(
        &target,
        &json!({"groupSortStateV1": "stale-browser-order"}).to_string(),
    );
    import_bundle(target.state(), target.root(), &bundle, &target_user).unwrap();

    let storage: String = target
        .connection()
        .query_row(
            "SELECT json_storage FROM users WHERE id = ?1",
            params![target_user.id],
            |row| row.get(0),
        )
        .unwrap();
    let storage: Value = serde_json::from_str(&storage).unwrap();
    let restored: Value =
        serde_json::from_str(storage["groupSortStateV1"].as_str().unwrap()).unwrap();
    assert_eq!(restored, group_sort_state);
}

#[test]
fn legacy_bundle_without_group_sort_state_preserves_existing_server_order() {
    let source = FreshProductState::new("legacy-bundle-group-sort-source");
    source.seed_selected_resources();
    let source_user = insert_fixture_user(&source, r#"{"mode":"rule"}"#);
    let mut bundle = export_bundle(source.state(), &source_user).unwrap();
    bundle.as_object_mut().unwrap().remove("groupSortState");

    let target = FreshProductState::new("legacy-bundle-group-sort-target");
    let existing = json!({
        "version": 1,
        "groupSortableKeys": ["1"],
        "groupSortOrders": {}
    });
    let target_user = insert_fixture_user(
        &target,
        &json!({"groupSortStateV1": existing.to_string()}).to_string(),
    );

    import_bundle(target.state(), target.root(), &bundle, &target_user).unwrap();

    let storage: String = target
        .connection()
        .query_row(
            "SELECT json_storage FROM users WHERE id = ?1",
            params![target_user.id],
            |row| row.get(0),
        )
        .unwrap();
    let storage: Value = serde_json::from_str(&storage).unwrap();
    assert_eq!(storage["groupSortStateV1"], json!(existing.to_string()));
}

#[test]
fn malformed_bundle_group_sort_state_is_rejected_before_import() {
    let fixture = FreshProductState::new("bundle-invalid-group-sort-state");
    fixture.seed_selected_resources();
    let user = insert_fixture_user(&fixture, r#"{"mode":"rule"}"#);
    let mut bundle = export_bundle(fixture.state(), &user).unwrap();
    bundle["groupSortState"] = json!({
        "version": 1,
        "groupSortableKeys": [1],
        "groupSortOrders": {}
    });

    let error = import_bundle(fixture.state(), fixture.root(), &bundle, &user).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("groupSortState.groupSortableKeys values must be strings")
    );
}
