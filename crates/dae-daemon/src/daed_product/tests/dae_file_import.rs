use super::support::FreshProductState;
use super::*;

fn fixture_user(fixture: &FreshProductState) -> UserRecord {
    let conn = fixture.connection();
    conn.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage) VALUES(?1, ?2, ?3, ?4)",
        params!["fixture", "hash", "secret", r#"{"mode":"rule"}"#],
    )
    .unwrap();
    load_user_by_id(fixture.state(), conn.last_insert_rowid())
        .unwrap()
        .unwrap()
}

fn complete_dae_file(first_port: u16, second_port: u16, first_tag: &str) -> String {
    format!(
        r#"
global {{
    log_level: 'debug'
    fallback_resolver: '127.0.0.1:53'
}}
node {{
    {first_tag}: 'socks5://127.0.0.1:{first_port}'
    second: 'socks5://127.0.0.1:{second_port}'
}}
group {{
    proxy {{
        filter: name({first_tag}, second)
        policy: min
    }}
}}
routing {{
    fallback: proxy
}}
dns {{
    upstream {{
        local: 'udp://127.0.0.1:53'
    }}
    routing {{
        request {{ fallback: local }}
        response {{ fallback: local }}
    }}
}}
"#
    )
}

#[test]
fn full_dae_file_import_materializes_authoritative_resources() {
    for database_index in 0..2 {
        let fixture = FreshProductState::new(&format!("dae-file-import-{database_index}"));
        fixture.seed_selected_resources();
        let user = fixture_user(&fixture);
        let first_port = 20_000 + fastrand::u16(0..10_000);
        let second_port = 30_000 + fastrand::u16(0..10_000);
        let content = complete_dae_file(first_port, second_port, "first");

        let outcome = import_dae_file(fixture.state(), &content, "fixture", &user).unwrap();
        assert_eq!(outcome.node_ids.len(), 2);
        assert_eq!(outcome.group_ids.len(), 1);
        let conn = fixture.connection();
        assert_eq!(
            selected_id(&conn, SectionKind::Config).unwrap(),
            Some(outcome.config_id)
        );
        assert_eq!(
            selected_id(&conn, SectionKind::Dns).unwrap(),
            Some(outcome.dns_id)
        );
        assert_eq!(
            selected_id(&conn, SectionKind::Routing).unwrap(),
            Some(outcome.routing_id)
        );
        let stored_global: String = conn
            .query_row(
                "SELECT global FROM configs WHERE id = ?1",
                params![outcome.config_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored_global.contains("global {"));
        assert!(!stored_global.contains("node {"));
        assert!(!stored_global.contains("routing {"));
        drop(conn);

        let materialized = materialize_runtime(fixture.state(), None, true).unwrap();
        let generated = materialized["content"].as_str().unwrap();
        let config = build_runtime_config_from_content(generated).unwrap();
        assert_eq!(config.node.len(), 2);
        assert_eq!(config.group.len(), 1);
        assert_eq!(config.group[0].name, "proxy");
        assert!(generated.contains(&first_port.to_string()));
        assert!(generated.contains(&second_port.to_string()));

        let reimported = import_dae_file(fixture.state(), generated, "roundtrip", &user).unwrap();
        assert_eq!(reimported.node_ids, outcome.node_ids);
        assert_eq!(reimported.group_ids, outcome.group_ids);

        let renamed = complete_dae_file(first_port, second_port, "renamed-first");
        let renamed_outcome = import_dae_file(fixture.state(), &renamed, "fixture", &user).unwrap();
        assert_eq!(renamed_outcome.node_ids[0], outcome.node_ids[0]);
        assert_eq!(renamed_outcome.node_ids[1], outcome.node_ids[1]);
        assert_eq!(renamed_outcome.group_ids, outcome.group_ids);
    }
}

#[test]
fn commit_time_identity_conflict_rolls_back_every_staged_resource() {
    let fixture = FreshProductState::new("dae-file-import-transaction");
    fixture.seed_selected_resources();
    let user = fixture_user(&fixture);
    let conn = fixture.connection();
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag) VALUES(1, 'now', 'https://subscription.invalid/list', 'ok', '', 'fixture-sub')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, ?5, 1)",
        params![
            "socks5://127.0.0.1:19000",
            "subscription-first",
            "127.0.0.1:19000",
            "socks5",
            "first",
        ],
    )
    .unwrap();
    drop(conn);
    let content = complete_dae_file(19_001, 19_002, "first");

    let error = import_dae_file(fixture.state(), &content, "must-rollback", &user).unwrap_err();
    assert!(error.to_string().contains("subscription-managed node"));
    let conn = fixture.connection();
    assert_eq!(selected_id(&conn, SectionKind::Config).unwrap(), Some(1));
    assert_eq!(selected_id(&conn, SectionKind::Dns).unwrap(), Some(1));
    assert_eq!(selected_id(&conn, SectionKind::Routing).unwrap(), Some(1));
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM configs WHERE name LIKE 'must-rollback-%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM groups", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn invalid_full_file_import_leaves_selected_resources_and_defaults_untouched() {
    let fixture = FreshProductState::new("dae-file-import-rollback");
    fixture.seed_selected_resources();
    let user = fixture_user(&fixture);
    let before_storage = user.json_storage.clone();
    let invalid = r#"
global {}
global { log_level: 'debug' }
routing { fallback: direct }
"#;

    let error = import_dae_file(fixture.state(), invalid, "invalid", &user).unwrap_err();
    assert!(error.to_string().contains("duplicate top-level section"));
    let conn = fixture.connection();
    assert_eq!(selected_id(&conn, SectionKind::Config).unwrap(), Some(1));
    assert_eq!(selected_id(&conn, SectionKind::Dns).unwrap(), Some(1));
    assert_eq!(selected_id(&conn, SectionKind::Routing).unwrap(), Some(1));
    assert_eq!(
        conn.query_row(
            "SELECT json_storage FROM users WHERE id = ?1",
            params![user.id],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        before_storage
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn full_file_import_rejects_group_filters_that_cannot_round_trip() {
    let fixture = FreshProductState::new("dae-file-import-filter");
    fixture.seed_selected_resources();
    let user = fixture_user(&fixture);
    let content = r#"
global { fallback_resolver: '127.0.0.1:53' }
node { first: 'socks5://127.0.0.1:1080' }
group {
    proxy {
        filter: name(keyword(first))
        policy: fixed
    }
}
routing { fallback: proxy }
"#;

    assert!(import_dae_file(fixture.state(), content, "filter", &user).is_err());
    assert_eq!(
        fixture
            .connection()
            .query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn dae_config_file_api_reports_the_resources_it_imported() {
    let fixture = FreshProductState::new("dae-file-import-api");
    fixture.seed_selected_resources();
    let user = fixture_user(&fixture);
    let app = AppState {
        config_dir: fixture.root().to_path_buf(),
        state: fixture.state().to_path_buf(),
        web_root: fixture.root().to_path_buf(),
        api_only: true,
        control_socket: fixture.root().join("control.sock"),
        runtime: Arc::new(ProductRuntimeManager::new()),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        auth_runtime: product_test_auth_runtime(),
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
    };
    let content = complete_dae_file(18_080, 18_081, "first");
    let request = HttpRequest {
        method: "PUT".to_owned(),
        path: "/api/user/me/dae-config-file".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({
            "namePrefix": "api-fixture",
            "content": content,
        }))
        .unwrap(),
    };

    let response = api_put_dae_config_file(&app, &request, &user);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["imported"], json!(true));
    assert_eq!(body["resources"]["nodeIds"].as_array().unwrap().len(), 2);
    assert_eq!(body["resources"]["groupIds"].as_array().unwrap().len(), 1);
    assert_eq!(body["warnings"], json!([]));

    let preview_request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/user/me/dae-config-file/preview".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({
            "namePrefix": "preview-fixture",
            "content": complete_dae_file(18_082, 18_083, "preview-first"),
        }))
        .unwrap(),
    };
    let preview = api_preview_dae_config_file(&app, &preview_request, &user);
    assert_eq!(preview.status, 200);
    let preview_body: Value = serde_json::from_slice(&preview.body).unwrap();
    assert_eq!(preview_body["bundle"]["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(
        preview_body["bundle"]["groups"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        preview_body["bundle"]["configs"][0]["name"],
        "preview-fixture-global"
    );

    let invalid_preview = HttpRequest {
        body: serde_json::to_vec(&json!({
            "content": "global {}\nglobal {}\nrouting { fallback: direct }"
        }))
        .unwrap(),
        ..preview_request
    };
    assert_eq!(
        api_preview_dae_config_file(&app, &invalid_preview, &user).status,
        400
    );
}
