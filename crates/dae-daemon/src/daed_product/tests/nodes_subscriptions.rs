use super::*;

#[test]
pub(crate) fn subscription_http_body_limit_is_enforced_without_preallocating_limit() {
    let body = b"vmess://small-node#ok\n";
    let mut response = Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"[..]);
    response.extend_from_slice(body);
    let parsed = http_response_body_with_limit(&response, 1024).unwrap();
    assert_eq!(parsed.as_bytes(), body);

    let mut oversized = Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"[..]);
    oversized.extend(std::iter::repeat_n(b'a', 17));
    let err = http_response_body_with_limit(&oversized, 16).unwrap_err();
    assert!(
        err.to_string()
            .contains("subscription response body exceeds 16 bytes"),
        "{err}"
    );
}

#[test]
pub(crate) fn subscription_chunked_body_limit_is_cumulative_and_checks_crlf() {
    let decoded = decode_chunked_body(b"4\r\nnode\r\n2\r\nok\r\n0\r\n\r\n").unwrap();
    assert_eq!(decoded, b"nodeok");

    let err =
        decode_chunked_body_with_limit(b"8\r\n12345678\r\n1\r\n9\r\n0\r\n\r\n", 8).unwrap_err();
    assert!(
        err.to_string()
            .contains("decoded subscription body exceeds 8 bytes"),
        "{err}"
    );

    let err = decode_chunked_body_with_limit(b"4\r\nnodeXX0\r\n\r\n", 16).unwrap_err();
    assert!(
        err.to_string()
            .contains("chunked body chunk missing trailing CRLF"),
        "{err}"
    );
}

#[test]
pub(crate) fn subscription_response_reader_stops_after_configured_limit() {
    let mut reader = io::Cursor::new(vec![b'a'; 128 * 1024 + 17]);
    let err = read_subscription_http_response_with_limit(&mut reader, 16).unwrap_err();
    assert!(
        err.to_string().contains("subscription response exceeds"),
        "{err}"
    );
}

#[test]
pub(crate) fn subscription_content_supports_sip008_plain_and_base64_lists() {
    let sip008 = r#"{
        "version": 1,
        "servers": [{
            "remarks": "sip-node",
            "server": "example.com",
            "server_port": 8388,
            "method": "aes-128-gcm",
            "password": "secret",
            "plugin": "v2ray-plugin",
            "plugin_opts": "tls;host=front.example.com"
        }]
    }"#;
    let sip008_links = subscription_links_from_content(sip008);
    assert_eq!(sip008_links.len(), 1);
    assert!(sip008_links[0].starts_with("ss://"));
    assert!(sip008_links[0].contains("example.com:8388"));
    assert!(sip008_links[0].contains("sip-node"));
    assert!(sip008_links[0].contains("plugin="));

    let plain = "vless://uuid@example.com:443#plain\n# comment\n";
    assert_eq!(
        subscription_links_from_content(plain),
        vec!["vless://uuid@example.com:443#plain".to_owned()]
    );

    let encoded = STANDARD.encode("vmess://eyJwcyI6ImJhc2U2NCIsImFkZCI6ImV4YW1wbGUuY29tIn0=\n");
    assert_eq!(
        subscription_links_from_content(&encoded),
        vec!["vmess://eyJwcyI6ImJhc2U2NCIsImFkZCI6ImV4YW1wbGUuY29tIn0=".to_owned()]
    );
}

#[test]
pub(crate) fn hysteria2_mport_node_link_is_stored_as_official_port_hopping_link() {
    let parsed = parse_node_link(
        "hysteria2://auth@pq.us1.globals-download.com:35000/?insecure=1&sni=www.apple.com&mport=35000-39000#pq",
        None,
    );

    assert_eq!(parsed.protocol, "hysteria2");
    assert_eq!(parsed.address, "pq.us1.globals-download.com:35000-39000");
    assert_eq!(
        parsed.normalized_link.as_deref(),
        Some(
            "hysteria2://auth@pq.us1.globals-download.com:35000-39000?insecure=1&sni=www.apple.com#pq"
        )
    );
}

#[test]
pub(crate) fn subscription_file_and_http_file_fallback_follow_config_dir_scope() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let relative_dir = dir.join("relative").join("path");
    fs::create_dir_all(&relative_dir).unwrap();
    let file_path = relative_dir.join("mysub.sub");
    fs::write(
        &file_path,
        b"@ignored instruction\nvless://uuid@example.com:443#file\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let content = fetch_subscription_content(&dir, None, "file://relative/path/mysub.sub").unwrap();
    assert_eq!(content, "vless://uuid@example.com:443#file");
    let escaped = fetch_subscription_content(&dir, None, "file:///tmp/mysub.sub")
        .unwrap_err()
        .to_string();
    assert!(escaped.contains("not support absolute path"), "{escaped}");

    let persist_dir = dir.join("persist.d");
    fs::create_dir_all(&persist_dir).unwrap();
    let cached = persist_dir.join("cached.sub");
    fs::write(&cached, b"vless://uuid@example.com:443#cached\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cached, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let content =
        fetch_subscription_content(&dir, Some("cached"), "http-file://127.0.0.1:9/sub").unwrap();
    assert_eq!(content, "vless://uuid@example.com:443#cached");

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_schema_adds_use_proxy_to_existing_tables() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    if let Some(parent) = state.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let conn = Connection::open(&state).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            updated_at TEXT NOT NULL DEFAULT '',
            link TEXT NOT NULL,
            cron_exp TEXT DEFAULT '10 */6 * * *',
            cron_enable INTEGER DEFAULT 1,
            status TEXT NOT NULL DEFAULT '',
            info TEXT NOT NULL DEFAULT '',
            tag TEXT UNIQUE
        );
        INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
        VALUES(7, 'now', 'https://subscription.invalid/list', 'imported', '', 'legacy');
        "#,
    )
    .unwrap();
    drop(conn);

    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let has_use_proxy = {
        let mut stmt = conn.prepare("PRAGMA table_info(subscriptions)").unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(1)).unwrap();
        rows.map(|row| row.unwrap())
            .any(|column| column == "use_proxy")
    };
    assert!(has_use_proxy);
    let use_proxy: i64 = conn
        .query_row(
            "SELECT use_proxy FROM subscriptions WHERE id = 7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(use_proxy, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn create_subscription_persists_use_proxy_flag() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let subscription_dir = dir.join("sub");
    fs::create_dir_all(&subscription_dir).unwrap();
    let file_path = subscription_dir.join("test.sub");
    fs::write(&file_path, b"vless://uuid@example.com:443#proxied\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/subscriptions".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"link":"file://sub/test.sub","tag":"proxied","useProxy":true}"#.to_vec(),
    };

    let response = create_subscription(&state, &dir, &request);
    assert_eq!(response.status, 201);
    let subscriptions = list_subscriptions_value(&state, false).unwrap();
    assert_eq!(subscriptions["items"][0]["useProxy"], json!(true));
    let conn = open_state_connection(&state).unwrap();
    let use_proxy: i64 = conn
        .query_row(
            "SELECT use_proxy FROM subscriptions WHERE tag = 'proxied'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(use_proxy, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn delete_subscription_removes_dependent_node_state() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let subscription_id = 7_i64;
    let group_id = 9_i64;
    let subscription_tag = "subscription-under-test";
    let group_name = "resource_group";
    let removed_node_id = 51_i64;
    let retained_node_id = 52_i64;
    let removed_node_name = "subscription-node";
    let retained_node_name = "manual-node";
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            subscription_id,
            "2026-06-26T00:00:00Z",
            "https://subscription.invalid/list",
            "fetched",
            "",
            subscription_tag
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(?1, ?2, ?3, 1)",
        params![group_id, group_name, "random"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_subscriptions(group_id, subscription_id) VALUES(?1, ?2)",
        params![group_id, subscription_id],
    )
    .unwrap();
    insert_config_node(
        &conn,
        removed_node_id,
        removed_node_name,
        "http://127.0.0.4:9/subscription#subscription-node",
        Some(subscription_id),
    );
    insert_config_node(
        &conn,
        retained_node_id,
        retained_node_name,
        "http://127.0.0.5:9/manual#manual-node",
        None,
    );
    for node_id in [removed_node_id, retained_node_id] {
        conn.execute(
            "INSERT INTO group_nodes(group_id, node_id) VALUES(?1, ?2)",
            params![group_id, node_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
                 VALUES(?1, 17, 1, ?2, NULL, ?2)",
            params![node_id, "2026-06-26T00:00:00Z"],
        )
        .unwrap();
    }
    drop(conn);

    let removed = delete_subscription(&state, subscription_id).unwrap();
    assert_eq!(removed, 1);
    let conn = open_state_connection(&state).unwrap();
    let subscription_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM subscriptions WHERE id = ?1",
            params![subscription_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(subscription_rows, 0);
    let removed_node_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM nodes WHERE id = ?1",
            params![removed_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(removed_node_rows, 0);
    let removed_group_nodes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_nodes WHERE node_id = ?1",
            params![removed_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(removed_group_nodes, 0);
    let removed_latency_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![removed_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(removed_latency_rows, 0);
    let group_subscription_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_subscriptions WHERE subscription_id = ?1",
            params![subscription_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(group_subscription_rows, 0);
    let retained_node_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM nodes WHERE id = ?1",
            params![retained_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_node_rows, 1);
    let retained_group_nodes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_nodes WHERE node_id = ?1",
            params![retained_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_group_nodes, 1);
    let retained_latency_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![retained_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_latency_rows, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_vmess_metadata_uses_protocol_parser() {
    let payload = STANDARD.encode(
        r#"{"v":"2","ps":"vmess-name","add":"vmess.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls"}"#,
    );
    let link = format!("vmess://{payload}");
    let parsed = parse_node_link(&link, None);
    assert_eq!(parsed.protocol, "vmess");
    assert_eq!(parsed.name, "vmess-name");
    assert_eq!(parsed.address, "vmess.example.com:443");
}

#[test]
pub(crate) fn node_labels_decode_uri_fragments_without_special_casing_nodes() {
    let content = test_config_with_node(
        "resource_node",
        "http://127.0.0.1:9/resource#%5Blabel%5Dresource-node",
        "egress",
    );
    let link = node_link_from_config(&content, "resource_node");
    let parsed = parse_node_link(&link, None);
    assert_eq!(parsed.name, "[label]resource-node");
    assert_eq!(
        decode_node_label("%5Blabel%5Dresource-node"),
        "[label]resource-node"
    );
    assert_eq!(decode_node_label("literal+plus"), "literal+plus");

    let node = json!({
        "id": 1,
        "name": parsed.name,
        "link": link
    });
    assert_eq!(runtime_node_tag(&node), "[label]resource-node");
}

#[test]
pub(crate) fn update_node_clears_latency_when_link_identity_changes() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let node_id = 41_i64;
    let node_name = "editable-node";
    let initial_link = "http://127.0.0.1:9/initial#editable-node";
    let next_link = "http://127.0.0.2:9/next#editable-node";
    insert_config_node(&conn, node_id, node_name, initial_link, None);
    conn.execute(
        "INSERT INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
             VALUES(?1, 23, 1, ?2, NULL, ?2)",
        params![node_id, "2026-06-26T00:00:00Z"],
    )
    .unwrap();
    drop(conn);

    let request = HttpRequest {
        method: "PUT".to_owned(),
        path: format!("/api/nodes/{node_id}"),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({ "link": next_link })).unwrap(),
    };
    let response = update_node(&state, &request, node_id);
    assert_eq!(response.status, 200);

    let conn = open_state_connection(&state).unwrap();
    let stored_link: String = conn
        .query_row(
            "SELECT link FROM nodes WHERE id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_link, next_link);
    let latency_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(latency_rows, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn update_node_preserves_latency_for_label_only_changes() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let node_id = 42_i64;
    let node_name = "label-node";
    let link = "http://127.0.0.3:9/resource#label-node";
    let next_tag = "renamed-label-node";
    insert_config_node(&conn, node_id, node_name, link, None);
    conn.execute(
        "INSERT INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
             VALUES(?1, 31, 1, ?2, NULL, ?2)",
        params![node_id, "2026-06-26T00:00:00Z"],
    )
    .unwrap();
    drop(conn);

    let tag_only_request = HttpRequest {
        method: "PUT".to_owned(),
        path: format!("/api/nodes/{node_id}"),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({ "tag": next_tag })).unwrap(),
    };
    let response = update_node(&state, &tag_only_request, node_id);
    assert_eq!(response.status, 200);
    let conn = open_state_connection(&state).unwrap();
    let latency_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(latency_rows, 1);
    let stored_tag: String = conn
        .query_row(
            "SELECT tag FROM nodes WHERE id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_tag, next_tag);
    drop(conn);

    let link_and_tag_request = HttpRequest {
        method: "PUT".to_owned(),
        path: format!("/api/nodes/{node_id}"),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({ "link": link, "tag": node_name })).unwrap(),
    };
    let response = update_node(&state, &link_and_tag_request, node_id);
    assert_eq!(response.status, 200);
    let conn = open_state_connection(&state).unwrap();
    let latency_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(latency_rows, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn create_group_rejects_unsupported_policy_before_persisting() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/groups".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"name":"bad","policy":"fastest","policyParams":[]}"#.to_vec(),
    };

    let response = create_group(&state, &request);
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("unsupported group policy"),
        "{body}"
    );
    let conn = open_state_connection(&state).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM groups", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn update_group_rejects_unsupported_policy_without_mutating_existing_group() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let group_name = "policy_guard_group";
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, ?1, ?2, 3)",
        params![group_name, GROUP_POLICY_FIXED],
    )
    .unwrap();
    let request = HttpRequest {
        method: "PUT".to_owned(),
        path: "/api/groups/9".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"policy":"fastest","policyParams":[]}"#.to_vec(),
    };

    let response = update_group(&state, &request, 9);
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("unsupported group policy"),
        "{body}"
    );
    let (policy, version): (String, i64) = conn
        .query_row(
            "SELECT policy, version FROM groups WHERE id = 9",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(policy, GROUP_POLICY_FIXED);
    assert_eq!(version, 3);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn create_group_rejects_fixed_group_with_multiple_nodes_without_persisting() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let group_name = "single_node_group";
    insert_config_node(&conn, 1, "node-a", "http://127.0.0.1:9/node-a#node-a", None);
    insert_config_node(&conn, 2, "node-b", "http://127.0.0.2:9/node-b#node-b", None);
    drop(conn);
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/groups".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({
            "name": group_name,
            "policy": GROUP_POLICY_FIXED,
            "nodeIds": [1, 2],
            "policyParams": []
        }))
        .unwrap(),
    };

    let response = create_group(&state, &request);
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("fixed group can match only one node"),
        "{body}"
    );
    let conn = open_state_connection(&state).unwrap();
    let group_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM groups WHERE name = ?1",
            params![group_name],
            |row| row.get(0),
        )
        .unwrap();
    let binding_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM group_nodes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(group_count, 0);
    assert_eq!(binding_count, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn update_group_nodes_rejects_second_node_for_fixed_group_without_mutating() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let group_name = "node_binding_group";
    insert_config_node(&conn, 1, "node-a", "http://127.0.0.1:9/node-a#node-a", None);
    insert_config_node(&conn, 2, "node-b", "http://127.0.0.2:9/node-b#node-b", None);
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, ?1, ?2, 3)",
        params![group_name, GROUP_POLICY_FIXED],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, 1)",
        [],
    )
    .unwrap();
    drop(conn);
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/groups/9/nodes".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"nodeIds":[2]}"#.to_vec(),
    };

    let response = update_group_nodes(&state, &request, 9, true);
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("fixed group can match only one node"),
        "{body}"
    );
    let conn = open_state_connection(&state).unwrap();
    let node_ids = conn
        .prepare("SELECT node_id FROM group_nodes WHERE group_id = 9 ORDER BY node_id")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let version: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(node_ids, vec![1]);
    assert_eq!(version, 3);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn update_group_subscriptions_rejects_multi_match_for_fixed_group_without_mutating() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let group_name = "subscription_binding_group";
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, ?1, ?2, 3)",
        params![group_name, GROUP_POLICY_FIXED],
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &[
            "http://127.0.0.1:9/candidate-a#candidate-a".to_owned(),
            "http://127.0.0.2:9/candidate-b#candidate-b".to_owned(),
        ],
    )
    .unwrap();
    drop(conn);
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/groups/9/subscriptions".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"subscriptionIds":[7]}"#.to_vec(),
    };

    let response = update_group_subscriptions(&state, &request, 9, true);
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("fixed group can match only one node"),
        "{body}"
    );
    let conn = open_state_connection(&state).unwrap();
    let binding_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_subscriptions WHERE group_id = 9",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(binding_count, 0);
    assert_eq!(version, 3);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn update_group_rejects_fixed_policy_for_multi_node_group_without_partial_update() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let group_name = "policy_update_group";
    insert_config_node(&conn, 1, "node-a", "http://127.0.0.1:9/node-a#node-a", None);
    insert_config_node(&conn, 2, "node-b", "http://127.0.0.2:9/node-b#node-b", None);
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, ?1, ?2, 2)",
        params![group_name, DEFAULT_PRODUCT_GROUP_POLICY],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, 2)",
        [],
    )
    .unwrap();
    drop(conn);
    let request = HttpRequest {
        method: "PUT".to_owned(),
        path: "/api/groups/9".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({
            "name": "renamed",
            "policy": GROUP_POLICY_FIXED,
            "policyParams": [{"key": "", "val": "1"}]
        }))
        .unwrap(),
    };

    let response = update_group(&state, &request, 9);
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("fixed group can match only one node"),
        "{body}"
    );
    let conn = open_state_connection(&state).unwrap();
    let (name, policy, version): (String, String, i64) = conn
        .query_row(
            "SELECT name, policy, version FROM groups WHERE id = 9",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let policy_param_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_policy_params WHERE group_id = 9",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(name, group_name);
    assert_eq!(policy, DEFAULT_PRODUCT_GROUP_POLICY);
    assert_eq!(version, 2);
    assert_eq!(policy_param_count, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn node_lists_keep_manual_subscription_and_runtime_scopes_separate() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
             VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a')",
        [],
    )
    .unwrap();
    insert_config_node(
        &conn,
        1,
        "manual_node",
        "http://127.0.0.1:9/manual-node#manual-node",
        None,
    );
    replace_subscription_nodes(
        &conn,
        7,
        &["http://127.0.0.1:9/subscription-node#subscription-node".to_owned()],
    )
    .unwrap();

    let manual = list_nodes_value(&state, None).unwrap();
    assert_eq!(manual["totalCount"], json!(1));
    assert_eq!(manual["items"][0]["name"], json!("manual_node"));

    let subscription = list_nodes_value(&state, Some(7)).unwrap();
    assert_eq!(subscription["totalCount"], json!(1));
    assert_eq!(subscription["items"][0]["name"], json!("subscription-node"));
    assert_eq!(
        subscription["items"][0]["runtimeTag"],
        json!("subscription-node")
    );

    let runtime = list_all_nodes_value(&state).unwrap();
    assert_eq!(runtime["totalCount"], json!(2));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_refresh_marks_runtime_modified_for_unbound_node_changes() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    fs::create_dir_all(dir.join("subs")).unwrap();
    let subscription_file = dir.join("subs/list.txt");
    fs::write(
        &subscription_file,
        "vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443?security=tls&type=tcp&sni=example.com#DMIT-HKT1\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&subscription_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: direct }', 1, 1);
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'file://subs/list.txt', 'pending', '', 'sub-a');
        "#,
    )
    .unwrap();
    drop(conn);
    materialize_runtime(&state, None, false).unwrap();
    let conn = open_state_connection(&state).unwrap();
    assert!(!runtime_modified(&conn, true).unwrap());
    drop(conn);

    let report = refresh_subscription_from_remote(&state, &dir, 7).unwrap();
    assert_eq!(report["runtimeInputChanged"], json!(true));
    let conn = open_state_connection(&state).unwrap();
    assert!(runtime_modified(&conn, true).unwrap());
    drop(conn);

    materialize_runtime(&state, None, false).unwrap();
    let conn = open_state_connection(&state).unwrap();
    assert!(!runtime_modified(&conn, true).unwrap());
    drop(conn);
    let report = refresh_subscription_from_remote(&state, &dir, 7).unwrap();
    assert_eq!(report["runtimeInputChanged"], json!(false));
    let conn = open_state_connection(&state).unwrap();
    assert!(!runtime_modified(&conn, true).unwrap());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn group_subscription_bindings_apply_name_regex_to_matched_nodes() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'resource_group', 'random', 1);
            INSERT INTO group_subscriptions(group_id, subscription_id, name_filter_regex)
                VALUES(9, 7, 'candidate-alpha');
            "#,
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &[
            "http://127.0.0.1:9/candidate-alpha#candidate-alpha".to_owned(),
            "http://127.0.0.1:9/candidate-beta#candidate-beta".to_owned(),
        ],
    )
    .unwrap();

    let group = get_group_value(&state, 9).unwrap().unwrap();
    assert_eq!(group["subscriptions"][0]["matchedCount"], json!(1));
    assert_eq!(
        group["subscriptions"][0]["matchedNodes"][0]["name"],
        json!("candidate-alpha")
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn group_summary_avoids_full_node_and_matched_node_expansion() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(8, 'now', 'https://subscription.invalid/selected', 'fetched', '', 'sub-b');
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'resource_group', 'random', 2);
            INSERT INTO group_subscriptions(group_id, subscription_id, name_filter_regex)
                VALUES(9, 7, 'candidate');
            INSERT INTO group_subscriptions(group_id, subscription_id, name_filter_regex)
                VALUES(9, 8, 'selected');
            INSERT INTO group_policy_params(group_id, key, value)
                VALUES(9, 'filter', 'candidate');
            "#,
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &[
            "http://127.0.0.1:9/candidate-alpha#candidate-alpha".to_owned(),
            "http://127.0.0.1:9/candidate-beta#candidate-beta".to_owned(),
            "http://127.0.0.1:9/candidate-gamma#candidate-gamma".to_owned(),
            "http://127.0.0.1:9/candidate-delta#candidate-delta".to_owned(),
            "http://127.0.0.1:9/candidate-epsilon#candidate-epsilon".to_owned(),
            "http://127.0.0.1:9/candidate-zeta#candidate-zeta".to_owned(),
            "http://127.0.0.1:9/candidate-eta#candidate-eta".to_owned(),
            "http://127.0.0.1:9/ignored#ignored".to_owned(),
        ],
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        8,
        &[
            "http://127.0.0.1:9/selected-alpha#selected-alpha".to_owned(),
            "http://127.0.0.1:9/ignored-alpha#ignored-alpha".to_owned(),
            "http://127.0.0.1:9/selected-beta#selected-beta".to_owned(),
        ],
    )
    .unwrap();
    let selected_beta_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE name = ?1",
            params!["selected-beta"],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
         VALUES(?1, 7, 1, 'now', '7ms', 'now')",
        params![selected_beta_id],
    )
    .unwrap();
    for (index, name) in [
        "manual-alpha",
        "manual-beta",
        "manual-gamma",
        "manual-delta",
        "manual-epsilon",
        "manual-zeta",
    ]
    .into_iter()
    .enumerate()
    {
        let node_id = 30 + i64::try_from(index).unwrap();
        insert_config_node(
            &conn,
            node_id,
            name,
            &format!("http://127.0.0.1:9/{name}#{name}"),
            None,
        );
        conn.execute(
            "INSERT INTO group_nodes(group_id, node_id) VALUES(9, ?1)",
            params![node_id],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, ?1)",
        params![999_999_i64],
    )
    .unwrap();
    drop(conn);

    let summary = list_group_summaries_value(&state).unwrap();
    let group = &summary["items"][0];
    assert_eq!(group["id"], json!(9));
    assert_eq!(group["nodeCount"], json!(6));
    assert_eq!(group["subscriptionCount"], json!(2));
    assert_eq!(group["firstNode"]["name"], json!("manual-alpha"));
    assert_eq!(group["materializedCandidateCount"], json!(15));
    assert_eq!(group["currentNode"]["name"], json!("selected-beta"));
    assert_eq!(group["bestNode"]["name"], json!("selected-beta"));
    assert_eq!(
        group["sampleMaterializedCandidates"]
            .as_array()
            .map(Vec::len),
        Some(5),
        "{group}"
    );
    assert_eq!(
        group["sampleMaterializedCandidates"][0]["name"],
        json!("manual-alpha")
    );
    assert_eq!(
        group["sampleNodes"].as_array().map(Vec::len),
        Some(5),
        "{group}"
    );
    assert_eq!(group["sampleNodes"][0]["name"], json!("manual-alpha"));
    assert_eq!(group["sampleNodes"][4]["name"], json!("manual-epsilon"));
    assert_eq!(group["subscriptions"].as_array().map(Vec::len), Some(2));
    assert_eq!(group["subscriptions"][0]["matchedCount"], json!(7));
    assert_eq!(
        group["subscriptions"][0]["sampleMatchedNodes"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );
    assert_eq!(group["subscriptions"][1]["matchedCount"], json!(2));
    assert_eq!(
        group["subscriptions"][1]["sampleMatchedNodes"][0]["name"],
        json!("selected-alpha")
    );
    assert_eq!(
        group["subscriptions"][1]["sampleMatchedNodes"][1]["name"],
        json!("selected-beta")
    );
    assert!(group.get("nodes").is_none(), "{group}");
    assert!(group.get("firstSubscription").is_none(), "{group}");
    assert!(
        group["subscriptions"][0].get("matchedNodes").is_none(),
        "{group}"
    );

    let full = list_groups_value(&state).unwrap();
    assert_eq!(
        full["items"][0]["subscriptions"][0]["matchedNodes"][0]["name"],
        json!("candidate-alpha")
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn group_summary_merges_runtime_selector_snapshot() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let group_name = "runtime-group";
    let node_a_link = "http://127.0.0.1:9/node-a#node-a";
    let node_b_link = "http://127.0.0.2:9/node-b#node-b";
    insert_config_node(&conn, 1, "node-a", node_a_link, None);
    insert_config_node(&conn, 2, "node-b", node_b_link, None);
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, ?1, ?2, 1)",
        params![group_name, GROUP_POLICY_MIN],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, 1), (9, 2)",
        [],
    )
    .unwrap();
    drop(conn);

    let mut runtime_selectors = BTreeMap::new();
    runtime_selectors.insert(
        group_name.to_owned(),
        json!({
            "group": group_name,
            "policy": GROUP_POLICY_MIN,
            "selectedNodeTag": "node-b-renamed",
            "selectedLinkHash": runtime_link_hash(node_b_link),
            "selectedNetworkType": "tcp4",
            "selectedLatencyMs": 17,
            "selectionSource": "min-runtime-selector",
            "aliveCandidateCount": 2,
        }),
    );

    let summary =
        list_group_summaries_value_with_runtime_selection(&state, &runtime_selectors).unwrap();
    let group = &summary["items"][0];

    assert_eq!(group["runtimeSelectedNode"]["name"], json!("node-b"));
    assert_eq!(group["runtimeSelectedNetworkType"], json!("tcp4"));
    assert_eq!(group["runtimeSelectedLatencyMs"], json!(17));
    assert_eq!(
        group["runtimeSelectionSource"],
        json!("min-runtime-selector")
    );
    assert_eq!(group["runtimeAliveCandidateCount"], json!(2));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn state_schema_removes_dangling_group_and_latency_references() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO group_nodes(group_id, node_id) VALUES(777, 888);
            INSERT INTO group_subscriptions(group_id, subscription_id) VALUES(777, 999);
            INSERT INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
                VALUES(888, 10, 1, 'now', 'ok', 'now');
            "#,
    )
    .unwrap();
    drop(conn);

    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    for table in ["group_nodes", "group_subscriptions", "node_latency_results"] {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = conn.query_row(&sql, [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0, "{table}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_refresh_preserves_group_bound_nodes_by_unique_name() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'resource_group', 'random', 1);
            "#,
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &[
            "http://127.0.0.1:9/previous-resource#stable-resource".to_owned(),
            "http://127.0.0.1:9/removed-resource#removed-resource".to_owned(),
        ],
    )
    .unwrap();
    let stable_node_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7 AND name = 'stable-resource'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let removed_node_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7 AND name = 'removed-resource'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, ?1)",
        params![stable_node_id],
    )
    .unwrap();

    let report = replace_subscription_nodes(
        &conn,
        7,
        &[
            "http://127.0.0.1:9/updated-resource#stable-resource".to_owned(),
            "http://127.0.0.1:9/other-resource#other-resource".to_owned(),
        ],
    )
    .unwrap();
    assert_eq!(report.len(), 2);
    let kept_link: String = conn
        .query_row(
            "SELECT link FROM nodes WHERE id = ?1",
            params![stable_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        kept_link,
        "http://127.0.0.1:9/updated-resource#stable-resource"
    );
    let group_binding_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_nodes WHERE group_id = 9 AND node_id = ?1",
            params![stable_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(group_binding_count, 1);
    let removed_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM nodes WHERE id = ?1",
            params![removed_node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(removed_count, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_refresh_updates_unbound_unique_node_by_name() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
             VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a')",
        [],
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &["http://127.0.0.1:9/old-endpoint#stable-resource".to_owned()],
    )
    .unwrap();
    let node_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7 AND name = 'stable-resource'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
             VALUES(?1, 37, 1, '2026-06-19T00:00:00Z', NULL, '2026-06-19T00:00:00Z')",
        params![node_id],
    )
    .unwrap();

    let report = replace_subscription_nodes(
        &conn,
        7,
        &["http://127.0.0.2:9/new-endpoint#stable-resource".to_owned()],
    )
    .unwrap();
    assert_eq!(report.len(), 1);
    assert_eq!(report[0]["node"]["id"], json!(node_id));
    let (kept_id, kept_link, kept_address): (i64, String, String) = conn
        .query_row(
            "SELECT id, link, address FROM nodes WHERE subscription_id = 7 AND name = 'stable-resource'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(kept_id, node_id);
    assert_eq!(kept_link, "http://127.0.0.2:9/new-endpoint#stable-resource");
    assert_eq!(kept_address, "127.0.0.2");
    let latency_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(latency_rows, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_refresh_renames_unbound_node_by_display_identity() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
             VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a')",
        [],
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &["vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443?security=tls&type=tcp&sni=example.com#DMIT-HKT1".to_owned()],
    )
    .unwrap();
    let node_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7 AND name = 'DMIT-HKT1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
             VALUES(?1, 37, 1, '2026-06-19T00:00:00Z', NULL, '2026-06-19T00:00:00Z')",
        params![node_id],
    )
    .unwrap();

    let report = replace_subscription_nodes(
        &conn,
        7,
        &["vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443?security=tls&type=tcp&sni=example.com#DMIT-HK-T1".to_owned()],
    )
    .unwrap();
    assert_eq!(report.len(), 1);
    assert_eq!(report[0]["node"]["id"], json!(node_id));
    let (kept_id, kept_name, kept_link): (i64, String, String) = conn
        .query_row(
            "SELECT id, name, link FROM nodes WHERE subscription_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(kept_id, node_id);
    assert_eq!(kept_name, "DMIT-HK-T1");
    assert!(kept_link.ends_with("#DMIT-HK-T1"), "{kept_link}");
    let latency_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(latency_rows, 1);
    let node_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM nodes WHERE subscription_id = 7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(node_count, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_refresh_renames_group_bound_node_by_display_identity() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'resource_group', 'random', 1);
            "#,
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &["vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443?security=tls&type=tcp&sni=example.com#DMIT-HKT1".to_owned()],
    )
    .unwrap();
    let node_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7 AND name = 'DMIT-HKT1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, ?1)",
        params![node_id],
    )
    .unwrap();
    let version_after_bind: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get(0)
        })
        .unwrap();

    let report = replace_subscription_nodes(
        &conn,
        7,
        &["vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443?security=tls&type=tcp&sni=example.com#DMIT-HK-T1".to_owned()],
    )
    .unwrap();
    assert_eq!(report.len(), 1);
    assert_eq!(report[0]["node"]["id"], json!(node_id));
    let kept_name: String = conn
        .query_row(
            "SELECT name FROM nodes WHERE id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(kept_name, "DMIT-HK-T1");
    let group_binding_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_nodes WHERE group_id = 9 AND node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(group_binding_count, 1);
    let version_after_rename: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version_after_rename, version_after_bind + 1);
    let node_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM nodes WHERE subscription_id = 7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(node_count, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_refresh_scopes_unique_names_by_subscription_and_manual_nodes() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/a', 'fetched', '', 'sub-a');
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(8, 'now', 'https://subscription.invalid/b', 'fetched', '', 'sub-b');
            "#,
    )
    .unwrap();
    insert_config_node(
        &conn,
        1,
        "shared-a",
        "http://127.0.0.10:9/manual#shared-a",
        None,
    );
    replace_subscription_nodes(&conn, 7, &["http://127.0.0.1:9/sub-a#shared-a".to_owned()])
        .unwrap();
    replace_subscription_nodes(&conn, 8, &["http://127.0.0.8:9/sub-b#shared-a".to_owned()])
        .unwrap();
    let sub_a_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7 AND name = 'shared-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let sub_b_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 8 AND name = 'shared-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    replace_subscription_nodes(
        &conn,
        7,
        &["http://127.0.0.2:9/sub-a-new#shared-a".to_owned()],
    )
    .unwrap();

    let rows = conn
        .prepare("SELECT id, link, subscription_id FROM nodes WHERE name = 'shared-a' ORDER BY id")
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (1, "http://127.0.0.10:9/manual#shared-a".to_owned(), None),
            (
                sub_a_id,
                "http://127.0.0.2:9/sub-a-new#shared-a".to_owned(),
                Some(7)
            ),
            (
                sub_b_id,
                "http://127.0.0.8:9/sub-b#shared-a".to_owned(),
                Some(8)
            ),
        ]
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn subscription_refresh_keeps_group_version_when_preserved_node_is_unchanged() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'resource_group', 'random', 1);
            "#,
    )
    .unwrap();
    replace_subscription_nodes(
        &conn,
        7,
        &["http://127.0.0.1:9/stable-node#stable-node".to_owned()],
    )
    .unwrap();
    let node_id: i64 = conn
        .query_row(
            "SELECT id FROM nodes WHERE subscription_id = 7 LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, ?1)",
        params![node_id],
    )
    .unwrap();
    let version_after_bind: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get(0)
        })
        .unwrap();

    replace_subscription_nodes(
        &conn,
        7,
        &["http://127.0.0.1:9/stable-node#stable-node".to_owned()],
    )
    .unwrap();
    let version_after_same_refresh: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version_after_same_refresh, version_after_bind);

    replace_subscription_nodes(
        &conn,
        7,
        &["http://127.0.0.1:10/stable-node#stable-node".to_owned()],
    )
    .unwrap();
    let version_after_changed_refresh: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 9", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version_after_changed_refresh, version_after_bind + 1);

    fs::remove_dir_all(dir).unwrap();
}
