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
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, 'proxy', 'fixed', 3)",
        [],
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
    assert_eq!(policy, "fixed");
    assert_eq!(version, 3);
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
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'resource_group', 'random', 2);
            INSERT INTO group_subscriptions(group_id, subscription_id, name_filter_regex)
                VALUES(9, 7, 'candidate');
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
    insert_config_node(
        &conn,
        30,
        "manual",
        "http://127.0.0.1:9/manual#manual",
        None,
    );
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(9, 30)",
        [],
    )
    .unwrap();
    drop(conn);

    let summary = list_group_summaries_value(&state).unwrap();
    let group = &summary["items"][0];
    assert_eq!(group["id"], json!(9));
    assert_eq!(group["nodeCount"], json!(1));
    assert_eq!(group["subscriptionCount"], json!(1));
    assert_eq!(group["firstNode"]["name"], json!("manual"));
    assert_eq!(group["firstSubscription"]["matchedCount"], json!(7));
    assert_eq!(
        group["firstSubscription"]["sampleMatchedNodes"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );
    assert_eq!(
        group["firstSubscription"]["sampleMatchedNodes"][0]["name"],
        json!("candidate-alpha")
    );
    assert!(group.get("nodes").is_none(), "{group}");
    assert!(group.get("subscriptions").is_none(), "{group}");
    assert!(
        group["firstSubscription"].get("matchedNodes").is_none(),
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
