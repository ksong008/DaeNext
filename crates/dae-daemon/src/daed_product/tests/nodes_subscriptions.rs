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
