use super::*;

#[test]
fn subscription_rename_preserves_runtime_identity_binding_and_latency() {
    let fixture = FreshProductState::new("subscription-rename-identity");
    let endpoint = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let original_name = format!("original-{}", fastrand::u64(..));
    let renamed = format!("renamed-{}", fastrand::u64(..));
    let original_link = format!("socks://{}#{original_name}", endpoint.local_addr().unwrap());
    let renamed_link = format!("socks://{}#{renamed}", endpoint.local_addr().unwrap());
    let conn = fixture.connection();
    insert_subscription(&conn);
    let report = replace_subscription_nodes(&conn, 11, &[original_link]).unwrap();
    let node_id = report[0]["node"]["id"].as_i64().unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(21, 'rename_group', 'random', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(21, ?1)",
        params![node_id],
    )
    .unwrap();
    seed_latency(&conn, node_id);
    drop(conn);

    let before = get_node_value(fixture.state(), node_id).unwrap().unwrap();
    let before_tag = runtime_node_tag(&before);
    let conn = fixture.connection();
    let report =
        replace_subscription_nodes(&conn, 11, std::slice::from_ref(&renamed_link)).unwrap();
    assert_eq!(report[0]["node"]["id"], json!(node_id));
    let latency_count = row_count(
        &conn,
        "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
        node_id,
    );
    let binding_count = row_count(
        &conn,
        "SELECT COUNT(*) FROM group_nodes WHERE group_id = 21 AND node_id = ?1",
        node_id,
    );
    drop(conn);

    let after = get_node_value(fixture.state(), node_id).unwrap().unwrap();
    assert_eq!(after["id"], json!(node_id));
    assert_eq!(after["name"], json!(renamed));
    assert_eq!(after["link"], json!(renamed_link));
    assert_eq!(runtime_node_tag(&after), before_tag);
    assert_eq!(latency_count, 1);
    assert_eq!(binding_count, 1);
    let summary = list_group_summaries_value(fixture.state()).unwrap();
    assert_eq!(summary["items"][0]["currentNode"]["name"], json!(renamed));
}

#[test]
fn unique_display_name_target_changes_reuse_id_and_invalidate_latency() {
    let fixture = FreshProductState::new("subscription-target-change");
    let first_endpoint = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second_endpoint = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let display_name = format!("stable-display-{}", fastrand::u64(..));
    let first_link = format!(
        "socks://{}#{display_name}",
        first_endpoint.local_addr().unwrap()
    );
    let second_link = format!(
        "socks://{}#{display_name}",
        second_endpoint.local_addr().unwrap()
    );
    let protocol_changed_link = format!(
        "http://{}/resource#{display_name}",
        second_endpoint.local_addr().unwrap()
    );
    let conn = fixture.connection();
    insert_subscription(&conn);
    let first = replace_subscription_nodes(&conn, 11, &[first_link]).unwrap();
    let node_id = first[0]["node"]["id"].as_i64().unwrap();
    let runtime_tag = RuntimeNodeTag::from_node_id(node_id);
    seed_latency(&conn, node_id);

    let second = replace_subscription_nodes(&conn, 11, &[second_link]).unwrap();
    assert_eq!(second[0]["node"]["id"], json!(node_id));
    assert_eq!(latency_count(&conn, node_id), 0);
    seed_latency(&conn, node_id);

    let protocol_changed = replace_subscription_nodes(&conn, 11, &[protocol_changed_link]).unwrap();
    assert_eq!(protocol_changed[0]["node"]["id"], json!(node_id));
    assert_eq!(latency_count(&conn, node_id), 0);
    drop(conn);
    let node = get_node_value(fixture.state(), node_id).unwrap().unwrap();
    assert_eq!(node["protocol"], json!("http"));
    assert_eq!(runtime_node_tag(&node), runtime_tag);
}

#[test]
fn removed_subscription_node_gets_new_identity_when_readded() {
    let fixture = FreshProductState::new("subscription-delete-readd");
    let endpoint = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let link = format!(
        "socks://{}#readded-{}",
        endpoint.local_addr().unwrap(),
        fastrand::u64(..)
    );
    let conn = fixture.connection();
    insert_subscription(&conn);
    let first = replace_subscription_nodes(&conn, 11, std::slice::from_ref(&link)).unwrap();
    let first_id = first[0]["node"]["id"].as_i64().unwrap();
    replace_subscription_nodes(&conn, 11, &[]).unwrap();
    assert_eq!(
        row_count(&conn, "SELECT COUNT(*) FROM nodes WHERE id = ?1", first_id),
        0
    );
    let second = replace_subscription_nodes(&conn, 11, &[link]).unwrap();
    let second_id = second[0]["node"]["id"].as_i64().unwrap();
    assert_ne!(first_id, second_id);
    assert_ne!(
        RuntimeNodeTag::from_node_id(first_id),
        RuntimeNodeTag::from_node_id(second_id)
    );
}

fn insert_subscription(conn: &Connection) {
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
         VALUES(11, 'now', 'file:///fixture/subscription', 'fetched', '', 'fixture-source')",
        [],
    )
    .unwrap();
}

fn seed_latency(conn: &Connection, node_id: i64) {
    conn.execute(
        "INSERT OR REPLACE INTO node_latency_results(
            node_id, latency_ms, alive, tested_at, message, updated_at
         ) VALUES(?1, 17, 1, 'now', NULL, 'now')",
        params![node_id],
    )
    .unwrap();
}

fn latency_count(conn: &Connection, node_id: i64) -> i64 {
    row_count(
        conn,
        "SELECT COUNT(*) FROM node_latency_results WHERE node_id = ?1",
        node_id,
    )
}

fn row_count(conn: &Connection, sql: &str, id: i64) -> i64 {
    conn.query_row(sql, params![id], |row| row.get(0)).unwrap()
}
