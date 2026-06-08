use super::super::super::*;
use super::*;
#[test]
pub(crate) fn default_resources_bind_supplied_node_ids_to_group() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    insert_config_node(
        &conn,
        1,
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
        None,
    );
    drop(conn);

    let response = ensure_default_resources(&state, &json!({"nodeIds": [1]})).unwrap();
    let group_id = response["defaultGroupID"]
        .as_str()
        .unwrap()
        .parse::<i64>()
        .unwrap();
    let conn = open_state_connection(&state).unwrap();
    let bound_count = conn
        .query_row(
            "SELECT COUNT(*) FROM group_nodes WHERE group_id = ?1 AND node_id = ?2",
            params![group_id, 1_i64],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(bound_count, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn default_resources_are_idempotent_for_empty_policy_params() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let body = json!({
        "configName": "global",
        "global": "global {}",
        "dnsName": "default",
        "dns": "dns {}",
        "routingName": "default",
        "routing": "routing { fallback: proxy }",
        "groupName": "proxy",
        "policy": "random",
        "policyParams": [],
        "mode": "rule"
    });

    let first = ensure_default_resources(&state, &body).unwrap();
    let group_id = first["defaultGroupID"]
        .as_str()
        .unwrap()
        .parse::<i64>()
        .unwrap();
    let conn = open_state_connection(&state).unwrap();
    let first_version: i64 = conn
        .query_row(
            "SELECT version FROM groups WHERE id = ?1",
            params![group_id],
            |row| row.get(0),
        )
        .unwrap();
    drop(conn);

    ensure_default_resources(&state, &body).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let second_version: i64 = conn
        .query_row(
            "SELECT version FROM groups WHERE id = ?1",
            params![group_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(second_version, first_version);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn default_resources_do_not_overwrite_existing_group_policy() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(1, 'proxy', 'fixed', 7)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_policy_params(key, value, group_id) VALUES('', '1', 1)",
        [],
    )
    .unwrap();
    drop(conn);

    let response = ensure_default_resources(
        &state,
        &json!({
            "groupName": "proxy",
            "policy": "min_moving_avg",
            "policyParams": [],
        }),
    )
    .unwrap();
    assert_eq!(response["defaultGroupID"], json!("1"));

    let conn = open_state_connection(&state).unwrap();
    let group: (String, i64) = conn
        .query_row(
            "SELECT policy, version FROM groups WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let param: (String, String) = conn
        .query_row(
            "SELECT key, value FROM group_policy_params WHERE group_id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(group, ("fixed".to_owned(), 7));
    assert_eq!(param, ("".to_owned(), "1".to_owned()));
    fs::remove_dir_all(dir).unwrap();
}
