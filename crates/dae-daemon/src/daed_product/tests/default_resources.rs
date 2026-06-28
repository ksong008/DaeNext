use super::*;
#[test]
pub(crate) fn default_resources_do_not_create_default_group_for_empty_state() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();

    let response = ensure_default_resources(
        &state,
        &json!({
            "groupName": DEFAULT_PRODUCT_GROUP_NAME,
            "policy": DEFAULT_PRODUCT_GROUP_POLICY,
        }),
    )
    .unwrap();
    assert_eq!(response["defaultGroupID"], json!(""));

    let conn = open_state_connection(&state).unwrap();
    let group_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM groups", [], |row| row.get(0))
        .unwrap();
    assert_eq!(group_count, 0);
    for table in ["configs", "dns", "routings"] {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE selected = 1");
        let selected_count: i64 = conn.query_row(&sql, [], |row| row.get(0)).unwrap();
        assert_eq!(selected_count, 1, "{table}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn default_resources_prefer_selected_routing_group_over_default_group() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "INSERT INTO routings(id, name, routing, selected, version)
         VALUES(4, 'active', 'routing { domain(suffix:example.test) -> media fallback: proxy }', 1, 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(7, 'proxy', ?1, 3)",
        params![GROUP_POLICY_FIXED],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(8, 'media', ?1, 5)",
        params![DEFAULT_PRODUCT_GROUP_POLICY],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(9, 'default', ?1, 0)",
        params![DEFAULT_PRODUCT_GROUP_POLICY],
    )
    .unwrap();
    drop(conn);

    let response = ensure_default_resources(
        &state,
        &json!({
            "groupName": DEFAULT_PRODUCT_GROUP_NAME,
            "policy": DEFAULT_PRODUCT_GROUP_POLICY,
            "routingName": DEFAULT_PRODUCT_ROUTING_NAME,
            "routing": format!("routing {{ fallback: {DEFAULT_PRODUCT_GROUP_NAME} }}"),
        }),
    )
    .unwrap();
    assert_eq!(response["defaultGroupID"], json!("7"));

    let conn = open_state_connection(&state).unwrap();
    let group_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM groups", [], |row| row.get(0))
        .unwrap();
    let default_group_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM groups WHERE name = ?1",
            params![DEFAULT_PRODUCT_GROUP_NAME],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(group_count, 3);
    assert_eq!(default_group_count, 1);
    fs::remove_dir_all(dir).unwrap();
}

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

    let group_name = "resource_group";
    let response = ensure_default_resources(
        &state,
        &json!({
            "groupName": group_name,
            "nodeIds": [1],
        }),
    )
    .unwrap();
    let group_id = response["defaultGroupID"]
        .as_str()
        .unwrap()
        .parse::<i64>()
        .unwrap();
    let conn = open_state_connection(&state).unwrap();
    let (group_name, bound_count): (String, i64) = conn
        .query_row(
            "SELECT g.name, COUNT(gn.node_id)
             FROM groups g
             LEFT JOIN group_nodes gn ON gn.group_id = g.id AND gn.node_id = ?2
             WHERE g.id = ?1
             GROUP BY g.id, g.name",
            params![group_id, 1_i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(group_name, "resource_group");
    assert_eq!(bound_count, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn default_resources_are_idempotent_for_empty_policy_params() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let group_name = "egress";
    let body = json!({
        "configName": DEFAULT_PRODUCT_CONFIG_NAME,
        "global": DEFAULT_GLOBAL_RESOURCE_TEXT,
        "dnsName": DEFAULT_PRODUCT_DNS_NAME,
        "dns": "dns {}",
        "routingName": DEFAULT_PRODUCT_ROUTING_NAME,
        "routing": format!("routing {{ fallback: {group_name} }}"),
        "groupName": group_name,
        "policy": DEFAULT_PRODUCT_GROUP_POLICY,
        "policyParams": [],
        "mode": DEFAULT_PRODUCT_MODE
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
    let group_name = "existing_egress";
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(1, ?1, ?2, 7)",
        params![group_name, GROUP_POLICY_FIXED],
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
            "groupName": group_name,
            "policy": GROUP_POLICY_MIN_MOVING_AVG,
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
    assert_eq!(group, (GROUP_POLICY_FIXED.to_owned(), 7));
    assert_eq!(param, ("".to_owned(), "1".to_owned()));
    fs::remove_dir_all(dir).unwrap();
}
