use super::*;

#[test]
fn bundle_roundtrip_preserves_node_id_runtime_tag_and_group_binding() {
    let source = FreshProductState::new("identity-bundle-source");
    source.seed_selected_resources();
    let endpoint = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let link = format!(
        "socks://{}#bundle-node-{}",
        endpoint.local_addr().unwrap(),
        fastrand::u64(..)
    );
    let conn = source.connection();
    conn.execute(
        "INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
         VALUES(11, 'now', 'file:///fixture/bundle-source', 'fetched', '', 'bundle-source')",
        [],
    )
    .unwrap();
    let report = replace_subscription_nodes(&conn, 11, std::slice::from_ref(&link)).unwrap();
    let node_id = report[0]["node"]["id"].as_i64().unwrap();
    conn.execute(
        "INSERT INTO groups(id, name, policy, version) VALUES(21, 'bundle_group', 'random', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_subscriptions(group_id, subscription_id, name_filter_regex)
         VALUES(21, 11, NULL)",
        [],
    )
    .unwrap();
    drop(conn);

    let user = fixture_user();
    let bundle = export_bundle(source.state(), &user).unwrap();
    let exported_node = bundle["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["id"] == json!(node_id))
        .unwrap();
    let expected_tag = RuntimeNodeTag::from_node_id(node_id);
    assert_eq!(exported_node["runtimeTag"], json!(expected_tag.as_str()));

    let target = FreshProductState::new("identity-bundle-target");
    target
        .connection()
        .execute(
            "INSERT INTO users(id, username, password_hash, jwt_secret, json_storage)
             VALUES(?1, ?2, '', '', '{}')",
            params![user.id(), user.username()],
        )
        .unwrap();
    let outcome = import_bundle(target.state(), target.root(), &bundle, &user).unwrap();
    assert!(outcome.imported);
    let imported_nodes = list_all_nodes_value(target.state()).unwrap();
    let imported = node_by_id(&imported_nodes, node_id);
    assert_eq!(runtime_node_tag(imported), expected_tag);
    assert_eq!(imported["link"], json!(link));

    let groups = list_groups_value(target.state()).unwrap();
    assert_eq!(
        groups["items"][0]["subscriptions"][0]["matchedCount"],
        json!(1)
    );
    let content = render_generated_config(
        "fixture",
        Some(&(1, "global".to_owned(), "global {}".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "routing { fallback: bundle_group }".to_owned(),
            1,
        )),
        &groups,
        &imported_nodes,
    )
    .unwrap();
    assert_eq!(node_link_from_config(&content, expected_tag.as_str()), link);
}

fn fixture_user() -> UserRecord {
    UserRecord::new(
        1,
        "fixture-user".to_owned(),
        String::new(),
        String::new(),
        "{}".to_owned(),
        None,
        None,
    )
}
