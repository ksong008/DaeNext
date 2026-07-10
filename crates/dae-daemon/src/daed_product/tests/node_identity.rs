use super::support::FreshProductState;
use super::*;
use std::net::{Ipv4Addr, TcpListener};

#[test]
fn cross_subscription_same_display_name_uses_unique_runtime_identity() {
    let fixture = FreshProductState::new("cross-subscription-runtime-identity");
    fixture.seed_selected_resources();
    let endpoint_a = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let endpoint_b = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let shared_display_name = format!("shared-label-{}", fastrand::u64(..));
    let link_a = format!(
        "socks://{}#{}",
        endpoint_a.local_addr().unwrap(),
        shared_display_name
    );
    let link_b = format!(
        "socks://{}#{}",
        endpoint_b.local_addr().unwrap(),
        shared_display_name
    );

    let conn = fixture.connection();
    conn.execute_batch(
        r#"
        INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
            VALUES(11, 'now', 'file:///fixture/subscription-a', 'fetched', '', 'source-a');
        INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
            VALUES(12, 'now', 'file:///fixture/subscription-b', 'fetched', '', 'source-b');
        INSERT INTO groups(id, name, policy, version) VALUES(21, 'fixed_source_a', 'fixed', 1);
        INSERT INTO groups(id, name, policy, version) VALUES(22, 'min_source_a', 'min', 1);
        INSERT INTO groups(id, name, policy, version) VALUES(23, 'random_source_a', 'random', 1);
        INSERT INTO group_subscriptions(group_id, subscription_id) VALUES(21, 11);
        INSERT INTO group_subscriptions(group_id, subscription_id) VALUES(22, 11);
        INSERT INTO group_subscriptions(group_id, subscription_id) VALUES(23, 11);
        "#,
    )
    .unwrap();
    let name_filter = format!("^{}$", regex::escape(&shared_display_name));
    conn.execute(
        "UPDATE group_subscriptions SET name_filter_regex = ?1",
        params![name_filter],
    )
    .unwrap();
    for (id, link, subscription_id) in [(31_i64, &link_a, 11_i64), (32, &link_b, 12)] {
        let parsed = parse_node_link(link, None);
        conn.execute(
            "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(?1, ?2, ?3, ?4, ?5, NULL, ?6)",
            params![
                id,
                link,
                parsed.display_name,
                parsed.address,
                parsed.protocol,
                subscription_id
            ],
        )
        .unwrap();
    }
    drop(conn);

    let nodes = list_all_nodes_value(fixture.state()).unwrap();
    let groups = list_groups_value(fixture.state()).unwrap();
    let node_a = node_by_id(&nodes, 31);
    let node_b = node_by_id(&nodes, 32);
    let tag_a = runtime_node_tag(node_a);
    let tag_b = runtime_node_tag(node_b);
    assert_eq!(tag_a, RuntimeNodeTag::from_node_id(31));
    assert_eq!(tag_b, RuntimeNodeTag::from_node_id(32));
    assert_ne!(
        tag_a, tag_b,
        "different database nodes need unique runtime tags"
    );
    assert_eq!(node_a["name"], json!(shared_display_name));
    assert_eq!(node_b["name"], json!(shared_display_name));

    let content = render_generated_config(
        "fixture",
        Some(&(1, "global".to_owned(), "global {}".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "routing { fallback: fixed_source_a }".to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap();
    let config = build_runtime_config_from_content(&content).unwrap();
    assert_eq!(config.node.len(), 2);
    assert_eq!(node_link_from_config(&content, tag_a.as_str()), link_a);
    assert_eq!(node_link_from_config(&content, tag_b.as_str()), link_b);

    assert_eq!(config.group.len(), 3);
    for group in &config.group {
        let selected_tags = group
            .filter
            .iter()
            .flatten()
            .filter(|filter| filter.name == "name" && !filter.not)
            .flat_map(|filter| filter.params.iter().map(|param| param.val.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(selected_tags, vec![tag_a.as_str()], "group {}", group.name);
    }

    let runtime_selectors = BTreeMap::from([(
        "min_source_a".to_owned(),
        json!({"selectedNodeTag": tag_a.as_str()}),
    )]);
    let summary =
        list_group_summaries_value_with_runtime_selection(fixture.state(), &runtime_selectors)
            .unwrap();
    let selected_group = summary["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["name"] == json!("min_source_a"))
        .unwrap();
    assert_eq!(selected_group["materializedCandidateCount"], json!(1));
    assert_eq!(selected_group["runtimeSelectedNode"]["id"], json!(31));
    assert_eq!(
        selected_group["runtimeSelectedNode"]["name"],
        json!(shared_display_name)
    );
}

fn node_by_id(nodes: &Value, id: i64) -> &Value {
    nodes["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["id"] == json!(id))
        .unwrap()
}
