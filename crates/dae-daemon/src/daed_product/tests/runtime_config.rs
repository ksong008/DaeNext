use super::*;
use dae_config::DynamicFunctionValue;
#[test]
pub(crate) fn generated_runtime_config_renders_parseable_nodes_and_groups() {
    let source_config = test_config_with_node(
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
        "egress",
    );
    let parsed_source = build_runtime_config_from_content(&source_config).unwrap();
    let egress_name = parsed_source.group[0].name.clone();
    let alternate_name = "alternate_egress".to_owned();
    let node = config_node_value(
        1,
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
    );
    let groups = json!({
        "items": [
            {
                "name": egress_name,
                "policy": "random",
                "nodes": [node.clone()],
                "subscriptions": []
            },
            {
                "name": alternate_name,
                "policy": "random",
                "nodes": [node.clone()],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({
        "items": [node]
    });
    let content = render_generated_config(
            "test",
            Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
            Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
            Some(&(
                1,
                "routing".to_owned(),
                "routing {\n    sample(scope:sample-set:alpha-!beta, suffix:resource.invalid) -> alternate_egress\n    fallback: egress\n}\n".to_owned(),
                1,
            )),
            &groups,
            &nodes,
        )
        .unwrap();
    assert!(content.contains("node {"));
    assert!(content.contains("resource_node:"));
    assert!(content.contains("filter: name('resource_node')"));
    let config = build_runtime_config_from_content(&content).unwrap();
    assert_eq!(config.node.len(), 1);
    assert_eq!(config.group[0].name, "egress");
    assert_eq!(
        config.routing.rules[0].and_functions[0].params[0].val,
        "sample-set:alpha-!beta"
    );
}

#[test]
fn generated_runtime_config_skips_empty_groups_not_referenced_by_selected_routing() {
    let node = config_node_value(
        1,
        "primary_node",
        "http://127.0.0.1:9/node-under-test#primary-node",
    );
    let groups = json!({
        "items": [
            {
                "name": "primary",
                "policy": "random",
                "nodes": [node.clone()],
                "subscriptions": []
            },
            {
                "name": "unused",
                "policy": "random",
                "nodes": [],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": [node]});
    let content = render_generated_config(
        "test",
        Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "routing {\n    fallback: primary\n}\n".to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap();

    assert!(content.contains("    primary {"));
    assert!(!content.contains("    unused {"));
    let config = build_runtime_config_from_content(&content).unwrap();
    assert_eq!(config.group.len(), 1);
    assert_eq!(config.group[0].name, "primary");
}

#[test]
fn generated_runtime_config_preserves_group_policy_params() {
    let node = config_node_value(1, "node_a", "http://127.0.0.1:9/node-under-test#node-a");
    let groups = json!({
        "items": [
            {
                "name": "proxy",
                "policy": "fixed",
                "policyParams": [{"key": "", "val": "1"}],
                "nodes": [node.clone()],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": [node]});
    let content = render_generated_config(
        "test",
        Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "routing {\n    fallback: proxy\n}\n".to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap();

    assert!(content.contains("policy: fixed("));
    let config = build_runtime_config_from_content(&content).unwrap();
    match &config.group[0].policy {
        DynamicFunctionValue::Function(function) => {
            assert_eq!(function.name, "fixed");
            assert_eq!(function.params[0].val, "1");
        }
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            assert_eq!(functions[0].name, "fixed");
            assert_eq!(functions[0].params[0].val, "1");
        }
        other => panic!("unexpected group policy: {other:?}"),
    }
}

#[test]
fn generated_runtime_config_parses_selected_global_dns_and_routing_sections() {
    let source_config = test_config_with_node(
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
        "egress",
    );
    let parsed_source = build_runtime_config_from_content(&source_config).unwrap();
    let node = config_node_value(
        1,
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
    );
    let groups = json!({
        "items": [
            {
                "name": parsed_source.group[0].name.clone(),
                "policy": "random",
                "nodes": [node.clone()],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": [node]});
    const LOCAL_DNS_BIND_PORT: u16 = 8053;
    const LOCAL_DNS_UPSTREAM_PORT: u16 = 8054;
    let dns_section = format!(
        "dns {{\n    bind: '127.0.0.1:{LOCAL_DNS_BIND_PORT}'\n    upstream {{\n        primary: 'udp://127.0.0.1:{LOCAL_DNS_UPSTREAM_PORT}'\n    }}\n}}\n"
    );
    let content = render_generated_config(
            "test",
            Some(&(
                1,
                "global".to_owned(),
                "global {\n    log_level: debug\n    lan_interface: if_test0\n    wan_interface: if_test1\n}\n"
                    .to_owned(),
                1,
            )),
            Some(&(
                1,
                "dns".to_owned(),
                dns_section,
                1,
            )),
            Some(&(
                1,
                "routing".to_owned(),
                "routing {\n    domain(suffix:example.test) -> egress\n    fallback: egress\n}\n"
                    .to_owned(),
                1,
            )),
            &groups,
            &nodes,
        )
        .unwrap();

    let config = build_runtime_config_from_content(&content).unwrap();
    assert_eq!(config.global.log_level, "debug");
    assert_eq!(
        config.global.lan_interface.as_deref(),
        Some(&["if_test0".to_owned()][..])
    );
    assert_eq!(
        config.global.wan_interface.as_deref(),
        Some(&["if_test1".to_owned()][..])
    );
    assert_eq!(config.dns.bind, format!("127.0.0.1:{LOCAL_DNS_BIND_PORT}"));
    assert_eq!(
        config.dns.upstream.as_slice(),
        [format!("primary:udp://127.0.0.1:{LOCAL_DNS_UPSTREAM_PORT}")]
    );
    assert_eq!(config.routing.rules.len(), 1);
    match &config.routing.fallback {
        DynamicFunctionValue::String(value) => assert_eq!(value, "egress"),
        other => panic!("unexpected routing fallback: {other:?}"),
    }
}

#[test]
fn generated_runtime_config_accepts_dns_body_resources() {
    let source_config = test_config_with_node(
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
        "egress",
    );
    let parsed_source = build_runtime_config_from_content(&source_config).unwrap();
    let node = config_node_value(
        1,
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
    );
    let groups = json!({
        "items": [
            {
                "name": parsed_source.group[0].name.clone(),
                "policy": "random",
                "nodes": [node.clone()],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": [node]});
    let content = render_generated_config(
        "test",
        Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
        Some(&(
            1,
            "dns".to_owned(),
            "upstream {\n    primary: 'udp://resolver.test:53'\n}\nrouting {\n    request {\n        fallback: primary\n    }\n}\n"
                .to_owned(),
            1,
        )),
        Some(&(
            1,
            "routing".to_owned(),
            "routing { fallback: egress }\n".to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap();

    assert!(content.contains("# selected dns\ndns {\n"));
    let config = build_runtime_config_from_content(&content).unwrap();
    assert_eq!(config.dns.upstream, ["primary:udp://resolver.test:53"]);
}

#[test]
fn generated_runtime_config_preserves_complete_dns_sections() {
    let raw = "dns {\n    bind: '127.0.0.1:8053'\n}\n";
    assert_eq!(render_dns_section(Some(raw)), raw);
    assert_eq!(render_dns_section(None), "dns {}\n");
}

#[test]
fn generated_runtime_config_accepts_routing_body_resources() {
    let source_config = test_config_with_node(
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
        "egress",
    );
    let parsed_source = build_runtime_config_from_content(&source_config).unwrap();
    let node = config_node_value(
        1,
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
    );
    let groups = json!({
        "items": [
            {
                "name": parsed_source.group[0].name.clone(),
                "policy": "random",
                "nodes": [node.clone()],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": [node]});
    let content = render_generated_config(
        "test",
        Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "domain(suffix:example.test) -> egress\nfallback: egress\n".to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap();

    assert!(content.contains("# selected routing\nrouting {\n"));
    let config = build_runtime_config_from_content(&content).unwrap();
    assert_eq!(config.routing.rules.len(), 1);
    match &config.routing.fallback {
        DynamicFunctionValue::String(value) => assert_eq!(value, "egress"),
        other => panic!("unexpected routing fallback: {other:?}"),
    }
}

#[test]
fn generated_runtime_config_preserves_complete_routing_sections() {
    let raw = "routing {\n    fallback: proxy\n}\n";
    assert_eq!(render_routing_section(Some(raw)), raw);
    assert_eq!(render_routing_section(None), "routing {}\n");
}

#[test]
fn generated_runtime_config_rejects_empty_group_filters() {
    let source_config = test_config_with_node(
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
        "egress",
    );
    let parsed_source = build_runtime_config_from_content(&source_config).unwrap();
    let egress_name = parsed_source.group[0].name.clone();
    let groups = json!({
        "items": [
            {
                "name": egress_name,
                "policy": "random",
                "nodes": [],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": []});
    let err = render_generated_config(
        "test",
        Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "routing { fallback: egress }\n".to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("group egress has no matched nodes")
    );
}

#[test]
fn generated_runtime_config_rejects_empty_must_group_reference() {
    let groups = json!({
        "items": [
            {
                "name": "backup",
                "policy": "random",
                "nodes": [],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": []});
    let err = render_generated_config(
        "test",
        Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "routing {\n    dip(geoip:telegram) -> must_backup\n    fallback: direct\n}\n"
                .to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("group backup has no matched nodes")
    );
}

#[test]
fn generated_runtime_config_rejects_fixed_group_with_multiple_matched_nodes() {
    let node_a = config_node_value(1, "node_a", "http://127.0.0.1:9/node-a#node-a");
    let node_b = config_node_value(2, "node_b", "http://127.0.0.2:9/node-b#node-b");
    let groups = json!({
        "items": [
            {
                "name": "proxy",
                "policy": "fixed",
                "nodes": [node_a.clone(), node_b.clone()],
                "subscriptions": []
            }
        ]
    });
    let nodes = json!({"items": [node_a, node_b]});

    let err = render_generated_config(
        "test",
        Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
        Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
        Some(&(
            1,
            "routing".to_owned(),
            "routing { fallback: proxy }\n".to_owned(),
            1,
        )),
        &groups,
        &nodes,
    )
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("fixed group proxy can match only one node"),
        "{err}"
    );
}
