use super::super::super::*;
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
                "dns {\n    bind: '127.0.0.1:5353'\n    upstream {\n        primary: 'udp://127.0.0.1:5300'\n    }\n}\n"
                    .to_owned(),
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
    assert_eq!(config.dns.bind, "127.0.0.1:5353");
    assert_eq!(
        config.dns.upstream.as_slice(),
        ["primary:udp://127.0.0.1:5300"]
    );
    assert_eq!(config.routing.rules.len(), 1);
    match &config.routing.fallback {
        DynamicFunctionValue::String(value) => assert_eq!(value, "egress"),
        other => panic!("unexpected routing fallback: {other:?}"),
    }
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
