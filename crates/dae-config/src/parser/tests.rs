use super::*;
use crate::ItemKind;
use crate::fixtures::PARSER_AST_BASIC;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn parses_quoted_keyable_tags_with_config_delimiters() {
    let sections = parse_config(
        r#"
node {
  "9.[region]edge": "scheme://token@example.invalid:443?mode=test&type=stream#edge"
  "name with space": "opaque://example.invalid"
  "name#fragment": "endpoint://example.invalid"
}
dns {
  upstream {
    "dns.[region]": "udp://1.1.1.1:53"
  }
}
"#,
    )
    .unwrap();

    let Item::Param(first_node) = &sections[0].items[0] else {
        panic!("first node should be a param");
    };
    assert_eq!(first_node.key, "9.[region]edge");
    assert_eq!(
        first_node.val,
        "scheme://token@example.invalid:443?mode=test&type=stream#edge"
    );
    let Item::Param(space_node) = &sections[0].items[1] else {
        panic!("second node should be a param");
    };
    assert_eq!(space_node.key, "name with space");
    let Item::Param(fragment_node) = &sections[0].items[2] else {
        panic!("third node should be a param");
    };
    assert_eq!(fragment_node.key, "name#fragment");

    let Item::Section(upstream) = &sections[1].items[0] else {
        panic!("upstream should be a nested section");
    };
    let Item::Param(dns_upstream) = &upstream.items[0] else {
        panic!("dns upstream should be a param");
    };
    assert_eq!(dns_upstream.key, "dns.[region]");
    assert_eq!(dns_upstream.val, "udp://1.1.1.1:53");
}

#[test]
fn parses_ast_basic_success_case() {
    let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
    let input = fixture["cases"][0]["input"].as_str().unwrap();
    let sections = parse_config(input).unwrap();

    assert_eq!(sections.len(), 5);
    assert_eq!(sections[0].name, "include");
    assert_eq!(sections[1].name, "global");
    assert_eq!(sections[2].name, "node");
    assert_eq!(sections[3].name, "group");
    assert_eq!(sections[4].name, "routing");

    let Item::Param(include) = &sections[0].items[0] else {
        panic!("include item should be param");
    };
    assert_eq!(include.key, "");
    assert_eq!(include.val, "child.dae");

    let Item::Param(tcp_check_url) = &sections[1].items[0] else {
        panic!("tcp_check_url item should be param");
    };
    assert_eq!(tcp_check_url.key, "tcp_check_url");
    assert_eq!(
        tcp_check_url.val,
        "https://connectivity.example/generate_204,1.1.1.1"
    );

    assert_eq!(sections[3].items[0].kind(), ItemKind::Section);
    let Item::Section(group) = &sections[3].items[0] else {
        panic!("group item should be a nested section");
    };
    assert_eq!(group.name, "test_group");

    let Item::Param(filter) = &group.items[0] else {
        panic!("filter item should be param");
    };
    assert_eq!(filter.key, "filter");
    assert_eq!(filter.and_functions.len(), 2);
    assert_eq!(filter.and_functions[0].name, "name");
    assert!(filter.and_functions[0].not);
    assert_eq!(filter.and_functions[0].params[0].key, "keyword");
    assert_eq!(filter.and_functions[0].params[0].val, "hk");
    assert_eq!(filter.and_functions[1].name, "subtag");
    assert_eq!(filter.annotation[0].key, "add_latency");
    assert_eq!(filter.annotation[0].val, "-500ms");

    let Item::Param(policy) = &group.items[1] else {
        panic!("policy item should be param");
    };
    assert_eq!(policy.and_functions[0].name, "fixed");
    assert_eq!(policy.and_functions[0].params[0].val, "0");

    let Item::RoutingRule(rule) = &sections[4].items[1] else {
        panic!("second routing item should be rule");
    };
    assert_eq!(rule.and_functions[0].name, "domain");
    assert_eq!(rule.and_functions[0].params[0].key, "suffix");
    assert_eq!(rule.outbound.name, "proxy");
    assert_eq!(rule.outbound.params[0].key, "mark");
    assert_eq!(rule.outbound.params[0].val, "1");
}

#[test]
fn parses_bare_function_param_values_with_delimiter_fragments() {
    let sections = parse_config(
        r#"
routing {
    sample(scope:set-alpha-!beta, source:sample-set:item@scope) -> outlet
}
"#,
    )
    .unwrap();

    let Item::RoutingRule(rule) = &sections[0].items[0] else {
        panic!("routing item should be a rule");
    };
    let params = &rule.and_functions[0].params;
    assert_eq!(params[0].key, "scope");
    assert_eq!(params[0].val, "set-alpha-!beta");
    assert_eq!(params[1].key, "source");
    assert_eq!(params[1].val, "sample-set:item@scope");
}

#[test]
fn parses_delimiter_fragments_in_generic_function_values_only_until_structure_boundaries() {
    let sections = parse_config(
        r#"
group {
    sample {
        filter: name(label:!edge:alpha) && subtag(scope:default)
        policy: fixed(0)
    }
}
"#,
    )
    .unwrap();

    let Item::Section(group) = &sections[0].items[0] else {
        panic!("group item should be a nested section");
    };
    let Item::Param(filter) = &group.items[0] else {
        panic!("filter item should be a param");
    };
    assert_eq!(filter.and_functions.len(), 2);
    assert_eq!(filter.and_functions[0].name, "name");
    assert_eq!(filter.and_functions[0].params[0].key, "label");
    assert_eq!(filter.and_functions[0].params[0].val, "!edge:alpha");
    assert_eq!(filter.and_functions[1].name, "subtag");
    assert_eq!(filter.and_functions[1].params[0].key, "scope");
    assert_eq!(filter.and_functions[1].params[0].val, "default");
}

#[test]
fn parses_ast_basic_projection_matches_native_golden() {
    let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
    let case = &fixture["cases"][0];
    let input = case["input"].as_str().unwrap();
    let sections = parse_config(input).unwrap();

    assert_eq!(project_sections(&sections), case["sections"]);
}

#[test]
fn parses_example_dae_projection_and_strings_match_native_golden() {
    let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
    let example = include_str!("../../../../example.dae");
    let example_bytes = include_bytes!("../../../../example.dae");
    let sections = parse_config(example).unwrap();
    let want = &fixture["example_dae"];
    let section_strings = project_section_strings(&sections);
    let joined = section_strings.join(want["section_string_join_separator"].as_str().unwrap());

    assert_eq!(hex_sha256(example_bytes), want["input_sha256"]);
    assert_eq!(
        sections.len(),
        want["section_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        count_items_recursive(&sections),
        want["item_count_recursive"].as_u64().unwrap() as usize
    );
    assert_eq!(project_sections(&sections), want["sections"]);
    assert_eq!(json!(section_strings), want["section_strings"]);
    assert_eq!(
        hex_sha256(joined.as_bytes()),
        want["section_strings_sha256"]
    );
}

#[test]
fn rejects_ast_basic_error_cases() {
    let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
    for case in &fixture["cases"].as_array().unwrap()[1..] {
        let input = case["input"].as_str().unwrap();
        assert!(parse_config(input).is_err(), "{}", case["name"]);
    }
}

#[test]
fn parses_example_and_marshal_golden_text() {
    let example = include_str!("../../../../example.dae");
    let sections = parse_config(example).unwrap();
    assert!(sections.iter().any(|section| section.name == "global"));
    assert!(sections.iter().any(|section| section.name == "routing"));

    let fixture = dae_golden::load_json(crate::fixtures::MARSHAL_EXAMPLE_ROUNDTRIP).unwrap();
    let text = fixture["marshal"]["text"].as_str().unwrap();
    let sections = parse_config(text).unwrap();
    assert_eq!(sections[0].name, "global");
    assert_eq!(sections.last().unwrap().name, "dns");
}

fn project_sections(sections: &[Section]) -> Value {
    Value::Array(sections.iter().map(project_section).collect())
}

fn project_section_strings(sections: &[Section]) -> Vec<String> {
    sections
        .iter()
        .map(|section| section.to_config_string(false, false))
        .collect()
}

fn count_items_recursive(sections: &[Section]) -> usize {
    sections.iter().map(count_section_items).sum()
}

fn count_section_items(section: &Section) -> usize {
    section
        .items
        .iter()
        .map(|item| {
            1 + match item {
                Item::Section(section) => count_section_items(section),
                Item::Param(_) | Item::RoutingRule(_) => 0,
            }
        })
        .sum()
}

fn hex_sha256(input: &[u8]) -> String {
    format!("{:x}", Sha256::digest(input))
}

fn project_section(section: &Section) -> Value {
    json!({
        "name": section.name,
        "items": section.items.iter().map(project_item).collect::<Vec<_>>(),
    })
}

fn project_item(item: &Item) -> Value {
    match item {
        Item::Param(param) => json!({
            "item_type": "Param",
            "value_kind": "Param",
            "param": project_param(param),
        }),
        Item::Section(section) => json!({
            "item_type": "Param",
            "value_kind": "Section",
            "section": project_section(section),
        }),
        Item::RoutingRule(rule) => json!({
            "item_type": "RoutingRule",
            "value_kind": "RoutingRule",
            "routing_rule": project_routing_rule(rule),
        }),
    }
}

fn project_param(param: &Param) -> Value {
    let mut out = serde_json::Map::from_iter([
        ("key".to_owned(), json!(param.key)),
        ("val".to_owned(), json!(param.val)),
    ]);
    if !param.and_functions.is_empty() {
        out.insert(
            "and_functions".to_owned(),
            Value::Array(param.and_functions.iter().map(project_function).collect()),
        );
    }
    if !param.annotation.is_empty() {
        out.insert(
            "annotation".to_owned(),
            Value::Array(param.annotation.iter().map(project_param).collect()),
        );
    }
    Value::Object(out)
}

fn project_function(function: &Function) -> Value {
    json!({
        "name": function.name,
        "not": function.not,
        "params": function.params.iter().map(project_param).collect::<Vec<_>>(),
    })
}

fn project_routing_rule(rule: &RoutingRule) -> Value {
    json!({
        "and_functions": rule.and_functions.iter().map(project_function).collect::<Vec<_>>(),
        "outbound": project_function(&rule.outbound),
    })
}
