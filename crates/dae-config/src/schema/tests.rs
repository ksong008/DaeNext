use super::*;
use crate::fixtures::SCHEMA_DEFAULT_PATCH;
use crate::parser::parse_config;
use serde_json::{Value, json};

#[test]
fn builds_schema_default_patch_golden_cases() {
    let fixture = dae_golden::load_json(SCHEMA_DEFAULT_PATCH).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let parsed = parse_config(input);
        if case["phase"].as_str() == Some("parse") {
            assert!(parsed.is_err(), "{}", case["name"]);
            continue;
        }
        let sections = parsed.unwrap();
        let got = build_config(&sections);
        assert_eq!(
            got.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        if let Ok(config) = got {
            assert_eq!(project_config(&config), case["config"], "{}", case["name"]);
        } else {
            let error = got.unwrap_err().to_string();
            assert!(
                error.contains(case["error"].as_str().unwrap()),
                "{}: {error}",
                case["name"]
            );
        }
    }
}

fn project_config(config: &Config) -> Value {
    json!({
        "global": project_global(&config.global),
        "subscription": config.subscription,
        "node": config.node,
        "group": config.group.iter().map(project_group).collect::<Vec<_>>(),
        "routing": {
            "rules": project_rules(&config.routing.rules),
            "fallback": project_dynamic(&config.routing.fallback),
        },
        "dns": project_dns(&config.dns),
    })
}

fn project_global(global: &Global) -> Value {
    json!({
        "tproxy_port": global.tproxy_port,
        "tproxy_port_protect": global.tproxy_port_protect,
        "so_mark_from_dae": global.so_mark_from_dae,
        "log_level": global.log_level,
        "tcp_check_url": global.tcp_check_url,
        "tcp_check_http_method": global.tcp_check_http_method,
        "udp_check_dns": global.udp_check_dns,
        "check_interval": global.check_interval.to_string(),
        "check_tolerance": global.check_tolerance.to_string(),
        "udp_endpoint_pool_size": global.udp_endpoint_pool_size,
        "lan_interface": global.lan_interface,
        "wan_interface": global.wan_interface,
        "allow_insecure": global.allow_insecure,
        "dial_mode": global.dial_mode,
        "disable_waiting_network": global.disable_waiting_network,
        "enable_local_tcp_fast_redirect": global.enable_local_tcp_fast_redirect,
        "auto_config_kernel_parameter": global.auto_config_kernel_parameter,
        "auto_config_firewall_rule": global.auto_config_firewall_rule,
        "sniffing_timeout": global.sniffing_timeout.to_string(),
        "tls_implementation": global.tls_implementation,
        "utls_imitate": global.utls_imitate,
        "tls_fragment": global.tls_fragment,
        "tls_fragment_length": global.tls_fragment_length,
        "tls_fragment_interval": global.tls_fragment_interval,
        "pprof_port": global.pprof_port,
        "mptcp": global.mptcp,
        "fallback_resolver": global.fallback_resolver,
        "bandwidth_max_tx": global.bandwidth_max_tx,
        "bandwidth_max_rx": global.bandwidth_max_rx,
        "udphop_interval": global.udphop_interval.to_string(),
    })
}

fn project_group(group: &Group) -> Value {
    json!({
        "name": group.name,
        "filter": group.filter.iter().map(|functions| project_functions(functions)).collect::<Vec<_>>(),
        "filter_annotation": group.filter_annotation.iter().map(|params| {
            params.as_ref().map(|params| project_params(params))
        }).collect::<Vec<_>>(),
        "policy": project_dynamic(&group.policy),
        "tcp_check_url": group.tcp_check_url,
        "tcp_check_http_method": group.tcp_check_http_method,
        "udp_check_dns": group.udp_check_dns,
        "check_interval": group.check_interval.to_string(),
        "check_tolerance": group.check_tolerance.to_string(),
    })
}

fn project_dns(dns: &Dns) -> Value {
    json!({
        "ipversion_prefer": dns.ipversion_prefer,
        "fixed_domain_ttl": dns.fixed_domain_ttl,
        "upstream": dns.upstream,
        "routing": {
            "request": {
                "rules": project_rules(&dns.routing.request.rules),
                "fallback": project_dynamic(&dns.routing.request.fallback),
            },
            "response": {
                "rules": project_rules(&dns.routing.response.rules),
                "fallback": project_dynamic(&dns.routing.response.fallback),
            },
        },
        "bind": dns.bind,
    })
}

fn project_dynamic(value: &DynamicFunctionValue) -> Value {
    match value {
        DynamicFunctionValue::Nil => json!({"kind": "nil"}),
        DynamicFunctionValue::String(value) => json!({"kind": "string", "string": value}),
        DynamicFunctionValue::Function(function) => {
            json!({"kind": "function", "function": project_function(function)})
        }
        DynamicFunctionValue::FunctionList(functions) => {
            json!({"kind": "function_list", "functions": project_functions(functions)})
        }
    }
}

fn project_rules(rules: &[RoutingRule]) -> Vec<Value> {
    rules
        .iter()
        .map(|rule| {
            json!({
                "and_functions": project_functions(&rule.and_functions),
                "outbound": project_function(&rule.outbound),
            })
        })
        .collect()
}

fn project_functions(functions: &[Function]) -> Vec<Value> {
    functions.iter().map(project_function).collect()
}

fn project_function(function: &Function) -> Value {
    json!({
        "name": function.name,
        "not": function.not,
        "params": project_params(&function.params),
    })
}

fn project_params(params: &[Param]) -> Vec<Value> {
    params
        .iter()
        .map(|param| {
            json!({
                "key": param.key,
                "val": param.val,
            })
        })
        .collect()
}
