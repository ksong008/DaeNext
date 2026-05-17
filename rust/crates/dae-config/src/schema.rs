use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;

use dae_config_util::{FuzzyDecode, GoDuration, fuzzy_decode, is_valid_http_method};

use crate::ast::{Function, Item, Param, RoutingRule, Section};
use crate::dynamic::DynamicFunctionValue;
use crate::error::ConfigError;

pub type KeyableString = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub global: Global,
    pub subscription: Vec<KeyableString>,
    pub node: Vec<KeyableString>,
    pub group: Vec<Group>,
    pub routing: Routing,
    pub dns: Dns,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Global {
    pub tproxy_port: u16,
    pub tproxy_port_protect: bool,
    pub so_mark_from_dae: u32,
    pub log_level: String,
    pub tcp_check_url: Vec<String>,
    pub tcp_check_http_method: String,
    pub udp_check_dns: Vec<String>,
    pub check_interval: GoDuration,
    pub check_tolerance: GoDuration,
    pub udp_endpoint_pool_size: i32,
    pub lan_interface: Option<Vec<String>>,
    pub wan_interface: Option<Vec<String>>,
    pub allow_insecure: bool,
    pub dial_mode: String,
    pub disable_waiting_network: bool,
    pub enable_local_tcp_fast_redirect: bool,
    pub auto_config_kernel_parameter: bool,
    pub auto_config_firewall_rule: bool,
    pub sniffing_timeout: GoDuration,
    pub tls_implementation: String,
    pub utls_imitate: String,
    pub tls_fragment: bool,
    pub tls_fragment_length: String,
    pub tls_fragment_interval: String,
    pub pprof_port: u16,
    pub mptcp: bool,
    pub fallback_resolver: String,
    pub bandwidth_max_tx: String,
    pub bandwidth_max_rx: String,
    pub udphop_interval: GoDuration,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            tproxy_port: 12345,
            tproxy_port_protect: true,
            so_mark_from_dae: 0,
            log_level: "info".to_owned(),
            tcp_check_url: split_csv("http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111"),
            tcp_check_http_method: "HEAD".to_owned(),
            udp_check_dns: split_csv("dns.google:53,8.8.8.8,2001:4860:4860::8888"),
            check_interval: parse_default_duration("30s"),
            check_tolerance: parse_default_duration("0"),
            udp_endpoint_pool_size: 4096,
            lan_interface: None,
            wan_interface: None,
            allow_insecure: false,
            dial_mode: "domain".to_owned(),
            disable_waiting_network: false,
            enable_local_tcp_fast_redirect: false,
            auto_config_kernel_parameter: false,
            auto_config_firewall_rule: false,
            sniffing_timeout: parse_default_duration("100ms"),
            tls_implementation: "tls".to_owned(),
            utls_imitate: "chrome_auto".to_owned(),
            tls_fragment: false,
            tls_fragment_length: "50-100".to_owned(),
            tls_fragment_interval: "10-20".to_owned(),
            pprof_port: 0,
            mptcp: false,
            fallback_resolver: "8.8.8.8:53".to_owned(),
            bandwidth_max_tx: "0".to_owned(),
            bandwidth_max_rx: "0".to_owned(),
            udphop_interval: parse_default_duration("30s"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    pub name: String,
    pub filter: Vec<Vec<Function>>,
    pub filter_annotation: Vec<Option<Vec<Param>>>,
    pub policy: DynamicFunctionValue,
    pub tcp_check_url: Option<Vec<String>>,
    pub tcp_check_http_method: String,
    pub udp_check_dns: Option<Vec<String>>,
    pub check_interval: GoDuration,
    pub check_tolerance: GoDuration,
}

impl Group {
    fn new(name: String) -> Self {
        Self {
            name,
            filter: Vec::new(),
            filter_annotation: Vec::new(),
            policy: DynamicFunctionValue::Nil,
            tcp_check_url: None,
            tcp_check_http_method: String::new(),
            udp_check_dns: None,
            check_interval: GoDuration::default(),
            check_tolerance: GoDuration::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Routing {
    pub rules: Vec<RoutingRule>,
    pub fallback: DynamicFunctionValue,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            fallback: DynamicFunctionValue::String("direct".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dns {
    pub ipversion_prefer: i32,
    pub fixed_domain_ttl: Vec<KeyableString>,
    pub upstream: Vec<KeyableString>,
    pub routing: DnsRouting,
    pub bind: String,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            ipversion_prefer: 0,
            fixed_domain_ttl: Vec::new(),
            upstream: Vec::new(),
            routing: DnsRouting::default(),
            bind: String::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DnsRouting {
    pub request: DnsRuleSet,
    pub response: DnsRuleSet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRuleSet {
    pub rules: Vec<RoutingRule>,
    pub fallback: DynamicFunctionValue,
}

impl Default for DnsRuleSet {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            fallback: DynamicFunctionValue::Nil,
        }
    }
}

pub fn build_config(sections: &[Section]) -> Result<Config, ConfigError> {
    let mut name_to_section: HashMap<&str, (&Section, bool)> = HashMap::new();
    for section in sections {
        name_to_section.insert(section.name.as_str(), (section, false));
    }

    let global = match name_to_section.get_mut("global") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_global(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"global\": {err}")))?
        }
        None => {
            return Err(ConfigError::Build(
                "section global is required but not provided".to_owned(),
            ));
        }
    };

    let subscription = match name_to_section.get_mut("subscription") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_string_section(section).map_err(|err| {
                ConfigError::Build(format!("failed to parse \"subscription\": {err}"))
            })?
        }
        None => Vec::new(),
    };

    let node = match name_to_section.get_mut("node") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_string_section(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"node\": {err}")))?
        }
        None => Vec::new(),
    };

    let group = match name_to_section.get_mut("group") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_group_section(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"group\": {err}")))?
        }
        None => Vec::new(),
    };

    let routing = match name_to_section.get_mut("routing") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_routing(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"routing\": {err}")))?
        }
        None => {
            return Err(ConfigError::Build(
                "section routing is required but not provided".to_owned(),
            ));
        }
    };

    let dns = match name_to_section.get_mut("dns") {
        Some((section, parsed)) => {
            *parsed = true;
            parse_dns(section)
                .map_err(|err| ConfigError::Build(format!("failed to parse \"dns\": {err}")))?
        }
        None => Dns::default(),
    };

    for (name, (section, parsed)) in name_to_section {
        if section.name == "include" {
            continue;
        }
        if !parsed {
            return Err(ConfigError::Build(format!("unknown section: {name}")));
        }
    }

    let mut config = Config {
        global,
        subscription,
        node,
        group,
        routing,
        dns,
    };
    patch_fallback_resolver(&config)?;
    patch_tcp_check_http_method(&mut config);
    patch_empty_dns(&mut config);
    patch_must_outbound(&mut config)?;
    Ok(config)
}

fn parse_global(section: &Section) -> Result<Global, String> {
    let mut global = Global::default();
    let mut tcp_check_url_set = false;
    let mut udp_check_dns_set = false;
    let mut lan_interface_set = false;
    let mut wan_interface_set = false;

    for item in &section.items {
        let Item::Param(param) = item else {
            return Err(unexpected_item_error(section, item));
        };
        reject_naked_param(param)?;
        reject_function_value(param)?;

        match param.key.as_str() {
            "tproxy_port" => global.tproxy_port = decode_param(param, "uint16")?,
            "tproxy_port_protect" => global.tproxy_port_protect = decode_param(param, "bool")?,
            "so_mark_from_dae" => global.so_mark_from_dae = decode_param(param, "uint32")?,
            "log_level" => global.log_level = param.val.clone(),
            "tcp_check_url" => push_csv(
                &mut global.tcp_check_url,
                &mut tcp_check_url_set,
                &param.val,
            ),
            "tcp_check_http_method" => global.tcp_check_http_method = param.val.clone(),
            "udp_check_dns" => push_csv(
                &mut global.udp_check_dns,
                &mut udp_check_dns_set,
                &param.val,
            ),
            "check_interval" => global.check_interval = decode_param(param, "time.Duration")?,
            "check_tolerance" => global.check_tolerance = decode_param(param, "time.Duration")?,
            "udp_endpoint_pool_size" => global.udp_endpoint_pool_size = decode_param(param, "int")?,
            "lan_interface" => push_optional_csv(
                &mut global.lan_interface,
                &mut lan_interface_set,
                &param.val,
            ),
            "wan_interface" => push_optional_csv(
                &mut global.wan_interface,
                &mut wan_interface_set,
                &param.val,
            ),
            "allow_insecure" => global.allow_insecure = decode_param(param, "bool")?,
            "dial_mode" => global.dial_mode = param.val.clone(),
            "disable_waiting_network" => {
                global.disable_waiting_network = decode_param(param, "bool")?
            }
            "enable_local_tcp_fast_redirect" => {
                global.enable_local_tcp_fast_redirect = decode_param(param, "bool")?;
            }
            "auto_config_kernel_parameter" => {
                global.auto_config_kernel_parameter = decode_param(param, "bool")?;
            }
            "auto_config_firewall_rule" => {
                global.auto_config_firewall_rule = decode_param(param, "bool")?;
            }
            "sniffing_timeout" => global.sniffing_timeout = decode_param(param, "time.Duration")?,
            "tls_implementation" => global.tls_implementation = param.val.clone(),
            "utls_imitate" => global.utls_imitate = param.val.clone(),
            "tls_fragment" => global.tls_fragment = decode_param(param, "bool")?,
            "tls_fragment_length" => global.tls_fragment_length = param.val.clone(),
            "tls_fragment_interval" => global.tls_fragment_interval = param.val.clone(),
            "pprof_port" => global.pprof_port = decode_param(param, "uint16")?,
            "mptcp" => global.mptcp = decode_param(param, "bool")?,
            "fallback_resolver" => global.fallback_resolver = param.val.clone(),
            "bandwidth_max_tx" => global.bandwidth_max_tx = param.val.clone(),
            "bandwidth_max_rx" => global.bandwidth_max_rx = param.val.clone(),
            "udphop_interval" => global.udphop_interval = decode_param(param, "time.Duration")?,
            key => return Err(format!("unexpected key: {key}")),
        }
    }

    Ok(global)
}

fn parse_group_section(section: &Section) -> Result<Vec<Group>, String> {
    let mut groups = Vec::new();
    for item in &section.items {
        let Item::Section(child) = item else {
            return Err(format!("unmatched type: {:?} -> config.Group", item.kind()));
        };
        let mut group = Group::new(child.name.clone());
        parse_group(&mut group, child)
            .map_err(|err| format!("error when parse \"{}\": {err}", child.name))?;
        groups.push(group);
    }
    Ok(groups)
}

fn parse_group(group: &mut Group, section: &Section) -> Result<(), String> {
    let mut policy_set = false;
    let mut tcp_check_url_set = false;
    let mut udp_check_dns_set = false;

    for item in &section.items {
        let Item::Param(param) = item else {
            return Err(unexpected_item_error(section, item));
        };
        reject_naked_param(param)?;
        match param.key.as_str() {
            "filter" => {
                if param.and_functions.is_empty() {
                    return Err(format!(
                        "failed to parse \"filter\": value \"{}\" cannot be convert to [][]*config_parser.Function",
                        param.val
                    ));
                }
                group.filter.push(param.and_functions.clone());
                let annotation = if param.annotation.is_empty() {
                    None
                } else {
                    Some(param.annotation.clone())
                };
                group.filter_annotation.push(annotation);
            }
            "policy" => {
                group.policy = dynamic_from_param(param);
                policy_set = true;
            }
            "tcp_check_url" => {
                reject_function_value(param)?;
                push_optional_csv(&mut group.tcp_check_url, &mut tcp_check_url_set, &param.val);
            }
            "tcp_check_http_method" => {
                reject_function_value(param)?;
                group.tcp_check_http_method = param.val.clone();
            }
            "udp_check_dns" => {
                reject_function_value(param)?;
                push_optional_csv(&mut group.udp_check_dns, &mut udp_check_dns_set, &param.val);
            }
            "check_interval" => {
                reject_function_value(param)?;
                group.check_interval = decode_param(param, "time.Duration")?;
            }
            "check_tolerance" => {
                reject_function_value(param)?;
                group.check_tolerance = decode_param(param, "time.Duration")?;
            }
            key => return Err(format!("unexpected key: {key}")),
        }
    }

    if !policy_set {
        return Err(format!(
            "section \"{}\" requires param \"policy\" but not found",
            section.name
        ));
    }
    Ok(())
}

fn parse_routing(section: &Section) -> Result<Routing, String> {
    let mut routing = Routing::default();
    for item in &section.items {
        match item {
            Item::RoutingRule(rule) => routing.rules.push(rule.clone()),
            Item::Param(param) => {
                reject_naked_param(param)?;
                match param.key.as_str() {
                    "fallback" => routing.fallback = dynamic_from_param(param),
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            _ => return Err(unexpected_item_error(section, item)),
        }
    }
    Ok(routing)
}

fn parse_dns(section: &Section) -> Result<Dns, String> {
    let mut dns = Dns::default();
    for item in &section.items {
        match item {
            Item::Param(param) => {
                reject_naked_param(param)?;
                reject_function_value(param)?;
                match param.key.as_str() {
                    "ipversion_prefer" => dns.ipversion_prefer = decode_param(param, "int")?,
                    "bind" => dns.bind = param.val.clone(),
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            Item::Section(child) => match child.name.as_str() {
                "fixed_domain_ttl" => dns.fixed_domain_ttl = parse_string_section(child)?,
                "upstream" => dns.upstream = parse_string_section(child)?,
                "routing" => dns.routing = parse_dns_routing(child)?,
                key => return Err(format!("unexpected key: {key}")),
            },
            Item::RoutingRule(_) => return Err(unexpected_item_error(section, item)),
        }
    }
    Ok(dns)
}

fn parse_dns_routing(section: &Section) -> Result<DnsRouting, String> {
    let mut routing = DnsRouting::default();
    for item in &section.items {
        let Item::Section(child) = item else {
            return Err(unexpected_item_error(section, item));
        };
        match child.name.as_str() {
            "request" => routing.request = parse_dns_rule_set(child, true)?,
            "response" => routing.response = parse_dns_rule_set(child, true)?,
            key => return Err(format!("unexpected key: {key}")),
        }
    }
    Ok(routing)
}

fn parse_dns_rule_set(
    section: &Section,
    required_when_present: bool,
) -> Result<DnsRuleSet, String> {
    let mut rule_set = DnsRuleSet::default();
    let mut fallback_set = false;
    for item in &section.items {
        match item {
            Item::RoutingRule(rule) => rule_set.rules.push(rule.clone()),
            Item::Param(param) => {
                reject_naked_param(param)?;
                match param.key.as_str() {
                    "fallback" => {
                        rule_set.fallback = dynamic_from_param(param);
                        fallback_set = true;
                    }
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            _ => return Err(unexpected_item_error(section, item)),
        }
    }
    if required_when_present && !fallback_set {
        return Err(format!(
            "section \"{}\" requires param \"fallback\" but not found",
            section.name
        ));
    }
    Ok(rule_set)
}

fn parse_string_section(section: &Section) -> Result<Vec<KeyableString>, String> {
    let mut out = Vec::new();
    for item in &section.items {
        let Item::Param(param) = item else {
            return Err(format!(
                "section {} does not support type {:?}: {}",
                section.name,
                item.kind(),
                item.to_config_string(false, false)
            ));
        };
        out.push(param.to_config_string(true, false));
    }
    Ok(out)
}

fn reject_naked_param(param: &Param) -> Result<(), String> {
    if param.key.is_empty() {
        return Err(format!(
            "unsupported text without a key: {}",
            param.to_config_string(true, false)
        ));
    }
    Ok(())
}

fn reject_function_value(param: &Param) -> Result<(), String> {
    if !param.and_functions.is_empty() {
        return Err(format!(
            "failed to parse \"{}\": value \"{}\" cannot be convert to string",
            param.key, param.val
        ));
    }
    Ok(())
}

fn decode_param<T>(param: &Param, go_type: &str) -> Result<T, String>
where
    T: FuzzyDecode,
{
    reject_function_value(param)?;
    fuzzy_decode::<T>(&param.val).ok_or_else(|| {
        format!(
            "failed to parse \"{}\": value \"{}\" cannot be convert to {}",
            param.key, param.val, go_type
        )
    })
}

fn dynamic_from_param(param: &Param) -> DynamicFunctionValue {
    if param.and_functions.is_empty() {
        DynamicFunctionValue::String(param.val.clone())
    } else {
        DynamicFunctionValue::FunctionList(param.and_functions.clone())
    }
}

fn push_csv(target: &mut Vec<String>, set: &mut bool, value: &str) {
    if !*set {
        target.clear();
        *set = true;
    }
    target.extend(split_csv(value));
}

fn push_optional_csv(target: &mut Option<Vec<String>>, set: &mut bool, value: &str) {
    if !*set {
        *target = Some(Vec::new());
        *set = true;
    }
    target.as_mut().unwrap().extend(split_csv(value));
}

fn split_csv(value: &str) -> Vec<String> {
    value.split(',').map(str::to_owned).collect()
}

fn parse_default_duration(value: &str) -> GoDuration {
    value.parse().unwrap_or_else(|_| {
        if value == "0" {
            GoDuration::default()
        } else {
            panic!("invalid hard-coded Go duration default {value}")
        }
    })
}

fn unexpected_item_error(section: &Section, item: &Item) -> String {
    match item {
        Item::RoutingRule(rule) => format!(
            "cannot use routing rule in this context: {}",
            rule.to_config_string(false, true, false)
        ),
        _ => format!(
            "unexpected type {:?} in section {}: {}",
            item.kind(),
            section.name,
            item.to_config_string(false, false)
        ),
    }
}

fn patch_fallback_resolver(config: &Config) -> Result<(), ConfigError> {
    SocketAddr::from_str(&config.global.fallback_resolver)
        .map(|_| ())
        .map_err(|_| {
            ConfigError::Build(format!(
                "invalid global.fallback_resolver {:?}: not an ip:port",
                config.global.fallback_resolver
            ))
        })
}

fn patch_tcp_check_http_method(config: &mut Config) {
    if !is_valid_http_method(&config.global.tcp_check_http_method) {
        config.global.tcp_check_http_method = "CONNECT".to_owned();
    }
}

fn patch_empty_dns(config: &mut Config) {
    if matches!(
        config.dns.routing.request.fallback,
        DynamicFunctionValue::Nil
    ) {
        config.dns.routing.request.fallback = DynamicFunctionValue::String("asis".to_owned());
    }
    if matches!(
        config.dns.routing.response.fallback,
        DynamicFunctionValue::Nil
    ) {
        config.dns.routing.response.fallback = DynamicFunctionValue::String("accept".to_owned());
    }
}

fn patch_must_outbound(config: &mut Config) -> Result<(), ConfigError> {
    for rule in &mut config.routing.rules {
        if rule.outbound.name.starts_with("must_") {
            if rule.outbound.name == "must_rules" {
                continue;
            }
            rule.outbound.name = rule.outbound.name.trim_start_matches("must_").to_owned();
            rule.outbound.params.push(Param {
                key: String::new(),
                val: "must".to_owned(),
                and_functions: Vec::new(),
                annotation: Vec::new(),
            });
        }
    }

    let mut fallback = dynamic_to_single_function(&config.routing.fallback)
        .map_err(|err| ConfigError::Build(format!("invalid routing fallback: {err}")))?;
    if fallback.name.starts_with("must_") {
        fallback.name = fallback.name.trim_start_matches("must_").to_owned();
        fallback.params.push(Param {
            key: String::new(),
            val: "must".to_owned(),
            and_functions: Vec::new(),
            annotation: Vec::new(),
        });
        config.routing.fallback = DynamicFunctionValue::Function(fallback);
    }
    Ok(())
}

fn dynamic_to_single_function(value: &DynamicFunctionValue) -> Result<Function, String> {
    match value {
        DynamicFunctionValue::String(name) => Ok(Function {
            name: name.clone(),
            not: false,
            params: Vec::new(),
        }),
        DynamicFunctionValue::Function(function) => Ok(function.clone()),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(functions[0].clone())
        }
        DynamicFunctionValue::FunctionList(functions) => Err(format!(
            "expected exactly 1 fallback function, got {}",
            functions.len()
        )),
        DynamicFunctionValue::Nil => Err("unsupported fallback type nil".to_owned()),
    }
}

#[cfg(test)]
mod tests {
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
}
