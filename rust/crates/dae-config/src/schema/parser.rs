use super::utils::*;
use super::*;

pub(super) fn parse_global(section: &Section) -> Result<Global, String> {
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

pub(super) fn parse_group_section(section: &Section) -> Result<Vec<Group>, String> {
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

pub(super) fn parse_routing(section: &Section) -> Result<Routing, String> {
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

pub(super) fn parse_dns(section: &Section) -> Result<Dns, String> {
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

pub(super) fn parse_string_section(section: &Section) -> Result<Vec<KeyableString>, String> {
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
