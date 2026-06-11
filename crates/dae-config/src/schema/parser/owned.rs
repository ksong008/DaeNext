use super::*;
pub(crate) fn parse_global_owned(section: Section) -> Result<Global, String> {
    let mut global = Global::default();
    let mut tcp_check_url_set = false;
    let mut udp_check_dns_set = false;
    let mut lan_interface_set = false;
    let mut wan_interface_set = false;

    for item in section.items {
        let Item::Param(param) = item else {
            return Err(unexpected_item_error_owned(&section.name, &item));
        };
        let Param {
            key,
            val,
            and_functions,
            ..
        } = param;
        reject_naked_key(&key)?;
        reject_function_value_parts(&key, &val, &and_functions)?;
        match key.as_str() {
            "tproxy_port" => global.tproxy_port = decode_value(&key, &val, "uint16")?,
            "tproxy_port_protect" => global.tproxy_port_protect = decode_value(&key, &val, "bool")?,
            "so_mark_from_dae" => global.so_mark_from_dae = decode_value(&key, &val, "uint32")?,
            "log_level" => global.log_level = val,
            "tcp_check_url" => push_csv(&mut global.tcp_check_url, &mut tcp_check_url_set, &val),
            "tcp_check_http_method" => global.tcp_check_http_method = val,
            "udp_check_dns" => push_csv(&mut global.udp_check_dns, &mut udp_check_dns_set, &val),
            "check_interval" => global.check_interval = decode_value(&key, &val, "time.Duration")?,
            "check_tolerance" => {
                global.check_tolerance = decode_value(&key, &val, "time.Duration")?
            }
            "udp_endpoint_pool_size" => {
                global.udp_endpoint_pool_size = decode_value(&key, &val, "int")?
            }
            "lan_interface" => {
                push_optional_csv(&mut global.lan_interface, &mut lan_interface_set, &val)
            }
            "wan_interface" => {
                push_optional_csv(&mut global.wan_interface, &mut wan_interface_set, &val)
            }
            "allow_insecure" => global.allow_insecure = decode_value(&key, &val, "bool")?,
            "dial_mode" => global.dial_mode = val,
            "disable_waiting_network" => {
                global.disable_waiting_network = decode_value(&key, &val, "bool")?
            }
            "enable_local_tcp_fast_redirect" => {
                global.enable_local_tcp_fast_redirect = decode_value(&key, &val, "bool")?
            }
            "auto_config_kernel_parameter" => {
                global.auto_config_kernel_parameter = decode_value(&key, &val, "bool")?
            }
            "auto_config_firewall_rule" => {
                global.auto_config_firewall_rule = decode_value(&key, &val, "bool")?
            }
            "sniffing_timeout" => {
                global.sniffing_timeout = decode_value(&key, &val, "time.Duration")?
            }
            "tls_implementation" => global.tls_implementation = val,
            "utls_imitate" => global.utls_imitate = val,
            "tls_fragment" => global.tls_fragment = decode_value(&key, &val, "bool")?,
            "tls_fragment_length" => global.tls_fragment_length = val,
            "tls_fragment_interval" => global.tls_fragment_interval = val,
            "pprof_port" => global.pprof_port = decode_value(&key, &val, "uint16")?,
            "mptcp" => global.mptcp = decode_value(&key, &val, "bool")?,
            "fallback_resolver" => global.fallback_resolver = val,
            "bandwidth_max_tx" => global.bandwidth_max_tx = val,
            "bandwidth_max_rx" => global.bandwidth_max_rx = val,
            "udphop_interval" => {
                global.udphop_interval = decode_value(&key, &val, "time.Duration")?
            }
            "resident_udp_session_limit" => {
                global.resident_udp_session_limit = Some(decode_value(&key, &val, "uint64")?)
            }
            "resident_udp_session_queue_depth" => {
                global.resident_udp_session_queue_depth = Some(decode_value(&key, &val, "uint64")?)
            }
            "resident_tcp_flow_stack_bytes" => {
                global.resident_tcp_flow_stack_bytes = Some(decode_value(&key, &val, "uint64")?)
            }
            "resident_event_queue_depth" => {
                global.resident_event_queue_depth = Some(decode_value(&key, &val, "uint64")?)
            }
            "resident_manual_probe_concurrency" => {
                global.resident_manual_probe_concurrency = Some(decode_value(&key, &val, "uint64")?)
            }
            "resident_health_check_concurrency" => {
                global.resident_health_check_concurrency = Some(decode_value(&key, &val, "uint64")?)
            }
            "http_queue" => global.http_queue = Some(decode_value(&key, &val, "uint64")?),
            "http_workers" => global.http_workers = Some(decode_value(&key, &val, "uint64")?),
            "http_worker_stack_bytes" => {
                global.http_worker_stack_bytes = Some(decode_value(&key, &val, "uint64")?)
            }
            "allocator_idle_reclaim_enabled" => {
                global.allocator_idle_reclaim_enabled = Some(decode_value(&key, &val, "bool")?)
            }
            "allocator_idle_reclaim_sample_interval" => {
                global.allocator_idle_reclaim_sample_interval =
                    Some(decode_value(&key, &val, "time.Duration")?)
            }
            "allocator_idle_reclaim_min_interval" => {
                global.allocator_idle_reclaim_min_interval =
                    Some(decode_value(&key, &val, "time.Duration")?)
            }
            "allocator_idle_reclaim_low_traffic_duration" => {
                global.allocator_idle_reclaim_low_traffic_duration =
                    Some(decode_value(&key, &val, "time.Duration")?)
            }
            "allocator_idle_reclaim_pressure_threshold_bytes" => {
                global.allocator_idle_reclaim_pressure_threshold_bytes =
                    Some(decode_value(&key, &val, "uint64")?)
            }
            "allocator_idle_reclaim_max_traffic_rate_bytes_per_second" => {
                global.allocator_idle_reclaim_max_traffic_rate_bytes_per_second =
                    Some(decode_value(&key, &val, "uint64")?)
            }
            key => return Err(format!("unexpected key: {key}")),
        }
    }

    Ok(global)
}

pub(crate) fn parse_group_section_owned(section: Section) -> Result<Vec<Group>, String> {
    let mut groups = Vec::new();
    for item in section.items {
        let Item::Section(child) = item else {
            return Err(format!("unmatched type: {:?} -> config.Group", item.kind()));
        };
        let child = *child;
        let child_name = child.name.clone();
        let mut group = Group::new(child.name.clone());
        parse_group_owned(&mut group, child)
            .map_err(|err| format!("error when parse \"{}\": {err}", child_name))?;
        groups.push(group);
    }
    Ok(groups)
}

pub(crate) fn parse_group_owned(group: &mut Group, section: Section) -> Result<(), String> {
    let mut policy_set = false;
    let mut tcp_check_url_set = false;
    let mut udp_check_dns_set = false;
    let section_name = section.name;

    for item in section.items {
        let Item::Param(param) = item else {
            return Err(unexpected_item_error_owned(&section_name, &item));
        };
        let Param {
            key,
            val,
            and_functions,
            annotation,
        } = param;
        reject_naked_key(&key)?;
        match key.as_str() {
            "filter" => {
                if and_functions.is_empty() {
                    return Err(format!(
                        "failed to parse \"filter\": value \"{}\" cannot be convert to [][]*config_parser.Function",
                        val
                    ));
                }
                group.filter.push(and_functions);
                group
                    .filter_annotation
                    .push((!annotation.is_empty()).then_some(annotation));
            }
            "policy" => {
                group.policy = dynamic_from_parts(val, and_functions);
                policy_set = true;
            }
            "tcp_check_url" => {
                reject_function_value_parts(&key, &val, &and_functions)?;
                push_optional_csv(&mut group.tcp_check_url, &mut tcp_check_url_set, &val);
            }
            "tcp_check_http_method" => {
                reject_function_value_parts(&key, &val, &and_functions)?;
                group.tcp_check_http_method = val;
            }
            "udp_check_dns" => {
                reject_function_value_parts(&key, &val, &and_functions)?;
                push_optional_csv(&mut group.udp_check_dns, &mut udp_check_dns_set, &val);
            }
            "check_interval" => {
                reject_function_value_parts(&key, &val, &and_functions)?;
                group.check_interval = decode_value(&key, &val, "time.Duration")?;
            }
            "check_tolerance" => {
                reject_function_value_parts(&key, &val, &and_functions)?;
                group.check_tolerance = decode_value(&key, &val, "time.Duration")?;
            }
            key => return Err(format!("unexpected key: {key}")),
        }
    }

    if !policy_set {
        return Err(format!(
            "section \"{}\" requires param \"policy\" but not found",
            section_name
        ));
    }
    Ok(())
}

pub(crate) fn parse_routing_owned(section: Section) -> Result<Routing, String> {
    let mut routing = Routing::default();
    let section_name = section.name;
    for item in section.items {
        match item {
            Item::RoutingRule(rule) => routing.rules.push(rule),
            Item::Param(param) => {
                let Param {
                    key,
                    val,
                    and_functions,
                    ..
                } = param;
                reject_naked_key(&key)?;
                match key.as_str() {
                    "fallback" => routing.fallback = dynamic_from_parts(val, and_functions),
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            _ => return Err(unexpected_item_error_owned(&section_name, &item)),
        }
    }
    Ok(routing)
}

pub(crate) fn parse_dns_owned(section: Section) -> Result<Dns, String> {
    let mut dns = Dns::default();
    let section_name = section.name;
    for item in section.items {
        match item {
            Item::Param(param) => {
                let Param {
                    key,
                    val,
                    and_functions,
                    ..
                } = param;
                reject_naked_key(&key)?;
                reject_function_value_parts(&key, &val, &and_functions)?;
                match key.as_str() {
                    "ipversion_prefer" => dns.ipversion_prefer = decode_value(&key, &val, "int")?,
                    "bind" => dns.bind = val,
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            Item::Section(child) => {
                let child = *child;
                match child.name.as_str() {
                    "fixed_domain_ttl" => dns.fixed_domain_ttl = parse_string_section_owned(child)?,
                    "upstream" => dns.upstream = parse_string_section_owned(child)?,
                    "routing" => dns.routing = parse_dns_routing_owned(child)?,
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            Item::RoutingRule(_) => return Err(unexpected_item_error_owned(&section_name, &item)),
        }
    }
    Ok(dns)
}

pub(crate) fn parse_dns_routing_owned(section: Section) -> Result<DnsRouting, String> {
    let mut routing = DnsRouting::default();
    let section_name = section.name;
    for item in section.items {
        let Item::Section(child) = item else {
            return Err(unexpected_item_error_owned(&section_name, &item));
        };
        let child = *child;
        match child.name.as_str() {
            "request" => routing.request = parse_dns_rule_set_owned(child, true)?,
            "response" => routing.response = parse_dns_rule_set_owned(child, true)?,
            key => return Err(format!("unexpected key: {key}")),
        }
    }
    Ok(routing)
}

pub(crate) fn parse_dns_rule_set_owned(
    section: Section,
    required_when_present: bool,
) -> Result<DnsRuleSet, String> {
    let mut rule_set = DnsRuleSet::default();
    let mut fallback_set = false;
    let section_name = section.name;
    for item in section.items {
        match item {
            Item::RoutingRule(rule) => rule_set.rules.push(rule),
            Item::Param(param) => {
                let Param {
                    key,
                    val,
                    and_functions,
                    ..
                } = param;
                reject_naked_key(&key)?;
                match key.as_str() {
                    "fallback" => {
                        rule_set.fallback = dynamic_from_parts(val, and_functions);
                        fallback_set = true;
                    }
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            _ => return Err(unexpected_item_error_owned(&section_name, &item)),
        }
    }
    if required_when_present && !fallback_set {
        return Err(format!(
            "section \"{}\" requires param \"fallback\" but not found",
            section_name
        ));
    }
    Ok(rule_set)
}

pub(crate) fn parse_string_section_owned(section: Section) -> Result<Vec<KeyableString>, String> {
    let mut out = Vec::new();
    let section_name = section.name;
    for item in section.items {
        let Item::Param(param) = item else {
            return Err(format!(
                "section {} does not support type {:?}: {}",
                section_name,
                item.kind(),
                item.to_config_string(false, false)
            ));
        };
        out.push(param.to_config_string(true, false));
    }
    Ok(out)
}
