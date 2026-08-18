use super::input::{InputMode, ItemInput, ParamInput, SectionInput, ValueInput};
use super::*;

pub(crate) fn parse_global<'a, M: InputMode>(
    section: M::Value<'a, Section>,
) -> Result<Global, String> {
    let SectionInput {
        name: section_name,
        items,
    } = M::section_parts(section);
    let mut global = Global::default();
    let mut tcp_check_url_set = false;
    let mut udp_check_dns_set = false;
    let mut lan_interface_set = false;
    let mut wan_interface_set = false;

    for item in items {
        let item = M::item_parts(item);
        let ItemInput::Param(param) = item else {
            return Err(unexpected_item_error(section_name.get(), &item));
        };
        let ParamInput {
            key,
            val,
            and_functions,
            ..
        } = M::param_parts(param);
        reject_naked_value(key.get(), val.get())?;
        reject_function_value_parts(key.get(), val.get(), and_functions.get())?;

        match key.get().as_str() {
            "tproxy_port" => global.tproxy_port = decode_value(key.get(), val.get(), "uint16")?,
            "tproxy_port_protect" => {
                global.tproxy_port_protect = decode_value(key.get(), val.get(), "bool")?
            }
            "so_mark_from_dae" => {
                global.so_mark_from_dae = decode_value(key.get(), val.get(), "uint32")?
            }
            "log_level" => global.log_level = val.take(),
            "tcp_check_url" => {
                push_csv(&mut global.tcp_check_url, &mut tcp_check_url_set, val.get())
            }
            "tcp_check_http_method" => global.tcp_check_http_method = val.take(),
            "udp_check_dns" => {
                push_csv(&mut global.udp_check_dns, &mut udp_check_dns_set, val.get())
            }
            "check_interval" => {
                global.check_interval = decode_value(key.get(), val.get(), "time.Duration")?
            }
            "check_tolerance" => {
                global.check_tolerance = decode_value(key.get(), val.get(), "time.Duration")?
            }
            "udp_endpoint_pool_size" => {
                global.udp_endpoint_pool_size = decode_value(key.get(), val.get(), "int")?
            }
            "lan_interface" => {
                push_optional_csv(&mut global.lan_interface, &mut lan_interface_set, val.get())
            }
            "wan_interface" => {
                push_optional_csv(&mut global.wan_interface, &mut wan_interface_set, val.get())
            }
            "allow_insecure" => global.allow_insecure = decode_value(key.get(), val.get(), "bool")?,
            "dial_mode" => global.dial_mode = val.take(),
            "disable_waiting_network" => {
                global.disable_waiting_network = decode_value(key.get(), val.get(), "bool")?
            }
            "enable_local_tcp_fast_redirect" => {
                global.enable_local_tcp_fast_redirect = decode_value(key.get(), val.get(), "bool")?
            }
            "auto_config_kernel_parameter" => {
                global.auto_config_kernel_parameter = decode_value(key.get(), val.get(), "bool")?
            }
            "auto_config_firewall_rule" => {
                global.auto_config_firewall_rule = decode_value(key.get(), val.get(), "bool")?
            }
            "sniffing_timeout" => {
                global.sniffing_timeout = decode_value(key.get(), val.get(), "time.Duration")?
            }
            "tls_implementation" => global.tls_implementation = val.take(),
            "utls_imitate" => global.utls_imitate = val.take(),
            "tls_fragment" => global.tls_fragment = decode_value(key.get(), val.get(), "bool")?,
            "tls_fragment_length" => global.tls_fragment_length = val.take(),
            "tls_fragment_interval" => global.tls_fragment_interval = val.take(),
            "pprof_port" => global.pprof_port = decode_value(key.get(), val.get(), "uint16")?,
            "mptcp" => global.mptcp = decode_value(key.get(), val.get(), "bool")?,
            "fallback_resolver" => global.fallback_resolver = val.take(),
            "bandwidth_max_tx" => global.bandwidth_max_tx = val.take(),
            "bandwidth_max_rx" => global.bandwidth_max_rx = val.take(),
            "udphop_interval" => {
                global.udphop_interval = decode_value(key.get(), val.get(), "time.Duration")?
            }
            "resident_udp_session_limit" => {
                global.resident_udp_session_limit =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_udp_session_queue_depth" => {
                global.resident_udp_session_queue_depth =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_tcp_flow_stack_bytes" => {
                global.resident_tcp_flow_stack_bytes =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_tcp_runtime_workers" => {
                global.resident_tcp_runtime_workers =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_tcp_connection_limit" => {
                global.resident_tcp_connection_limit =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_dns_upstream_refresh_seconds" => {
                global.resident_dns_upstream_refresh_seconds =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_event_queue_depth" => {
                global.resident_event_queue_depth =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_manual_probe_concurrency" => {
                global.resident_manual_probe_concurrency =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_tcp_probe_timeout_ms" => {
                global.resident_tcp_probe_timeout_ms =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "resident_health_check_concurrency" => {
                global.resident_health_check_concurrency =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "http_queue" => global.http_queue = Some(decode_value(key.get(), val.get(), "uint64")?),
            "http_workers" => {
                global.http_workers = Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "http_worker_stack_bytes" => {
                global.http_worker_stack_bytes = Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "allocator_idle_reclaim_enabled" => {
                global.allocator_idle_reclaim_enabled =
                    Some(decode_value(key.get(), val.get(), "bool")?)
            }
            "allocator_idle_reclaim_sample_interval" => {
                global.allocator_idle_reclaim_sample_interval =
                    Some(decode_value(key.get(), val.get(), "time.Duration")?)
            }
            "allocator_idle_reclaim_min_interval" => {
                global.allocator_idle_reclaim_min_interval =
                    Some(decode_value(key.get(), val.get(), "time.Duration")?)
            }
            "allocator_idle_reclaim_low_traffic_duration" => {
                global.allocator_idle_reclaim_low_traffic_duration =
                    Some(decode_value(key.get(), val.get(), "time.Duration")?)
            }
            "allocator_idle_reclaim_pressure_threshold_bytes" => {
                global.allocator_idle_reclaim_pressure_threshold_bytes =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            "allocator_idle_reclaim_max_traffic_rate_bytes_per_second" => {
                global.allocator_idle_reclaim_max_traffic_rate_bytes_per_second =
                    Some(decode_value(key.get(), val.get(), "uint64")?)
            }
            key => return Err(format!("unexpected key: {key}")),
        }
    }

    Ok(global)
}

pub(crate) fn parse_group_section<'a, M: InputMode>(
    section: M::Value<'a, Section>,
) -> Result<Vec<Group>, String> {
    let SectionInput { items, .. } = M::section_parts(section);
    let mut groups = Vec::new();
    for item in items {
        let item = M::item_parts(item);
        let ItemInput::Section(child) = item else {
            return Err(format!("unmatched type: {:?} -> config.Group", item.kind()));
        };
        groups.push(parse_group::<M>(child)?);
    }
    Ok(groups)
}

fn parse_group<'a, M: InputMode>(section: M::Value<'a, Section>) -> Result<Group, String> {
    let SectionInput { name, items } = M::section_parts(section);
    let mut group = Group::new(name.take());
    if let Err(err) = parse_group_items::<M>(&mut group, items) {
        return Err(format!("error when parse \"{}\": {err}", group.name));
    }
    Ok(group)
}

fn parse_group_items<'a, M: InputMode>(
    group: &mut Group,
    items: impl Iterator<Item = M::Value<'a, Item>>,
) -> Result<(), String> {
    let mut policy_set = false;
    let mut tcp_check_url_set = false;
    let mut udp_check_dns_set = false;

    for item in items {
        let item = M::item_parts(item);
        let ItemInput::Param(param) = item else {
            return Err(unexpected_item_error(&group.name, &item));
        };
        let ParamInput {
            key,
            val,
            and_functions,
            annotation,
        } = M::param_parts(param);
        reject_naked_value(key.get(), val.get())?;
        match key.get().as_str() {
            "filter" => {
                if and_functions.get().is_empty() {
                    return Err(format!(
                        "failed to parse \"filter\": value \"{}\" cannot be convert to [][]*config_parser.Function",
                        val.get()
                    ));
                }
                group.filter.push(and_functions.take());
                let annotation = (!annotation.get().is_empty()).then(|| annotation.take());
                group.filter_annotation.push(annotation);
            }
            "policy" => {
                group.policy = dynamic_from_parts(val.take(), and_functions.take());
                policy_set = true;
            }
            "tcp_check_url" => {
                reject_function_value_parts(key.get(), val.get(), and_functions.get())?;
                push_optional_csv(&mut group.tcp_check_url, &mut tcp_check_url_set, val.get());
            }
            "tcp_check_http_method" => {
                reject_function_value_parts(key.get(), val.get(), and_functions.get())?;
                group.tcp_check_http_method = val.take();
            }
            "udp_check_dns" => {
                reject_function_value_parts(key.get(), val.get(), and_functions.get())?;
                push_optional_csv(&mut group.udp_check_dns, &mut udp_check_dns_set, val.get());
            }
            "check_interval" => {
                reject_function_value_parts(key.get(), val.get(), and_functions.get())?;
                group.check_interval = decode_value(key.get(), val.get(), "time.Duration")?;
            }
            "check_tolerance" => {
                reject_function_value_parts(key.get(), val.get(), and_functions.get())?;
                group.check_tolerance = decode_value(key.get(), val.get(), "time.Duration")?;
            }
            key => return Err(format!("unexpected key: {key}")),
        }
    }

    if !policy_set {
        return Err(format!(
            "section \"{}\" requires param \"policy\" but not found",
            group.name
        ));
    }
    Ok(())
}

pub(crate) fn parse_routing<'a, M: InputMode>(
    section: M::Value<'a, Section>,
) -> Result<Routing, String> {
    let SectionInput {
        name: section_name,
        items,
    } = M::section_parts(section);
    let mut routing = Routing::default();
    for item in items {
        let item = M::item_parts(item);
        match item {
            ItemInput::RoutingRule(rule) => routing.rules.push(rule.take()),
            ItemInput::Param(param) => {
                let ParamInput {
                    key,
                    val,
                    and_functions,
                    ..
                } = M::param_parts(param);
                reject_naked_value(key.get(), val.get())?;
                match key.get().as_str() {
                    "fallback" => {
                        routing.fallback = dynamic_from_parts(val.take(), and_functions.take())
                    }
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            item => return Err(unexpected_item_error(section_name.get(), &item)),
        }
    }
    Ok(routing)
}

pub(crate) fn parse_dns<'a, M: InputMode>(section: M::Value<'a, Section>) -> Result<Dns, String> {
    let SectionInput {
        name: section_name,
        items,
    } = M::section_parts(section);
    let mut dns = Dns::default();
    for item in items {
        let item = M::item_parts(item);
        match item {
            ItemInput::Param(param) => {
                let ParamInput {
                    key,
                    val,
                    and_functions,
                    ..
                } = M::param_parts(param);
                reject_naked_value(key.get(), val.get())?;
                reject_function_value_parts(key.get(), val.get(), and_functions.get())?;
                match key.get().as_str() {
                    "ipversion_prefer" => {
                        dns.ipversion_prefer = decode_value(key.get(), val.get(), "int")?
                    }
                    "bind" => dns.bind = val.take(),
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            ItemInput::Section(child) => match child.get().name.as_str() {
                "fixed_domain_ttl" => dns.fixed_domain_ttl = parse_string_section::<M>(child)?,
                "upstream" => dns.upstream = parse_string_section::<M>(child)?,
                "routing" => dns.routing = parse_dns_routing::<M>(child)?,
                key => return Err(format!("unexpected key: {key}")),
            },
            item => return Err(unexpected_item_error(section_name.get(), &item)),
        }
    }
    Ok(dns)
}

fn parse_dns_routing<'a, M: InputMode>(
    section: M::Value<'a, Section>,
) -> Result<DnsRouting, String> {
    let SectionInput {
        name: section_name,
        items,
    } = M::section_parts(section);
    let mut routing = DnsRouting::default();
    for item in items {
        let item = M::item_parts(item);
        let ItemInput::Section(child) = item else {
            return Err(unexpected_item_error(section_name.get(), &item));
        };
        match child.get().name.as_str() {
            "request" => routing.request = parse_dns_rule_set::<M>(child, true)?,
            "response" => routing.response = parse_dns_rule_set::<M>(child, true)?,
            key => return Err(format!("unexpected key: {key}")),
        }
    }
    Ok(routing)
}

fn parse_dns_rule_set<'a, M: InputMode>(
    section: M::Value<'a, Section>,
    required_when_present: bool,
) -> Result<DnsRuleSet, String> {
    let SectionInput {
        name: section_name,
        items,
    } = M::section_parts(section);
    let mut rule_set = DnsRuleSet::default();
    let mut fallback_set = false;
    for item in items {
        let item = M::item_parts(item);
        match item {
            ItemInput::RoutingRule(rule) => rule_set.rules.push(rule.take()),
            ItemInput::Param(param) => {
                let ParamInput {
                    key,
                    val,
                    and_functions,
                    ..
                } = M::param_parts(param);
                reject_naked_value(key.get(), val.get())?;
                match key.get().as_str() {
                    "fallback" => {
                        rule_set.fallback = dynamic_from_parts(val.take(), and_functions.take());
                        fallback_set = true;
                    }
                    key => return Err(format!("unexpected key: {key}")),
                }
            }
            item => return Err(unexpected_item_error(section_name.get(), &item)),
        }
    }
    if required_when_present && !fallback_set {
        return Err(format!(
            "section \"{}\" requires param \"fallback\" but not found",
            section_name.get()
        ));
    }
    Ok(rule_set)
}

pub(crate) fn parse_string_section<'a, M: InputMode>(
    section: M::Value<'a, Section>,
) -> Result<Vec<KeyableString>, String> {
    let SectionInput {
        name: section_name,
        items,
    } = M::section_parts(section);
    let mut out = Vec::new();
    for item in items {
        let item = M::item_parts(item);
        let ItemInput::Param(param) = item else {
            return Err(format!(
                "section {} does not support type {:?}: {}",
                section_name.get(),
                item.kind(),
                item.to_config_string(false, false)
            ));
        };
        out.push(param.get().to_config_string(true, false));
    }
    Ok(out)
}

fn reject_naked_value(key: &str, val: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err(format!("unsupported text without a key: {val}"));
    }
    Ok(())
}

fn reject_function_value_parts(
    key: &str,
    val: &str,
    and_functions: &[Function],
) -> Result<(), String> {
    if !and_functions.is_empty() {
        return Err(format!(
            "failed to parse \"{key}\": value \"{val}\" cannot be convert to string"
        ));
    }
    Ok(())
}

fn decode_value<T>(key: &str, val: &str, value_type: &str) -> Result<T, String>
where
    T: FuzzyDecode,
{
    fuzzy_decode::<T>(val).ok_or_else(|| {
        format!("failed to parse \"{key}\": value \"{val}\" cannot be convert to {value_type}")
    })
}

fn dynamic_from_parts(val: String, and_functions: Vec<Function>) -> DynamicFunctionValue {
    if and_functions.is_empty() {
        DynamicFunctionValue::String(val)
    } else {
        DynamicFunctionValue::FunctionList(and_functions)
    }
}

fn unexpected_item_error<M: InputMode>(section_name: &str, item: &ItemInput<'_, M>) -> String {
    match item {
        ItemInput::RoutingRule(rule) => format!(
            "cannot use routing rule in this context: {}",
            rule.get().to_config_string(false, true, false)
        ),
        _ => format!(
            "unexpected type {:?} in section {}: {}",
            item.kind(),
            section_name,
            item.to_config_string(false, false)
        ),
    }
}
