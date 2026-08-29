use crate::rendering::dae_string_literal;
use dae_config::parser::parse_config;
use dae_config::{Item, Section};
use serde_json::{Value, json};
use std::collections::HashMap;

pub(crate) fn parse_global_directives(raw: &str) -> HashMap<String, String> {
    let body = global_block_body(raw).unwrap_or(raw);
    let mut directives = HashMap::new();
    for line in body.lines() {
        let line = strip_line_comment(line).trim();
        if line.is_empty() || line == "{" || line == "}" {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(',').to_owned();
        if key.is_empty() {
            continue;
        }
        directives.insert(key, clean_global_scalar(value));
    }
    directives
}

pub(crate) fn parse_global_directives_with_config_parser(
    raw: &str,
) -> Result<HashMap<String, String>, String> {
    let sections = parse_config(raw).or_else(|raw_err| {
        let wrapped = format!("global {{\n{raw}\n}}");
        parse_config(&wrapped)
            .map_err(|wrapped_err| format!("{raw_err}; wrapped global body: {wrapped_err}"))
    })?;
    let global = sections
        .iter()
        .find(|section| section.name == "global")
        .ok_or_else(|| "global section not found".to_owned())?;
    global_directives_from_section(global)
}

pub(crate) fn global_text_needs_config_parser(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.starts_with('#') {
        return true;
    }
    if trimmed.contains('\n') {
        return false;
    }
    let body = global_block_body(trimmed).unwrap_or(trimmed);
    if contains_quoted_global_block_delimiter(body) {
        return true;
    }
    global_body_contains_inline_directive(body)
}

fn global_directives_from_section(section: &Section) -> Result<HashMap<String, String>, String> {
    let mut directives = HashMap::new();
    for item in &section.items {
        let Item::Param(param) = item else {
            return Err(format!(
                "unexpected global item kind {:?}; expected parameter",
                item.kind()
            ));
        };
        if param.key.trim().is_empty() {
            return Err("unexpected naked global parameter".to_owned());
        }
        if !param.and_functions.is_empty() {
            return Err(format!(
                "unexpected function value for global.{}",
                param.key
            ));
        }
        directives.insert(param.key.clone(), param.val.clone());
    }
    Ok(directives)
}

fn contains_quoted_global_block_delimiter(raw: &str) -> bool {
    let mut quote = None;
    for ch in raw.chars() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '{' | '}' if quote.is_some() => return true,
            _ => {}
        }
    }
    false
}

fn global_body_contains_inline_directive(body: &str) -> bool {
    body.lines().any(|line| {
        let line = strip_line_comment(line);
        let Some((_, value)) = line.split_once(':') else {
            return false;
        };
        contains_global_directive_key_after_whitespace(value)
    })
}

fn contains_global_directive_key_after_whitespace(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0_usize;
    let mut quote = None;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'\'' | b'"' if quote == Some(byte) => {
                quote = None;
                index += 1;
            }
            b'\'' | b'"' if quote.is_none() => {
                quote = Some(byte);
                index += 1;
            }
            byte if quote.is_none() && byte.is_ascii_whitespace() => {
                let mut ident_start = index + 1;
                while ident_start < bytes.len() && bytes[ident_start].is_ascii_whitespace() {
                    ident_start += 1;
                }
                let mut ident_end = ident_start;
                while ident_end < bytes.len()
                    && (bytes[ident_end].is_ascii_alphanumeric() || bytes[ident_end] == b'_')
                {
                    ident_end += 1;
                }
                let mut colon = ident_end;
                while colon < bytes.len() && bytes[colon].is_ascii_whitespace() {
                    colon += 1;
                }
                if colon < bytes.len()
                    && bytes[colon] == b':'
                    && ident_start < ident_end
                    && is_identifier_start(bytes[ident_start])
                {
                    return true;
                }
                index = ident_end.max(index + 1);
            }
            _ => index += 1,
        }
    }
    false
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

pub(crate) fn global_block_body(raw: &str) -> Option<&str> {
    let start = raw.find("global")?;
    let open = raw[start..].find('{')? + start;
    let bytes = raw.as_bytes();
    let mut depth = 0_i32;
    let mut close = None;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(idx);
                    break;
                }
            }
            _ => {}
        }
    }
    close.and_then(|close| raw.get(open + 1..close))
}

pub(crate) fn strip_line_comment(line: &str) -> &str {
    let mut quote = None;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '#' if quote.is_none() => return &line[..idx],
            _ => {}
        }
    }
    line
}

pub(crate) fn clean_global_scalar(value: &str) -> String {
    let value = value.trim().trim_end_matches(',').trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value);
    value.trim().to_owned()
}

pub(crate) fn directive_string(directives: &HashMap<String, String>, key: &str) -> Option<String> {
    directives
        .get(key)
        .cloned()
        .filter(|value| !value.is_empty())
}

pub(crate) fn directive_bool(directives: &HashMap<String, String>, key: &str) -> Option<bool> {
    directives.get(key).and_then(|value| parse_boolish(value))
}

pub(crate) fn directive_u64(directives: &HashMap<String, String>, key: &str) -> Option<u64> {
    directives
        .get(key)
        .and_then(|value| value.trim().parse::<u64>().ok())
}

pub(crate) fn directive_array(
    directives: &HashMap<String, String>,
    key: &str,
) -> Option<Vec<String>> {
    directives
        .get(key)
        .map(|value| split_global_list(value))
        .filter(|values| !values.is_empty())
}

pub(crate) fn split_global_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn json_value_by_keys<'a>(source: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| source.get(*key))
}

pub(crate) fn json_string(source: &Value, keys: &[&str]) -> Option<String> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

pub(crate) fn json_bool(source: &Value, keys: &[&str]) -> Option<bool> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => parse_boolish(value),
        _ => None,
    })
}

pub(crate) fn json_u64(source: &Value, keys: &[&str]) -> Option<u64> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    })
}

pub(crate) fn json_array_or_split_string(source: &Value, keys: &[&str]) -> Option<Vec<String>> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Array(values) => {
            let out = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            (!out.is_empty()).then_some(out)
        }
        Value::String(value) => {
            let out = split_global_list(value);
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    })
}

pub fn parse_boolish(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

pub(crate) fn set_global_string(target: &mut Value, key: &str, value: Option<String>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

pub(crate) fn set_global_bool(target: &mut Value, key: &str, value: Option<bool>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

pub(crate) fn set_global_u64(target: &mut Value, key: &str, value: Option<u64>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

pub(crate) fn set_global_array(target: &mut Value, key: &str, value: Option<Vec<String>>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

pub(crate) fn default_global_value() -> Value {
    json!({})
}

pub(crate) fn merge_global_json_value(target: &mut Value, source: &Value) {
    set_global_string(
        target,
        "logLevel",
        json_string(source, &["logLevel", "log_level"]),
    );
    set_global_u64(
        target,
        "tproxyPort",
        json_u64(source, &["tproxyPort", "tproxy_port"]),
    );
    set_global_bool(
        target,
        "allowInsecure",
        json_bool(source, &["allowInsecure", "allow_insecure"]),
    );
    set_global_string(
        target,
        "checkInterval",
        json_string(source, &["checkInterval", "check_interval"]),
    );
    set_global_string(
        target,
        "checkTolerance",
        json_string(source, &["checkTolerance", "check_tolerance"]),
    );
    set_global_array(
        target,
        "lanInterface",
        json_array_or_split_string(source, &["lanInterface", "lan_interface"]),
    );
    set_global_array(
        target,
        "wanInterface",
        json_array_or_split_string(source, &["wanInterface", "wan_interface"]),
    );
    set_global_array(
        target,
        "udpCheckDns",
        json_array_or_split_string(source, &["udpCheckDns", "udp_check_dns"]),
    );
    set_global_array(
        target,
        "tcpCheckUrl",
        json_array_or_split_string(source, &["tcpCheckUrl", "tcp_check_url"]),
    );
    set_global_string(
        target,
        "fallbackResolver",
        json_string(source, &["fallbackResolver", "fallback_resolver"]),
    );
    set_global_string(
        target,
        "dialMode",
        json_string(source, &["dialMode", "dial_mode"]),
    );
    set_global_string(
        target,
        "tcpCheckHttpMethod",
        json_string(source, &["tcpCheckHttpMethod", "tcp_check_http_method"]),
    );
    set_global_u64(
        target,
        "udpEndpointPoolSize",
        json_u64(source, &["udpEndpointPoolSize", "udp_endpoint_pool_size"]),
    );
    set_global_bool(
        target,
        "disableWaitingNetwork",
        json_bool(
            source,
            &["disableWaitingNetwork", "disable_waiting_network"],
        ),
    );
    set_global_bool(
        target,
        "autoConfigKernelParameter",
        json_bool(
            source,
            &["autoConfigKernelParameter", "auto_config_kernel_parameter"],
        ),
    );
    set_global_bool(
        target,
        "autoConfigFirewallRule",
        json_bool(
            source,
            &["autoConfigFirewallRule", "auto_config_firewall_rule"],
        ),
    );
    set_global_string(
        target,
        "sniffingTimeout",
        json_string(source, &["sniffingTimeout", "sniffing_timeout"]),
    );
    set_global_string(
        target,
        "tlsImplementation",
        json_string(source, &["tlsImplementation", "tls_implementation"]),
    );
    set_global_string(
        target,
        "utlsImitate",
        json_string(source, &["utlsImitate", "utls_imitate"]),
    );
    set_global_bool(
        target,
        "tlsFragment",
        json_bool(source, &["tlsFragment", "tls_fragment"]),
    );
    set_global_string(
        target,
        "tlsFragmentLength",
        json_string(source, &["tlsFragmentLength", "tls_fragment_length"]),
    );
    set_global_string(
        target,
        "tlsFragmentInterval",
        json_string(source, &["tlsFragmentInterval", "tls_fragment_interval"]),
    );
    set_global_bool(
        target,
        "tproxyPortProtect",
        json_bool(source, &["tproxyPortProtect", "tproxy_port_protect"]),
    );
    set_global_u64(
        target,
        "soMarkFromDae",
        json_u64(source, &["soMarkFromDae", "so_mark_from_dae"]),
    );
    set_global_u64(
        target,
        "pprofPort",
        json_u64(source, &["pprofPort", "pprof_port"]),
    );
    set_global_bool(
        target,
        "enableLocalTcpFastRedirect",
        json_bool(
            source,
            &[
                "enableLocalTcpFastRedirect",
                "enable_local_tcp_fast_redirect",
            ],
        ),
    );
    set_global_bool(target, "mptcp", json_bool(source, &["mptcp"]));
    set_global_string(
        target,
        "bandwidthMaxTx",
        json_string(source, &["bandwidthMaxTx", "bandwidth_max_tx"]),
    );
    set_global_string(
        target,
        "bandwidthMaxRx",
        json_string(source, &["bandwidthMaxRx", "bandwidth_max_rx"]),
    );
    set_global_string(
        target,
        "udphopInterval",
        json_string(source, &["udphopInterval", "udphop_interval"]),
    );
    set_global_u64(
        target,
        "residentUdpSessionLimit",
        json_u64(
            source,
            &["residentUdpSessionLimit", "resident_udp_session_limit"],
        ),
    );
    set_global_u64(
        target,
        "residentUdpSessionQueueDepth",
        json_u64(
            source,
            &[
                "residentUdpSessionQueueDepth",
                "resident_udp_session_queue_depth",
            ],
        ),
    );
    set_global_u64(
        target,
        "residentTcpFlowStackBytes",
        json_u64(
            source,
            &["residentTcpFlowStackBytes", "resident_tcp_flow_stack_bytes"],
        ),
    );
    set_global_u64(
        target,
        "residentTcpRuntimeWorkers",
        json_u64(
            source,
            &["residentTcpRuntimeWorkers", "resident_tcp_runtime_workers"],
        ),
    );
    set_global_u64(
        target,
        "residentTcpConnectionLimit",
        json_u64(
            source,
            &[
                "residentTcpConnectionLimit",
                "resident_tcp_connection_limit",
            ],
        ),
    );
    set_global_u64(
        target,
        "residentDnsUpstreamRefreshSeconds",
        json_u64(
            source,
            &[
                "residentDnsUpstreamRefreshSeconds",
                "resident_dns_upstream_refresh_seconds",
            ],
        ),
    );
    set_global_u64(
        target,
        "residentEventQueueDepth",
        json_u64(
            source,
            &["residentEventQueueDepth", "resident_event_queue_depth"],
        ),
    );
    set_global_u64(
        target,
        "residentManualProbeConcurrency",
        json_u64(
            source,
            &[
                "residentManualProbeConcurrency",
                "resident_manual_probe_concurrency",
            ],
        ),
    );
    set_global_u64(
        target,
        "residentTcpProbeTimeoutMs",
        json_u64(
            source,
            &["residentTcpProbeTimeoutMs", "resident_tcp_probe_timeout_ms"],
        ),
    );
    set_global_u64(
        target,
        "residentHealthCheckConcurrency",
        json_u64(
            source,
            &[
                "residentHealthCheckConcurrency",
                "resident_health_check_concurrency",
            ],
        ),
    );
    set_global_u64(
        target,
        "httpQueue",
        json_u64(source, &["httpQueue", "http_queue"]),
    );
    set_global_u64(
        target,
        "httpWorkers",
        json_u64(source, &["httpWorkers", "http_workers"]),
    );
    set_global_u64(
        target,
        "httpWorkerStackBytes",
        json_u64(source, &["httpWorkerStackBytes", "http_worker_stack_bytes"]),
    );
    set_global_bool(
        target,
        "allocatorIdleReclaimEnabled",
        json_bool(
            source,
            &[
                "allocatorIdleReclaimEnabled",
                "allocator_idle_reclaim_enabled",
            ],
        ),
    );
    set_global_string(
        target,
        "allocatorIdleReclaimSampleInterval",
        json_string(
            source,
            &[
                "allocatorIdleReclaimSampleInterval",
                "allocator_idle_reclaim_sample_interval",
            ],
        ),
    );
    set_global_string(
        target,
        "allocatorIdleReclaimMinInterval",
        json_string(
            source,
            &[
                "allocatorIdleReclaimMinInterval",
                "allocator_idle_reclaim_min_interval",
            ],
        ),
    );
    set_global_string(
        target,
        "allocatorIdleReclaimLowTrafficDuration",
        json_string(
            source,
            &[
                "allocatorIdleReclaimLowTrafficDuration",
                "allocator_idle_reclaim_low_traffic_duration",
            ],
        ),
    );
    set_global_u64(
        target,
        "allocatorIdleReclaimPressureThresholdBytes",
        json_u64(
            source,
            &[
                "allocatorIdleReclaimPressureThresholdBytes",
                "allocator_idle_reclaim_pressure_threshold_bytes",
            ],
        ),
    );
    set_global_u64(
        target,
        "allocatorIdleReclaimMaxTrafficRateBytesPerSecond",
        json_u64(
            source,
            &[
                "allocatorIdleReclaimMaxTrafficRateBytesPerSecond",
                "allocator_idle_reclaim_max_traffic_rate_bytes_per_second",
            ],
        ),
    );
}

pub(crate) fn merge_global_directives(target: &mut Value, directives: &HashMap<String, String>) {
    set_global_string(
        target,
        "logLevel",
        directive_string(directives, "log_level"),
    );
    set_global_u64(
        target,
        "tproxyPort",
        directive_u64(directives, "tproxy_port"),
    );
    set_global_bool(
        target,
        "allowInsecure",
        directive_bool(directives, "allow_insecure"),
    );
    set_global_string(
        target,
        "checkInterval",
        directive_string(directives, "check_interval"),
    );
    set_global_string(
        target,
        "checkTolerance",
        directive_string(directives, "check_tolerance"),
    );
    set_global_array(
        target,
        "lanInterface",
        directive_array(directives, "lan_interface"),
    );
    set_global_array(
        target,
        "wanInterface",
        directive_array(directives, "wan_interface"),
    );
    set_global_array(
        target,
        "udpCheckDns",
        directive_array(directives, "udp_check_dns"),
    );
    set_global_array(
        target,
        "tcpCheckUrl",
        directive_array(directives, "tcp_check_url"),
    );
    set_global_string(
        target,
        "fallbackResolver",
        directive_string(directives, "fallback_resolver"),
    );
    set_global_string(
        target,
        "dialMode",
        directive_string(directives, "dial_mode"),
    );
    set_global_string(
        target,
        "tcpCheckHttpMethod",
        directive_string(directives, "tcp_check_http_method"),
    );
    set_global_u64(
        target,
        "udpEndpointPoolSize",
        directive_u64(directives, "udp_endpoint_pool_size"),
    );
    set_global_bool(
        target,
        "disableWaitingNetwork",
        directive_bool(directives, "disable_waiting_network"),
    );
    set_global_bool(
        target,
        "autoConfigKernelParameter",
        directive_bool(directives, "auto_config_kernel_parameter"),
    );
    set_global_bool(
        target,
        "autoConfigFirewallRule",
        directive_bool(directives, "auto_config_firewall_rule"),
    );
    set_global_string(
        target,
        "sniffingTimeout",
        directive_string(directives, "sniffing_timeout"),
    );
    set_global_string(
        target,
        "tlsImplementation",
        directive_string(directives, "tls_implementation"),
    );
    set_global_string(
        target,
        "utlsImitate",
        directive_string(directives, "utls_imitate"),
    );
    set_global_bool(
        target,
        "tlsFragment",
        directive_bool(directives, "tls_fragment"),
    );
    set_global_string(
        target,
        "tlsFragmentLength",
        directive_string(directives, "tls_fragment_length"),
    );
    set_global_string(
        target,
        "tlsFragmentInterval",
        directive_string(directives, "tls_fragment_interval"),
    );
    set_global_bool(
        target,
        "tproxyPortProtect",
        directive_bool(directives, "tproxy_port_protect"),
    );
    set_global_u64(
        target,
        "soMarkFromDae",
        directive_u64(directives, "so_mark_from_dae"),
    );
    set_global_u64(target, "pprofPort", directive_u64(directives, "pprof_port"));
    set_global_bool(
        target,
        "enableLocalTcpFastRedirect",
        directive_bool(directives, "enable_local_tcp_fast_redirect"),
    );
    set_global_bool(target, "mptcp", directive_bool(directives, "mptcp"));
    set_global_string(
        target,
        "bandwidthMaxTx",
        directive_string(directives, "bandwidth_max_tx"),
    );
    set_global_string(
        target,
        "bandwidthMaxRx",
        directive_string(directives, "bandwidth_max_rx"),
    );
    set_global_string(
        target,
        "udphopInterval",
        directive_string(directives, "udphop_interval"),
    );
    set_global_u64(
        target,
        "residentUdpSessionLimit",
        directive_u64(directives, "resident_udp_session_limit"),
    );
    set_global_u64(
        target,
        "residentUdpSessionQueueDepth",
        directive_u64(directives, "resident_udp_session_queue_depth"),
    );
    set_global_u64(
        target,
        "residentTcpFlowStackBytes",
        directive_u64(directives, "resident_tcp_flow_stack_bytes"),
    );
    set_global_u64(
        target,
        "residentTcpRuntimeWorkers",
        directive_u64(directives, "resident_tcp_runtime_workers"),
    );
    set_global_u64(
        target,
        "residentTcpConnectionLimit",
        directive_u64(directives, "resident_tcp_connection_limit"),
    );
    set_global_u64(
        target,
        "residentDnsUpstreamRefreshSeconds",
        directive_u64(directives, "resident_dns_upstream_refresh_seconds"),
    );
    set_global_u64(
        target,
        "residentEventQueueDepth",
        directive_u64(directives, "resident_event_queue_depth"),
    );
    set_global_u64(
        target,
        "residentManualProbeConcurrency",
        directive_u64(directives, "resident_manual_probe_concurrency"),
    );
    set_global_u64(
        target,
        "residentTcpProbeTimeoutMs",
        directive_u64(directives, "resident_tcp_probe_timeout_ms"),
    );
    set_global_u64(
        target,
        "residentHealthCheckConcurrency",
        directive_u64(directives, "resident_health_check_concurrency"),
    );
    set_global_u64(target, "httpQueue", directive_u64(directives, "http_queue"));
    set_global_u64(
        target,
        "httpWorkers",
        directive_u64(directives, "http_workers"),
    );
    set_global_u64(
        target,
        "httpWorkerStackBytes",
        directive_u64(directives, "http_worker_stack_bytes"),
    );
    set_global_bool(
        target,
        "allocatorIdleReclaimEnabled",
        directive_bool(directives, "allocator_idle_reclaim_enabled"),
    );
    set_global_string(
        target,
        "allocatorIdleReclaimSampleInterval",
        directive_string(directives, "allocator_idle_reclaim_sample_interval"),
    );
    set_global_string(
        target,
        "allocatorIdleReclaimMinInterval",
        directive_string(directives, "allocator_idle_reclaim_min_interval"),
    );
    set_global_string(
        target,
        "allocatorIdleReclaimLowTrafficDuration",
        directive_string(directives, "allocator_idle_reclaim_low_traffic_duration"),
    );
    set_global_u64(
        target,
        "allocatorIdleReclaimPressureThresholdBytes",
        directive_u64(
            directives,
            "allocator_idle_reclaim_pressure_threshold_bytes",
        ),
    );
    set_global_u64(
        target,
        "allocatorIdleReclaimMaxTrafficRateBytesPerSecond",
        directive_u64(
            directives,
            "allocator_idle_reclaim_max_traffic_rate_bytes_per_second",
        ),
    );
}

pub struct GlobalNormalizeResult {
    pub value: Value,
    pub parse_status: &'static str,
    pub parse_error: Option<String>,
}
pub fn normalize_global_value(raw: Option<&str>) -> Value {
    normalize_global_result(raw).value
}

pub fn normalize_global_result(raw: Option<&str>) -> GlobalNormalizeResult {
    let mut value = default_global_value();
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return GlobalNormalizeResult::ok(value);
    };
    if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
        merge_global_json_value(&mut value, &parsed);
        return GlobalNormalizeResult::ok(value);
    }
    if global_text_needs_config_parser(raw) {
        match parse_global_directives_with_config_parser(raw) {
            Ok(directives) => {
                merge_global_directives(&mut value, &directives);
                return GlobalNormalizeResult::ok(value);
            }
            Err(err) => {
                merge_global_directives(&mut value, &parse_global_directives(raw));
                return GlobalNormalizeResult::fallback(value, err);
            }
        }
    }
    merge_global_directives(&mut value, &parse_global_directives(raw));
    GlobalNormalizeResult::ok(value)
}

impl GlobalNormalizeResult {
    fn ok(value: Value) -> Self {
        Self {
            value,
            parse_status: "ok",
            parse_error: None,
        }
    }

    fn fallback(value: Value, parse_error: String) -> Self {
        Self {
            value,
            parse_status: "fallback",
            parse_error: Some(parse_error),
        }
    }
}

pub fn display_global_config_text(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return "global {}\n".to_owned();
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => render_global_config_text(&Value::Object(map)),
        _ => raw.to_owned(),
    }
}

pub fn render_global_config_text(source: &Value) -> String {
    if let Some(raw) = source.as_str() {
        return display_global_config_text(raw);
    }
    let normalized = normalize_global_value(Some(&source.to_string()));
    let mut lines = Vec::new();
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "tproxyPort",
        "tproxy_port",
        &["tproxyPort", "tproxy_port"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "tproxyPortProtect",
        "tproxy_port_protect",
        &["tproxyPortProtect", "tproxy_port_protect"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "soMarkFromDae",
        "so_mark_from_dae",
        &["soMarkFromDae", "so_mark_from_dae"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "logLevel",
        "log_level",
        &["logLevel", "log_level"],
    );
    push_global_array_field(
        &mut lines,
        &normalized,
        source,
        "tcpCheckUrl",
        "tcp_check_url",
        &["tcpCheckUrl", "tcp_check_url"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "tcpCheckHttpMethod",
        "tcp_check_http_method",
        &["tcpCheckHttpMethod", "tcp_check_http_method"],
    );
    push_global_array_field(
        &mut lines,
        &normalized,
        source,
        "udpCheckDns",
        "udp_check_dns",
        &["udpCheckDns", "udp_check_dns"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "checkInterval",
        "check_interval",
        &["checkInterval", "check_interval"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "checkTolerance",
        "check_tolerance",
        &["checkTolerance", "check_tolerance"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "udpEndpointPoolSize",
        "udp_endpoint_pool_size",
        &["udpEndpointPoolSize", "udp_endpoint_pool_size"],
    );
    push_global_array_field(
        &mut lines,
        &normalized,
        source,
        "lanInterface",
        "lan_interface",
        &["lanInterface", "lan_interface"],
    );
    push_global_array_field(
        &mut lines,
        &normalized,
        source,
        "wanInterface",
        "wan_interface",
        &["wanInterface", "wan_interface"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "allowInsecure",
        "allow_insecure",
        &["allowInsecure", "allow_insecure"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "dialMode",
        "dial_mode",
        &["dialMode", "dial_mode"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "disableWaitingNetwork",
        "disable_waiting_network",
        &["disableWaitingNetwork", "disable_waiting_network"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "enableLocalTcpFastRedirect",
        "enable_local_tcp_fast_redirect",
        &[
            "enableLocalTcpFastRedirect",
            "enable_local_tcp_fast_redirect",
        ],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "autoConfigKernelParameter",
        "auto_config_kernel_parameter",
        &["autoConfigKernelParameter", "auto_config_kernel_parameter"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "autoConfigFirewallRule",
        "auto_config_firewall_rule",
        &["autoConfigFirewallRule", "auto_config_firewall_rule"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "sniffingTimeout",
        "sniffing_timeout",
        &["sniffingTimeout", "sniffing_timeout"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "tlsImplementation",
        "tls_implementation",
        &["tlsImplementation", "tls_implementation"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "utlsImitate",
        "utls_imitate",
        &["utlsImitate", "utls_imitate"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "tlsFragment",
        "tls_fragment",
        &["tlsFragment", "tls_fragment"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "tlsFragmentLength",
        "tls_fragment_length",
        &["tlsFragmentLength", "tls_fragment_length"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "tlsFragmentInterval",
        "tls_fragment_interval",
        &["tlsFragmentInterval", "tls_fragment_interval"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "pprofPort",
        "pprof_port",
        &["pprofPort", "pprof_port"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "mptcp",
        "mptcp",
        &["mptcp"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "fallbackResolver",
        "fallback_resolver",
        &["fallbackResolver", "fallback_resolver"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "bandwidthMaxTx",
        "bandwidth_max_tx",
        &["bandwidthMaxTx", "bandwidth_max_tx"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "bandwidthMaxRx",
        "bandwidth_max_rx",
        &["bandwidthMaxRx", "bandwidth_max_rx"],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "udphopInterval",
        "udphop_interval",
        &["udphopInterval", "udphop_interval"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentUdpSessionLimit",
        "resident_udp_session_limit",
        &["residentUdpSessionLimit", "resident_udp_session_limit"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentUdpSessionQueueDepth",
        "resident_udp_session_queue_depth",
        &[
            "residentUdpSessionQueueDepth",
            "resident_udp_session_queue_depth",
        ],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentTcpFlowStackBytes",
        "resident_tcp_flow_stack_bytes",
        &["residentTcpFlowStackBytes", "resident_tcp_flow_stack_bytes"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentTcpRuntimeWorkers",
        "resident_tcp_runtime_workers",
        &["residentTcpRuntimeWorkers", "resident_tcp_runtime_workers"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentTcpConnectionLimit",
        "resident_tcp_connection_limit",
        &[
            "residentTcpConnectionLimit",
            "resident_tcp_connection_limit",
        ],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentDnsUpstreamRefreshSeconds",
        "resident_dns_upstream_refresh_seconds",
        &[
            "residentDnsUpstreamRefreshSeconds",
            "resident_dns_upstream_refresh_seconds",
        ],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentEventQueueDepth",
        "resident_event_queue_depth",
        &["residentEventQueueDepth", "resident_event_queue_depth"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentManualProbeConcurrency",
        "resident_manual_probe_concurrency",
        &[
            "residentManualProbeConcurrency",
            "resident_manual_probe_concurrency",
        ],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentTcpProbeTimeoutMs",
        "resident_tcp_probe_timeout_ms",
        &["residentTcpProbeTimeoutMs", "resident_tcp_probe_timeout_ms"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "residentHealthCheckConcurrency",
        "resident_health_check_concurrency",
        &[
            "residentHealthCheckConcurrency",
            "resident_health_check_concurrency",
        ],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "httpQueue",
        "http_queue",
        &["httpQueue", "http_queue"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "httpWorkers",
        "http_workers",
        &["httpWorkers", "http_workers"],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "httpWorkerStackBytes",
        "http_worker_stack_bytes",
        &["httpWorkerStackBytes", "http_worker_stack_bytes"],
    );
    push_global_bool_field(
        &mut lines,
        &normalized,
        source,
        "allocatorIdleReclaimEnabled",
        "allocator_idle_reclaim_enabled",
        &[
            "allocatorIdleReclaimEnabled",
            "allocator_idle_reclaim_enabled",
        ],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "allocatorIdleReclaimSampleInterval",
        "allocator_idle_reclaim_sample_interval",
        &[
            "allocatorIdleReclaimSampleInterval",
            "allocator_idle_reclaim_sample_interval",
        ],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "allocatorIdleReclaimMinInterval",
        "allocator_idle_reclaim_min_interval",
        &[
            "allocatorIdleReclaimMinInterval",
            "allocator_idle_reclaim_min_interval",
        ],
    );
    push_global_string_field(
        &mut lines,
        &normalized,
        source,
        "allocatorIdleReclaimLowTrafficDuration",
        "allocator_idle_reclaim_low_traffic_duration",
        &[
            "allocatorIdleReclaimLowTrafficDuration",
            "allocator_idle_reclaim_low_traffic_duration",
        ],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "allocatorIdleReclaimPressureThresholdBytes",
        "allocator_idle_reclaim_pressure_threshold_bytes",
        &[
            "allocatorIdleReclaimPressureThresholdBytes",
            "allocator_idle_reclaim_pressure_threshold_bytes",
        ],
    );
    push_global_u64_field(
        &mut lines,
        &normalized,
        source,
        "allocatorIdleReclaimMaxTrafficRateBytesPerSecond",
        "allocator_idle_reclaim_max_traffic_rate_bytes_per_second",
        &[
            "allocatorIdleReclaimMaxTrafficRateBytesPerSecond",
            "allocator_idle_reclaim_max_traffic_rate_bytes_per_second",
        ],
    );

    if lines.is_empty() {
        return "global {}\n".to_owned();
    }
    let mut out = String::from("global {\n");
    for line in lines {
        out.push_str("  ");
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

pub(crate) fn push_global_string_field(
    lines: &mut Vec<String>,
    normalized: &Value,
    _source: &Value,
    json_key: &str,
    config_key: &str,
    _aliases: &[&str],
) {
    let value = normalized
        .get(json_key)
        .and_then(Value::as_str)
        .unwrap_or("");
    if !value.is_empty() {
        lines.push(format!("{config_key}:{}", dae_string_literal(value)));
    }
}

pub(crate) fn push_global_array_field(
    lines: &mut Vec<String>,
    normalized: &Value,
    _source: &Value,
    json_key: &str,
    config_key: &str,
    _aliases: &[&str],
) {
    let values = normalized
        .get(json_key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !values.is_empty() {
        lines.push(format!(
            "{config_key}:{}",
            dae_string_literal(&values.join(","))
        ));
    }
}

pub(crate) fn push_global_bool_field(
    lines: &mut Vec<String>,
    normalized: &Value,
    source: &Value,
    json_key: &str,
    config_key: &str,
    aliases: &[&str],
) {
    let value = normalized
        .get(json_key)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if global_source_has_key(source, aliases) || value {
        lines.push(format!(
            "{config_key}:{}",
            dae_string_literal(&value.to_string())
        ));
    }
}

pub(crate) fn push_global_u64_field(
    lines: &mut Vec<String>,
    normalized: &Value,
    source: &Value,
    json_key: &str,
    config_key: &str,
    aliases: &[&str],
) {
    let value = normalized
        .get(json_key)
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if global_source_has_key(source, aliases) || value != 0 {
        lines.push(format!(
            "{config_key}:{}",
            dae_string_literal(&value.to_string())
        ));
    }
}

pub(crate) fn global_source_has_key(source: &Value, aliases: &[&str]) -> bool {
    aliases.iter().any(|alias| source.get(*alias).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_json_global_values() {
        let normalized = normalize_global_value(Some(r#"{"tproxyPort":12345,"mptcp":true}"#));
        assert_eq!(normalized["tproxyPort"], 12345);
        assert_eq!(normalized["mptcp"], true);
    }

    #[test]
    fn normalizes_config_global_values() {
        let normalized = normalize_global_value(Some("global { log_level:'debug' }"));
        assert_eq!(normalized["logLevel"], "debug");
    }

    #[test]
    fn renders_normalized_global_values() {
        let rendered = display_global_config_text(r#"{"logLevel":"debug"}"#);
        assert!(rendered.starts_with("global {\n"));
        assert!(rendered.contains("log_level:'debug'"));
    }
}
