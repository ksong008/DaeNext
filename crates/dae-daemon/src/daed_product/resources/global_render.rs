use super::*;
pub(crate) fn normalize_global_value(raw: Option<&str>) -> Value {
    let mut value = default_global_value();
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return value;
    };
    if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
        merge_global_json_value(&mut value, &parsed);
        return value;
    }
    merge_global_directives(&mut value, &parse_global_directives(raw));
    value
}

pub(crate) fn display_global_config_text(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return "global {}\n".to_owned();
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => render_global_config_text(&Value::Object(map)),
        _ => raw.to_owned(),
    }
}

pub(crate) fn render_global_config_text(source: &Value) -> String {
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
    source: &Value,
    json_key: &str,
    config_key: &str,
    aliases: &[&str],
) {
    let value = normalized
        .get(json_key)
        .and_then(Value::as_str)
        .unwrap_or("");
    if global_source_has_key(source, aliases) || !value.is_empty() {
        lines.push(format!("{config_key}:{}", dae_string_literal(value)));
    }
}

pub(crate) fn push_global_array_field(
    lines: &mut Vec<String>,
    normalized: &Value,
    source: &Value,
    json_key: &str,
    config_key: &str,
    aliases: &[&str],
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
    if global_source_has_key(source, aliases) || !values.is_empty() {
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
