use super::*;
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
