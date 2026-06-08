use super::*;
pub(crate) fn default_global_value() -> Value {
    json!({
        "logLevel": "",
        "tproxyPort": 0,
        "allowInsecure": false,
        "checkInterval": "",
        "checkTolerance": "",
        "lanInterface": [],
        "wanInterface": [],
        "udpCheckDns": [],
        "tcpCheckUrl": [],
        "fallbackResolver": "",
        "dialMode": "",
        "tcpCheckHttpMethod": "",
        "udpEndpointPoolSize": 0,
        "disableWaitingNetwork": false,
        "autoConfigKernelParameter": false,
        "autoConfigFirewallRule": false,
        "sniffingTimeout": "",
        "tlsImplementation": "",
        "utlsImitate": "",
        "tlsFragment": false,
        "tlsFragmentLength": "",
        "tlsFragmentInterval": "",
        "tproxyPortProtect": false,
        "soMarkFromDae": 0,
        "pprofPort": 0,
        "enableLocalTcpFastRedirect": false,
        "mptcp": false,
        "bandwidthMaxTx": "",
        "bandwidthMaxRx": "",
        "udphopInterval": "",
    })
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
}
