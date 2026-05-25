use std::sync::OnceLock;

use serde_json::{Value, json};

const OUTLINE_VERSION_PLACEHOLDER: &str = "__DAE_OUTLINE_VERSION_PLACEHOLDER__";

struct OutlineJsonTemplate {
    prefix: String,
    suffix: String,
}

pub fn export_outline(version: &str) -> Value {
    json!({
        "version": version,
        "leaves": [
            "[]*config_parser.Function",
            "[]*config_parser.Param",
            "bool",
            "config.FunctionListOrString",
            "config.FunctionOrString",
            "config.KeyableString",
            "config_parser.RoutingRule",
            "int",
            "string",
            "time.Duration",
            "uint16",
            "uint32"
        ],
        "structure": [
            global_outline(),
            json!({
                "name": "Subscription",
                "mapping": "subscription",
                "isArray": true,
                "type": "config.KeyableString",
                "desc": "Subscriptions defined here will be resolved as nodes and merged as a part of the global node pool.\nSupport to give the subscription a tag, and filter nodes from a given subscription in the group section."
            }),
            json!({
                "name": "Node",
                "mapping": "node",
                "isArray": true,
                "type": "config.KeyableString",
                "desc": "Nodes defined here will be merged as a part of the global node pool."
            }),
            group_outline(),
            routing_outline(),
            dns_outline()
        ]
    })
}

pub fn export_outline_json(version: &str) -> String {
    let template = outline_json_template();
    let encoded_version = serde_json::to_string(version).expect("outline version should serialize");
    let mut out = String::with_capacity(
        template.prefix.len() + encoded_version.len() + template.suffix.len(),
    );
    out.push_str(&template.prefix);
    out.push_str(&encoded_version);
    out.push_str(&template.suffix);
    out
}

pub fn export_flat_desc(version: &str) -> Value {
    let outline = export_outline(version);
    let mut rows = Vec::new();
    flatten_outline("", outline["structure"].as_array().unwrap(), &mut rows);
    Value::Array(rows)
}

fn flatten_outline(prefix: &str, structure: &[Value], rows: &mut Vec<Value>) {
    for elem in structure {
        let mapping = elem["mapping"].as_str().unwrap_or_default();
        let path = if prefix.is_empty() || mapping == "_" {
            mapping.to_owned()
        } else {
            format!("{prefix}.{mapping}")
        };
        rows.push(json!({
            "path": path,
            "name": elem["name"].as_str().unwrap_or_default(),
            "mapping": mapping,
            "type": elem["type"].as_str().unwrap_or_default(),
            "desc": elem["desc"].as_str().unwrap_or_default(),
        }));
        if let Some(children) = elem["structure"].as_array() {
            let child_prefix = if mapping == "_" { prefix } else { &path };
            flatten_outline(child_prefix, children, rows);
        }
    }
}

fn global_outline() -> Value {
    json!({
        "name": "Global",
        "mapping": "global",
        "required": true,
        "type": "config.Global",
        "structure": [
            leaf("TproxyPort", "tproxy_port", "uint16", Some("12345"), Some("tproxy port to listen on. It is NOT a HTTP/SOCKS port, and is just used by eBPF program.\nIn normal case, you do not need to use it."), false, false),
            leaf("TproxyPortProtect", "tproxy_port_protect", "bool", Some("true"), Some("Set it true to protect tproxy port from unsolicited traffic. Set it false to allow users to use self-managed iptables tproxy rules."), false, false),
            leaf("SoMarkFromDae", "so_mark_from_dae", "uint32", None, Some("If not zero, traffic sent from dae will be set SO_MARK. It is useful to avoid traffic loop with iptables tproxy rules."), false, false),
            leaf("LogLevel", "log_level", "string", Some("info"), Some("Log level: error, warn, info, debug, trace."), false, false),
            leaf("TcpCheckUrl", "tcp_check_url", "string", Some("http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111"), Some("Node connectivity check.\nHost of URL should have both IPv4 and IPv6 if you have double stack in local.\nConsidering traffic consumption, it is recommended to choose a site with anycast IP and less response."), true, false),
            leaf("TcpCheckHttpMethod", "tcp_check_http_method", "string", Some("HEAD"), Some("The HTTP request method to `tcp_check_url`. Use 'HEAD' by default because some server implementations bypass accounting for this kind of traffic."), false, false),
            leaf("UdpCheckDns", "udp_check_dns", "string", Some("dns.google:53,8.8.8.8,2001:4860:4860::8888"), Some("This DNS will be used to check UDP connectivity of nodes. And if dns_upstream below contains tcp, it also be used to check TCP DNS connectivity of nodes.\nThis DNS should have both IPv4 and IPv6 if you have double stack in local."), true, false),
            leaf("CheckInterval", "check_interval", "time.Duration", Some("30s"), Some("Interval of connectivity check for TCP and UDP"), false, false),
            leaf("CheckTolerance", "check_tolerance", "time.Duration", Some("0"), Some("Group will switch node only when new_latency <= old_latency - tolerance."), false, false),
            leaf("UdpEndpointPoolSize", "udp_endpoint_pool_size", "int", Some("4096"), Some("Maximum number of cached UDP endpoints before dae evicts the oldest inactive entries. Increase it for heavy QUIC, gaming, or P2P workloads."), false, false),
            leaf("LanInterface", "lan_interface", "string", None, Some("The LAN interface to bind. Use it if you want to proxy LAN."), true, false),
            leaf("WanInterface", "wan_interface", "string", None, Some("The WAN interface to bind. Use it if you want to proxy localhost. Use \"auto\" to auto detect."), true, false),
            leaf("AllowInsecure", "allow_insecure", "bool", Some("false"), Some("Allow insecure TLS certificates. It is not recommended to turn it on unless you have to."), false, false),
            leaf("DialMode", "dial_mode", "string", Some("domain"), Some(r#"Optional values of dial_mode are:
1. "ip". Dial proxy using the IP from DNS directly. This allows your ipv4, ipv6 to choose the optimal path respectively, and makes the IP version requested by the application meet expectations. For example, if you use curl -4 ip.sb, you will request IPv4 via proxy and get a IPv4 echo. And curl -6 ip.sb will request IPv6. This may solve some weird full-cone problem if your are be your node support that.Sniffing will be disabled in this mode.
2. "domain". Dial proxy using the domain from sniffing. This will relieve DNS pollution problem to a great extent if have impure DNS environment. Generally, this mode brings faster proxy response time because proxy will re-resolve the domain in remote, thus get better IP result to connect. This policy does not impact routing. That is to say, domain rewrite will be after traffic split of routing and dae will not re-route it.
3. "domain+". Based on domain mode but do not check the reality of sniffed domain. It is useful for users whose DNS requests do not go through dae but want faster proxy response time. Notice that, if DNS requests do not go through dae, dae cannot split traffic by domain.
4. "domain++". Based on domain+ mode but force to re-route traffic using sniffed domain to partially recover domain based traffic split ability. It doesn't work for direct traffic and consumes more CPU resources."#), false, false),
            leaf("DisableWaitingNetwork", "disable_waiting_network", "bool", Some("false"), Some("Disable waiting for network before pulling subscriptions."), false, false),
            leaf("EnableLocalTcpFastRedirect", "enable_local_tcp_fast_redirect", "bool", Some("false"), None, false, false),
            leaf("AutoConfigKernelParameter", "auto_config_kernel_parameter", "bool", Some("false"), Some("Automatically configure Linux kernel parameters like ip_forward and send_redirects. Check out https://github.com/daeuniverse/dae/blob/main/docs/en/user-guide/kernel-parameters.md to see what will dae do."), false, false),
            leaf("AutoConfigFirewallRule", "auto_config_firewall_rule", "bool", Some("false"), None, false, false),
            leaf("SniffingTimeout", "sniffing_timeout", "time.Duration", Some("100ms"), Some("Timeout to waiting for first data sending for sniffing. It is always 0 if dial_mode is ip. Set it higher is useful in high latency LAN network."), false, false),
            leaf("TlsImplementation", "tls_implementation", "string", Some("tls"), Some("TLS implementation. \"tls\" is to use Go's crypto/tls. \"utls\" is to use uTLS, which can imitate browser's Client Hello."), false, false),
            leaf("UtlsImitate", "utls_imitate", "string", Some("chrome_auto"), Some("The Client Hello ID for uTLS to imitate. This takes effect only if tls_implementation is utls. See more: https://github.com/daeuniverse/dae/blob/331fa23c16/component/outbound/transport/tls/utls.go#L17"), false, false),
            leaf("TlsFragment", "tls_fragment", "bool", Some("false"), None, false, false),
            leaf("TlsFragmentLength", "tls_fragment_length", "string", Some("50-100"), None, false, false),
            leaf("TlsFragmentInterval", "tls_fragment_interval", "string", Some("10-20"), None, false, false),
            leaf("PprofPort", "pprof_port", "uint16", Some("0"), None, false, false),
            leaf("Mptcp", "mptcp", "bool", Some("false"), Some("Enable Multipath TCP.  If is true, dae will try to use MPTCP to connect all nodes, but it will only take effects when the node supports MPTCP. It can use for load balance and failover to multiple interfaces and IPs."), false, false),
            leaf("FallbackResolver", "fallback_resolver", "string", Some("8.8.8.8:53"), None, false, false),
            leaf("BandwidthMaxTx", "bandwidth_max_tx", "string", Some("0"), None, false, false),
            leaf("BandwidthMaxRx", "bandwidth_max_rx", "string", Some("0"), None, false, false),
            leaf("UDPHopInterval", "udphop_interval", "time.Duration", Some("30s"), None, false, false)
        ]
    })
}

fn group_outline() -> Value {
    json!({
        "name": "Group",
        "mapping": "group",
        "isArray": true,
        "type": "config.Group",
        "desc": "Node group. Groups defined here can be used as outbounds in section \"routing\".",
        "structure": [
            leaf("Name", "_", "string", None, None, false, false),
            leaf("Filter", "filter", "[]*config_parser.Function", None, Some("Filter nodes from the global node pool defined by the \"subscription\" and \"node\" sections.\nAvailable functions: name, subtag. Not operator is supported.\nAvailable keys in name function: keyword, regex. No key indicates full match.\nAvailable keys in subtag function: regex. No key indicates full match."), true, false),
            leaf("FilterAnnotation", "_", "[]*config_parser.Param", None, None, true, false),
            leaf("Policy", "policy", "config.FunctionListOrString", None, Some("Dialer selection policy. For each new connection, select a node as dialer from group by this policy.\nAvailable values: random, fixed, min, min_avg10, min_moving_avg.\nrandom: Select randomly.\nfixed: Select the fixed node. Connectivity check will be disabled.\nmin: Select node by the latency of last check.\nmin_avg10: Select node by the average of latencies of last 10 checks.\nmin_moving_avg: Select node by the moving average of latencies of checks, which means more recent latencies have higher weight.\n"), false, true),
            leaf("TcpCheckUrl", "tcp_check_url", "string", None, Some("Override global config."), true, false),
            leaf("TcpCheckHttpMethod", "tcp_check_http_method", "string", None, Some("Override global config."), false, false),
            leaf("UdpCheckDns", "udp_check_dns", "string", None, Some("Override global config."), true, false),
            leaf("CheckInterval", "check_interval", "time.Duration", None, Some("Override global config."), false, false),
            leaf("CheckTolerance", "check_tolerance", "time.Duration", None, Some("Override global config."), false, false)
        ]
    })
}

fn routing_outline() -> Value {
    json!({
        "name": "Routing",
        "mapping": "routing",
        "required": true,
        "type": "config.Routing",
        "desc": "Traffic follows this routing. See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.\nNotice: domain traffic split will fail if DNS traffic is not taken over by dae.\nBuilt-in outbound: direct, must_direct, block.\nAvailable functions: domain, sip, dip, sport, dport, ipversion, l4proto, pname, mac.\nAvailable keys in domain function: suffix, keyword, regex, full. No key indicates suffix.\ndomain: Match domain.\nsip: Match source IP. CIDR format is also supported.\ndip: Match dest IP. CIDR format is also supported.\nsport: Match source port. Range like 8000-9000 is also supported.\ndport: Match dest port. Range like 8000-9000 is also supported.\nipversion: Match IP version. Available values: 4, 6.\nl4proto: Match level 4 protocol. Available values: tcp, udp.\npname: Match process name. It only works on WAN mode and for localhost programs.\nmac: Match source MAC address. It works on LAN mode.",
        "structure": [
            leaf("Rules", "_", "config_parser.RoutingRule", None, None, true, false),
            leaf("Fallback", "fallback", "config.FunctionOrString", Some("direct"), None, false, false)
        ]
    })
}

fn dns_outline() -> Value {
    json!({
        "name": "Dns",
        "mapping": "dns",
        "type": "config.Dns",
        "desc": "See more at https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/dns.md.",
        "structure": [
            leaf("IpVersionPrefer", "ipversion_prefer", "int", None, Some("For example, if ipversion_prefer is 4 and the domain name has both type A and type AAAA records, the dae will only respond to type A queries and response empty answer to type AAAA queries."), false, false),
            leaf("FixedDomainTtl", "fixed_domain_ttl", "config.KeyableString", None, Some("Give a fixed ttl for domains. Zero means that dae will request to upstream every time and not cache DNS results for these domains."), true, false),
            leaf("Upstream", "upstream", "config.KeyableString", None, Some("Value can be scheme://host:port, where the scheme can be tcp/udp/tcp+udp.\nIf host is a domain and has both IPv4 and IPv6 record, dae will automatically choose IPv4 or IPv6 to use according to group policy (such as min latency policy).\nPlease make sure DNS traffic will go through and be forwarded by dae, which is REQUIRED for domain routing.\nIf dial_mode is \"ip\", the upstream DNS answer SHOULD NOT be polluted, so domestic public DNS is not recommended."), true, false),
            json!({
                "name": "Routing",
                "mapping": "routing",
                "type": "config.DnsRouting",
                "structure": [
                    dns_rule_set_outline("Request", "request", "config.DnsRequestRouting", "DNS requests will follow this routing.\nBuilt-in outbound: asis.\nAvailable functions: qname, qtype"),
                    dns_rule_set_outline("Response", "response", "config.DnsResponseRouting", "DNS responses will follow this routing.\nBuilt-in outbound: accept, reject.\nAvailable functions: qname, qtype, ip, upstream")
                ]
            }),
            leaf("Bind", "bind", "string", None, None, false, false)
        ]
    })
}

fn dns_rule_set_outline(name: &str, mapping: &str, typ: &str, desc: &str) -> Value {
    json!({
        "name": name,
        "mapping": mapping,
        "type": typ,
        "desc": desc,
        "structure": [
            leaf("Rules", "_", "config_parser.RoutingRule", None, None, true, false),
            leaf("Fallback", "fallback", "config.FunctionOrString", None, None, false, true)
        ]
    })
}

fn leaf(
    name: &str,
    mapping: &str,
    typ: &str,
    default_value: Option<&str>,
    desc: Option<&str>,
    is_array: bool,
    required: bool,
) -> Value {
    let mut value = json!({
        "name": name,
        "mapping": mapping,
        "type": typ
    });
    let object = value.as_object_mut().unwrap();
    if is_array {
        object.insert("isArray".to_owned(), Value::Bool(true));
    }
    if let Some(default_value) = default_value {
        object.insert(
            "defaultValue".to_owned(),
            Value::String(default_value.to_owned()),
        );
    }
    if required {
        object.insert("required".to_owned(), Value::Bool(true));
    }
    if let Some(desc) = desc {
        object.insert("desc".to_owned(), Value::String(desc.to_owned()));
    }
    value
}

fn outline_json_template() -> &'static OutlineJsonTemplate {
    static TEMPLATE: OnceLock<OutlineJsonTemplate> = OnceLock::new();
    TEMPLATE.get_or_init(|| {
        let template = serde_json::to_string_pretty(&export_outline(OUTLINE_VERSION_PLACEHOLDER))
            .expect("outline json template should serialize");
        let marker =
            serde_json::to_string(OUTLINE_VERSION_PLACEHOLDER).expect("marker should serialize");
        let index = template
            .find(&marker)
            .expect("outline json template should contain version marker");
        OutlineJsonTemplate {
            prefix: template[..index].to_owned(),
            suffix: template[index + marker.len()..].to_owned(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::OUTLINE_EXPORT_OUTLINE;

    #[test]
    fn outline_matches_go_export_outline_golden() {
        let fixture = dae_golden::load_json(OUTLINE_EXPORT_OUTLINE).unwrap();
        assert_eq!(export_outline("test"), fixture["outline"]);

        let reparsed: Value = serde_json::from_str(&export_outline_json("test")).unwrap();
        assert_eq!(reparsed, fixture["outline"]);
        assert_eq!(
            export_outline_json("te\"st\n"),
            serde_json::to_string_pretty(&export_outline("te\"st\n")).unwrap()
        );
    }

    #[test]
    fn flat_desc_exposes_stable_paths() {
        let flat = export_flat_desc("test");
        let rows = flat.as_array().unwrap();
        assert!(rows.iter().any(|row| row["path"] == "global.tproxy_port"));
        assert!(rows.iter().any(|row| row["path"] == "routing.fallback"));
        assert!(
            rows.iter()
                .any(|row| row["path"] == "dns.routing.request.fallback")
        );
    }
}
