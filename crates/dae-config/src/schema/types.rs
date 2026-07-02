use super::utils::{parse_default_duration, split_csv};
use super::*;

pub type KeyableString = String;

pub const DEFAULT_LOG_LEVEL: &str = "error";

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
    pub check_interval: ConfigDuration,
    pub check_tolerance: ConfigDuration,
    pub udp_endpoint_pool_size: i32,
    pub lan_interface: Option<Vec<String>>,
    pub wan_interface: Option<Vec<String>>,
    pub allow_insecure: bool,
    pub dial_mode: String,
    pub disable_waiting_network: bool,
    pub enable_local_tcp_fast_redirect: bool,
    pub auto_config_kernel_parameter: bool,
    pub auto_config_firewall_rule: bool,
    pub sniffing_timeout: ConfigDuration,
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
    pub udphop_interval: ConfigDuration,
    pub resident_udp_session_limit: Option<u64>,
    pub resident_udp_session_queue_depth: Option<u64>,
    pub resident_tcp_flow_stack_bytes: Option<u64>,
    pub resident_event_queue_depth: Option<u64>,
    pub resident_manual_probe_concurrency: Option<u64>,
    pub resident_tcp_probe_timeout_ms: Option<u64>,
    pub resident_health_check_concurrency: Option<u64>,
    pub http_queue: Option<u64>,
    pub http_workers: Option<u64>,
    pub http_worker_stack_bytes: Option<u64>,
    pub allocator_idle_reclaim_enabled: Option<bool>,
    pub allocator_idle_reclaim_sample_interval: Option<ConfigDuration>,
    pub allocator_idle_reclaim_min_interval: Option<ConfigDuration>,
    pub allocator_idle_reclaim_low_traffic_duration: Option<ConfigDuration>,
    pub allocator_idle_reclaim_pressure_threshold_bytes: Option<u64>,
    pub allocator_idle_reclaim_max_traffic_rate_bytes_per_second: Option<u64>,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            tproxy_port: 12345,
            tproxy_port_protect: true,
            so_mark_from_dae: 0,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            tcp_check_url: split_csv("http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111"),
            tcp_check_http_method: "HEAD".to_owned(),
            udp_check_dns: split_csv("dns.google:53"),
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
            resident_udp_session_limit: None,
            resident_udp_session_queue_depth: None,
            resident_tcp_flow_stack_bytes: None,
            resident_event_queue_depth: None,
            resident_manual_probe_concurrency: None,
            resident_tcp_probe_timeout_ms: None,
            resident_health_check_concurrency: None,
            http_queue: None,
            http_workers: None,
            http_worker_stack_bytes: None,
            allocator_idle_reclaim_enabled: None,
            allocator_idle_reclaim_sample_interval: None,
            allocator_idle_reclaim_min_interval: None,
            allocator_idle_reclaim_low_traffic_duration: None,
            allocator_idle_reclaim_pressure_threshold_bytes: None,
            allocator_idle_reclaim_max_traffic_rate_bytes_per_second: None,
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
    pub check_interval: ConfigDuration,
    pub check_tolerance: ConfigDuration,
}

impl Group {
    pub(super) fn new(name: String) -> Self {
        Self {
            name,
            filter: Vec::new(),
            filter_annotation: Vec::new(),
            policy: DynamicFunctionValue::Nil,
            tcp_check_url: None,
            tcp_check_http_method: String::new(),
            udp_check_dns: None,
            check_interval: ConfigDuration::default(),
            check_tolerance: ConfigDuration::default(),
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Dns {
    pub ipversion_prefer: i32,
    pub fixed_domain_ttl: Vec<KeyableString>,
    pub upstream: Vec<KeyableString>,
    pub routing: DnsRouting,
    pub bind: String,
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
