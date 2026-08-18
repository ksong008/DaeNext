use super::*;
pub(super) const DEFAULT_SOURCE_OBJECT: &str = "";
pub(super) const DEFAULT_PEER_SECTION: &str = "tc/dae0peer_ingress";
pub(super) const DEFAULT_HOST_SECTION: &str = "tc/dae0_ingress";
pub(super) const DEFAULT_TPROXY_PORT: u16 = 12345;
pub(super) const DEFAULT_DAE_NETNS_ID: u32 = 49;
pub(super) const FILTER_PREF: &str = "49491";
pub(super) const PRODUCTION_NETNS: &str = "daens";
pub(super) const PRODUCTION_HOST_IFACE: &str = "dae0";
pub(super) const PRODUCTION_PEER_IFACE: &str = "dae0peer";

pub(crate) fn set_resident_event_log_sink(sink: Option<ResidentEventLogSink>) {
    dae_resident_dataplane::facade::set_event_log_sink(sink);
}

pub(crate) fn set_resident_event_log_policies(
    policy: Option<ResidentEventLogPolicy>,
    prefilter: Option<ResidentEventLogPrefilter>,
) {
    dae_resident_dataplane::facade::set_event_log_policies(policy, prefilter);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionRuntimeOwnerOptions {
    pub execute: bool,
    pub ack_root_gate: bool,
    pub source_object: PathBuf,
    pub geodata_asset_dirs: Vec<PathBuf>,
    pub tproxy_port: u16,
    /// Drop unsolicited WAN packets addressed to `tproxy_port` in native TC.
    pub tproxy_port_protect: bool,
    pub dae_netns_id: u32,
    pub netns_link_mode: NetnsLinkMode,
    pub peer_section: String,
    pub host_section: String,
    pub execute_active_tcp: bool,
    pub active_tcp_target_ip: String,
    pub active_tcp_client_ip: String,
    pub active_tcp_target_port: u16,
    pub active_tcp_so_mark: u32,
    pub active_tcp_mptcp: bool,
    pub execute_active_tcp_relay: bool,
    pub active_tcp_upstream_mptcp: bool,
    pub active_tcp_benchmark_iters: u32,
    pub execute_active_udp: bool,
    pub active_udp_target_ip: String,
    pub active_udp_target_port: u16,
    pub active_udp_benchmark_iters: u32,
    pub execute_active_dns: bool,
    pub active_dns_target_ip: String,
    pub active_dns_target_port: u16,
    pub active_dns_upstream_ip: String,
    pub active_dns_upstream_port: u16,
    pub active_dns_qname: String,
    pub active_dns_benchmark_iters: u32,
    pub execute_reload_runtime_parity: bool,
    pub native_ebpf_requested: bool,
    pub native_ebpf_backend: AttachBackend,
    pub native_ebpf_local_admission: bool,
    pub native_ebpf_embedded_object: bool,
}

impl Default for ProductionRuntimeOwnerOptions {
    fn default() -> Self {
        Self {
            execute: false,
            ack_root_gate: false,
            source_object: PathBuf::from(DEFAULT_SOURCE_OBJECT),
            geodata_asset_dirs: Vec::new(),
            tproxy_port: DEFAULT_TPROXY_PORT,
            tproxy_port_protect: true,
            dae_netns_id: DEFAULT_DAE_NETNS_ID,
            netns_link_mode: NetnsLinkMode::Auto,
            peer_section: DEFAULT_PEER_SECTION.to_owned(),
            host_section: DEFAULT_HOST_SECTION.to_owned(),
            execute_active_tcp: false,
            active_tcp_target_ip: DEFAULT_ACTIVE_TCP_TARGET_IP.to_owned(),
            active_tcp_client_ip: DEFAULT_ACTIVE_TCP_CLIENT_IP.to_owned(),
            active_tcp_target_port: DEFAULT_ACTIVE_TCP_TARGET_PORT,
            active_tcp_so_mark: DEFAULT_ACTIVE_TCP_SO_MARK,
            active_tcp_mptcp: DEFAULT_ACTIVE_TCP_MPTCP,
            execute_active_tcp_relay: false,
            active_tcp_upstream_mptcp: true,
            active_tcp_benchmark_iters: 5,
            execute_active_udp: false,
            active_udp_target_ip: DEFAULT_ACTIVE_UDP_TARGET_IP.to_owned(),
            active_udp_target_port: DEFAULT_ACTIVE_UDP_TARGET_PORT,
            active_udp_benchmark_iters: 5,
            execute_active_dns: false,
            active_dns_target_ip: String::new(),
            active_dns_target_port: DEFAULT_ACTIVE_DNS_TARGET_PORT,
            active_dns_upstream_ip: DEFAULT_ACTIVE_DNS_UPSTREAM_IP.to_owned(),
            active_dns_upstream_port: DEFAULT_ACTIVE_DNS_UPSTREAM_PORT,
            active_dns_qname: DEFAULT_ACTIVE_DNS_QNAME.to_owned(),
            active_dns_benchmark_iters: 5,
            execute_reload_runtime_parity: false,
            native_ebpf_requested: false,
            native_ebpf_backend: AttachBackend::Auto,
            native_ebpf_local_admission: false,
            native_ebpf_embedded_object: false,
        }
    }
}
