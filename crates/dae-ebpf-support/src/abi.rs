pub use dae_ebpf_abi::{
    BPF_DAE_PARAM_ABI_VERSION, BPF_LPM_FULL_PREFIX_BITS, BPF_LPM_IPV4_MAPPED_PREFIX_BITS,
    BPF_LPM_MAC_OFFSET, BpfDaeParam, BpfDomainRouting, BpfIpBytes, BpfLpmKey, BpfMatchSet,
    BpfOutboundConnectivityQuery, BpfPidPname, BpfRedirectEntry, BpfRedirectKey, BpfRoutingResult,
    BpfTimerOpaque, BpfTproxyMetrics, BpfTuplesKey, BpfUdpConnState, BpfUdpStateMetrics,
    LINK_HDR_LEN_ETHERNET, LINK_HDR_LEN_NONE, MATCH_TYPE_DOMAIN_SET, MATCH_TYPE_DSCP,
    MATCH_TYPE_FALLBACK, MATCH_TYPE_IP_SET, MATCH_TYPE_IP_VERSION, MATCH_TYPE_L4_PROTO,
    MATCH_TYPE_MAC, MATCH_TYPE_PORT, MATCH_TYPE_PROCESS_NAME, MATCH_TYPE_SOURCE_IP_SET,
    MATCH_TYPE_SOURCE_PORT, REDIRECT_TRACK_ABI_VERSION, TASK_COMM_LEN, TPROXY_MARK,
    UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT, UDP_STATE_SATURATION_POLICY_FAIL_CLOSED,
};

pub const MAX_MATCH_SET_LEN: usize = dae_ebpf_abi::MAX_MATCH_SET_LEN as usize;

pub const BASIC_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 2, 0);
pub const CHECKSUM_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 8, 0);
pub const SK_ASSIGN_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 7, 0);
pub const BPF_TIMER_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 15, 0);
pub const BPF_LOOP_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 17, 0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfAbiContract {
    pub dae_param_size: usize,
    pub dae_param_abi_version: u32,
    pub redirect_track_abi_version: u8,
    pub task_comm_len: usize,
    pub max_match_set_len: usize,
    pub tproxy_mark: u32,
    pub link_hdr_len_none: u32,
    pub link_hdr_len_ethernet: u32,
}

pub const fn bpf_abi_contract() -> BpfAbiContract {
    BpfAbiContract {
        dae_param_size: core::mem::size_of::<BpfDaeParam>(),
        dae_param_abi_version: BPF_DAE_PARAM_ABI_VERSION,
        redirect_track_abi_version: REDIRECT_TRACK_ABI_VERSION,
        task_comm_len: TASK_COMM_LEN,
        max_match_set_len: MAX_MATCH_SET_LEN,
        tproxy_mark: TPROXY_MARK,
        link_hdr_len_none: LINK_HDR_LEN_NONE,
        link_hdr_len_ethernet: LINK_HDR_LEN_ETHERNET,
    }
}

pub const fn redirect_runtime_generation(control_plane_pid: u32, dae0_ifindex: u32) -> u64 {
    ((control_plane_pid as u64) << 32) | dae0_ifindex as u64
}
