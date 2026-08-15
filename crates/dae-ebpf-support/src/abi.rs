pub use dae_ebpf_abi::{
    BPF_DAE_PARAM_ABI_VERSION, BpfDaeParam, BpfDomainRouting, BpfIpBytes, BpfLpmKey, BpfMatchSet,
    BpfOutboundConnectivityQuery, BpfPidPname, BpfRedirectEntry, BpfRedirectKey, BpfRoutingResult,
    BpfTimerOpaque, BpfTuplesKey, BpfUdpConnState, BpfUdpStateMetrics, LINK_HDR_LEN_ETHERNET,
    LINK_HDR_LEN_NONE, REDIRECT_TRACK_ABI_VERSION, TASK_COMM_LEN, TPROXY_MARK,
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
        max_match_set_len: MAX_MATCH_SET_LEN as usize,
        tproxy_mark: TPROXY_MARK,
        link_hdr_len_none: LINK_HDR_LEN_NONE,
        link_hdr_len_ethernet: LINK_HDR_LEN_ETHERNET,
    }
}

pub const fn redirect_runtime_generation(control_plane_pid: u32, dae0_ifindex: u32) -> u64 {
    ((control_plane_pid as u64) << 32) | dae0_ifindex as u64
}
