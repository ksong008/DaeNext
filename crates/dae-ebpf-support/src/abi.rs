#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfDaeParam {
    pub tproxy_port: u32,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub has_bpf_get_current_task: u8,
    pub padding: u8,
    pub task_struct_mm_offset: u32,
    pub mm_struct_arg_start_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfDomainRouting {
    pub bitmap: [u32; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfMatchSet {
    pub value: [u8; 16],
    pub not: u8,
    pub kind: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct BpfOutboundConnectivityQuery {
    pub outbound: u8,
    pub l4proto: u8,
    pub ipversion: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfPidPname {
    pub pid: u32,
    pub comm: [i8; 16],
    pub pname: [i8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfRedirectEntry {
    pub ifindex: u32,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub from_wan: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfIpBytes {
    pub u6_addr8: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfRedirectTuple {
    pub sip: BpfIpBytes,
    pub dip: BpfIpBytes,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfRoutingResult {
    pub mark: u32,
    pub must: u8,
    pub mac: [u8; 6],
    pub outbound: u8,
    pub pname: [u8; 16],
    pub pid: u32,
    pub dscp: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfTuplesKey {
    pub sip: BpfIpBytes,
    pub dip: BpfIpBytes,
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfTimerOpaque {
    pub opaque: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfUdpConnState {
    pub is_wan_ingress_direction: u8,
    pub padding: [u8; 7],
    pub timer: BpfTimerOpaque,
}

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_MATCH_SET_LEN: usize = 32 * 32;
pub const TPROXY_MARK: u32 = 0x0800_0000;
pub const LINK_HDR_LEN_NONE: u32 = 0;
pub const LINK_HDR_LEN_ETHERNET: u32 = 14;

pub const BASIC_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 2, 0);
pub const CHECKSUM_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 8, 0);
pub const SK_ASSIGN_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 7, 0);
pub const BPF_TIMER_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 15, 0);
pub const BPF_LOOP_FEATURE_VERSION: super::kernel::Version = super::kernel::Version::new(5, 17, 0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfAbiContract {
    pub dae_param_size: usize,
    pub task_comm_len: usize,
    pub max_match_set_len: usize,
    pub tproxy_mark: u32,
    pub link_hdr_len_none: u32,
    pub link_hdr_len_ethernet: u32,
}

pub const fn bpf_abi_contract() -> BpfAbiContract {
    BpfAbiContract {
        dae_param_size: core::mem::size_of::<BpfDaeParam>(),
        task_comm_len: TASK_COMM_LEN,
        max_match_set_len: MAX_MATCH_SET_LEN,
        tproxy_mark: TPROXY_MARK,
        link_hdr_len_none: LINK_HDR_LEN_NONE,
        link_hdr_len_ethernet: LINK_HDR_LEN_ETHERNET,
    }
}
