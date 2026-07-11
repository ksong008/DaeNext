#[repr(C)]
#[derive(Clone, Copy)]
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
    pub abi_version: u32,
    pub udp_state_saturation_policy: u32,
    pub udp_state_idle_timeout_ns: u64,
}

impl BpfDaeParam {
    pub const fn zeroed() -> Self {
        Self {
            tproxy_port: 0,
            control_plane_pid: 0,
            dae0_ifindex: 0,
            dae_netns_id: 0,
            dae0peer_mac: [0; 6],
            has_bpf_get_current_task: 0,
            padding: 0,
            task_struct_mm_offset: 0,
            mm_struct_arg_start_offset: 0,
            abi_version: 0,
            udp_state_saturation_policy: UDP_STATE_SATURATION_POLICY_FAIL_CLOSED,
            udp_state_idle_timeout_ns: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfIpBytes {
    pub u6_addr8: [u8; 16],
}

impl BpfIpBytes {
    pub const fn zeroed() -> Self {
        Self { u6_addr8: [0; 16] }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfDomainRouting {
    pub bitmap: [u32; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfPortRange {
    pub port_start: u16,
    pub port_end: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union BpfMatchValue {
    pub bytes: [u8; 16],
    pub index: u32,
    pub port_range: BpfPortRange,
    pub l4proto_type: u32,
    pub ip_version: u32,
    pub pname: [u32; TASK_COMM_LEN / 4],
    pub dscp: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfMatchSet {
    pub value: BpfMatchValue,
    pub not: u8,
    pub kind: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfOutboundConnectivityQuery {
    pub outbound: u8,
    pub l4proto: u8,
    pub ipversion: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfPidPname {
    pub pid: u32,
    pub comm: [i8; TASK_COMM_LEN],
    pub pname: [i8; TASK_COMM_LEN],
}

impl BpfPidPname {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            comm: [0; TASK_COMM_LEN],
            pname: [0; TASK_COMM_LEN],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfRedirectEntry {
    pub ifindex: u32,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub from_wan: u8,
    pub link_layer: u8,
    pub abi_version: u8,
    pub padding: u8,
}

impl BpfRedirectEntry {
    pub const fn zeroed() -> Self {
        Self {
            ifindex: 0,
            smac: [0; 6],
            dmac: [0; 6],
            from_wan: 0,
            link_layer: 0,
            abi_version: 0,
            padding: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfRedirectKey {
    pub sip: BpfIpBytes,
    pub dip: BpfIpBytes,
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub abi_version: u8,
    pub padding: [u8; 2],
    pub generation: u64,
}

impl BpfRedirectKey {
    pub const fn zeroed() -> Self {
        Self {
            sip: BpfIpBytes::zeroed(),
            dip: BpfIpBytes::zeroed(),
            sport: 0,
            dport: 0,
            l4proto: 0,
            abi_version: 0,
            padding: [0; 2],
            generation: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfRoutingResult {
    pub mark: u32,
    pub must: u8,
    pub mac: [u8; 6],
    pub outbound: u8,
    pub pname: [u8; TASK_COMM_LEN],
    pub pid: u32,
    pub dscp: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfTuplesKey {
    pub sip: BpfIpBytes,
    pub dip: BpfIpBytes,
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub padding: [u8; 3],
}

impl BpfTuplesKey {
    pub const fn zeroed() -> Self {
        Self {
            sip: BpfIpBytes::zeroed(),
            dip: BpfIpBytes::zeroed(),
            sport: 0,
            dport: 0,
            l4proto: 0,
            padding: [0; 3],
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct bpf_timer {
    pub __opaque: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfUdpConnState {
    pub is_wan_ingress_direction: u8,
    pub padding: [u8; 7],
    pub timer: bpf_timer,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfUdpStateMetrics {
    pub state_created_total: u64,
    pub state_refresh_total: u64,
    pub insert_failure_total: u64,
    pub post_insert_lookup_failure_total: u64,
    pub timer_init_failure_total: u64,
    pub timer_callback_failure_total: u64,
    pub timer_start_failure_total: u64,
}

impl BpfUdpConnState {
    pub const fn new(is_wan_ingress_direction: bool) -> Self {
        Self {
            is_wan_ingress_direction: is_wan_ingress_direction as u8,
            padding: [0; 7],
            timer: bpf_timer { __opaque: [0; 2] },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfLpmKey {
    pub prefix_len: u32,
    pub data: [u32; 4],
}

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_MATCH_SET_LEN: u32 = 32 * 32;
pub const MAX_LPM_NUM: u32 = MAX_MATCH_SET_LEN + 8;
pub const MAX_LPM_SIZE: u32 = 2_048_000;
pub const MAX_DST_MAPPING_NUM: u32 = 65_536 * 2;
pub const MAX_COOKIE_PID_PNAME_MAPPING_NUM: u32 = 65_536;
pub const MAX_DOMAIN_ROUTING_NUM: u32 = 65_536;
pub const TPROXY_MARK: u32 = 0x0800_0000;
pub const BPF_DAE_PARAM_ABI_VERSION: u32 = 2;
pub const UDP_STATE_SATURATION_POLICY_FAIL_CLOSED: u32 = 0;
pub const UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT: u64 = 300_000_000_000;
pub const REDIRECT_TRACK_ABI_VERSION: u8 = 2;
pub const LINK_HDR_LEN_ETHERNET: u32 = 14;

#[unsafe(no_mangle)]
#[used]
pub static PARAM: BpfDaeParam = BpfDaeParam::zeroed();

#[inline(always)]
pub fn param_control_plane_pid() -> u32 {
    unsafe { core::ptr::addr_of!(PARAM.control_plane_pid).read_volatile() }
}

#[inline(always)]
pub fn param_dae0_ifindex() -> u32 {
    unsafe { core::ptr::addr_of!(PARAM.dae0_ifindex).read_volatile() }
}

#[inline(always)]
pub fn param_dae_netns_id() -> u32 {
    unsafe { core::ptr::addr_of!(PARAM.dae_netns_id).read_volatile() }
}

#[inline(always)]
pub fn param_dae0peer_mac() -> [u8; 6] {
    unsafe {
        [
            core::ptr::addr_of!(PARAM.dae0peer_mac[0]).read_volatile(),
            core::ptr::addr_of!(PARAM.dae0peer_mac[1]).read_volatile(),
            core::ptr::addr_of!(PARAM.dae0peer_mac[2]).read_volatile(),
            core::ptr::addr_of!(PARAM.dae0peer_mac[3]).read_volatile(),
            core::ptr::addr_of!(PARAM.dae0peer_mac[4]).read_volatile(),
            core::ptr::addr_of!(PARAM.dae0peer_mac[5]).read_volatile(),
        ]
    }
}

#[inline(always)]
pub fn param_udp_state_idle_timeout_ns() -> u64 {
    let value = unsafe { core::ptr::addr_of!(PARAM.udp_state_idle_timeout_ns).read_volatile() };
    if value == 0 {
        UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT
    } else {
        value
    }
}

#[inline(always)]
pub fn param_udp_state_saturation_policy() -> u32 {
    unsafe { core::ptr::addr_of!(PARAM.udp_state_saturation_policy).read_volatile() }
}

#[inline(always)]
pub fn param_redirect_generation() -> u64 {
    let control_plane_pid =
        unsafe { core::ptr::addr_of!(PARAM.control_plane_pid).read_volatile() } as u64;
    let dae0_ifindex = unsafe { core::ptr::addr_of!(PARAM.dae0_ifindex).read_volatile() } as u64;
    (control_plane_pid << 32) | dae0_ifindex
}

#[inline(always)]
pub fn param_has_bpf_get_current_task() -> u8 {
    unsafe { core::ptr::addr_of!(PARAM.has_bpf_get_current_task).read_volatile() }
}

#[inline(always)]
pub fn param_task_struct_mm_offset() -> u32 {
    unsafe { core::ptr::addr_of!(PARAM.task_struct_mm_offset).read_volatile() }
}

#[inline(always)]
pub fn param_mm_struct_arg_start_offset() -> u32 {
    unsafe { core::ptr::addr_of!(PARAM.mm_struct_arg_start_offset).read_volatile() }
}
