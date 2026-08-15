pub use dae_ebpf_abi::*;

pub const MAX_LPM_NUM: u32 = MAX_MATCH_SET_LEN + 8;
pub const MAX_LPM_SIZE: u32 = 2_048_000;
pub const MAX_DST_MAPPING_NUM: u32 = 65_536 * 2;
pub const MAX_COOKIE_PID_PNAME_MAPPING_NUM: u32 = 65_536;
pub const MAX_DOMAIN_ROUTING_NUM: u32 = 65_536;

#[unsafe(no_mangle)]
#[used]
pub static PARAM: BpfDaeParam = BpfDaeParam::zeroed();

#[inline(always)]
pub fn param_control_plane_pid() -> u32 {
    unsafe { core::ptr::addr_of!(PARAM.control_plane_pid).read_volatile() }
}

#[inline(always)]
pub fn param_tproxy_port() -> u16 {
    unsafe { core::ptr::addr_of!(PARAM.tproxy_port).read_volatile() as u16 }
}

#[inline(always)]
pub fn param_tproxy_port_protect() -> bool {
    unsafe { core::ptr::addr_of!(PARAM.tproxy_port_protect).read_volatile() != 0 }
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
