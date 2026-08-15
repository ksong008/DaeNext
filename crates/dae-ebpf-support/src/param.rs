use crate::abi::{
    BPF_DAE_PARAM_ABI_VERSION, BpfDaeParam, UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT,
    UDP_STATE_SATURATION_POLICY_FAIL_CLOSED,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaeParamInput {
    pub tproxy_port: u16,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub has_bpf_get_current_task: bool,
    pub task_struct_mm_offset: u32,
    pub mm_struct_arg_start_offset: u32,
}

pub fn htons(value: u16) -> u16 {
    value.to_be()
}

pub fn build_dae_param(input: DaeParamInput) -> BpfDaeParam {
    build_dae_param_with_protection(input, true)
}

/// Build the PARAM image while explicitly selecting the native transparent
/// proxy ingress guard.  The legacy `build_dae_param` entry point keeps the
/// documented/default-protected behavior for tools that do not expose the
/// switch yet.
pub fn build_dae_param_with_protection(
    input: DaeParamInput,
    tproxy_port_protect: bool,
) -> BpfDaeParam {
    BpfDaeParam {
        tproxy_port: u32::from(htons(input.tproxy_port)),
        control_plane_pid: input.control_plane_pid,
        dae0_ifindex: input.dae0_ifindex,
        dae_netns_id: input.dae_netns_id,
        dae0peer_mac: input.dae0peer_mac,
        has_bpf_get_current_task: u8::from(input.has_bpf_get_current_task),
        tproxy_port_protect: u8::from(tproxy_port_protect),
        task_struct_mm_offset: input.task_struct_mm_offset,
        mm_struct_arg_start_offset: input.mm_struct_arg_start_offset,
        abi_version: BPF_DAE_PARAM_ABI_VERSION,
        udp_state_saturation_policy: UDP_STATE_SATURATION_POLICY_FAIL_CLOSED,
        udp_state_idle_timeout_ns: UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT,
    }
}
