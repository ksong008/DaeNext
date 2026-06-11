use crate::abi::BpfDaeParam;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaeParamInput {
    pub tproxy_port: u16,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub has_bpf_get_current_task: bool,
}

pub fn htons(value: u16) -> u16 {
    value.to_be()
}

pub fn build_dae_param(input: DaeParamInput) -> BpfDaeParam {
    BpfDaeParam {
        tproxy_port: u32::from(htons(input.tproxy_port)),
        control_plane_pid: input.control_plane_pid,
        dae0_ifindex: input.dae0_ifindex,
        dae_netns_id: input.dae_netns_id,
        dae0peer_mac: input.dae0peer_mac,
        has_bpf_get_current_task: u8::from(input.has_bpf_get_current_task),
        padding: 0,
    }
}
