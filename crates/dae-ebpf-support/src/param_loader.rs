use std::mem::size_of;

use crate::{BpfDaeParam, DaeParamInput, build_dae_param};

pub const DAE_PARAM_SYMBOL: &str = "PARAM";
pub const DAE_PARAM_SYMBOL_SIZE: usize = size_of::<BpfDaeParam>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaeParamRequirement {
    pub field: &'static str,
    pub source: &'static str,
    pub requirement: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeParamPayload {
    pub symbol: &'static str,
    pub rust_layout_size: usize,
    pub tproxy_port_host: u16,
    pub tproxy_port_big_endian: u32,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub has_bpf_get_current_task: bool,
    pub padding: u8,
}

pub fn dae_param_requirements() -> [DaeParamRequirement; 6] {
    [
        DaeParamRequirement {
            field: "tproxy_port",
            source: "DaeParamInput.tproxy_port / --tproxy-port",
            requirement: "must be packed as network-order u16 widened to u32 by Rust/Aya loader before BPF load",
        },
        DaeParamRequirement {
            field: "control_plane_pid",
            source: "os.Getpid() / Rust daemon pid",
            requirement: "must identify the userspace control-plane process before BPF load",
        },
        DaeParamRequirement {
            field: "dae0_ifindex",
            source: "netns.Dae0().Attrs().Index",
            requirement: "must be read after dae netns setup and before tc attach",
        },
        DaeParamRequirement {
            field: "dae_netns_id",
            source: "netns.NetnsID()",
            requirement: "must be read from the created dae netns before BPF load",
        },
        DaeParamRequirement {
            field: "dae0peer_mac",
            source: "netns.Dae0Peer().Attrs().HardwareAddr",
            requirement: "must be the six-byte peer MAC used by L2 redirect rewrite",
        },
        DaeParamRequirement {
            field: "has_bpf_get_current_task",
            source: "features.HaveProgramHelper(..., bpf_get_current_task)",
            requirement: "must reflect both cgroup helper probes before BPF load",
        },
    ]
}

pub fn build_dae_param_payload(input: DaeParamInput) -> DaeParamPayload {
    let packed = build_dae_param(input);
    DaeParamPayload {
        symbol: DAE_PARAM_SYMBOL,
        rust_layout_size: DAE_PARAM_SYMBOL_SIZE,
        tproxy_port_host: input.tproxy_port,
        tproxy_port_big_endian: packed.tproxy_port,
        control_plane_pid: packed.control_plane_pid,
        dae0_ifindex: packed.dae0_ifindex,
        dae_netns_id: packed.dae_netns_id,
        dae0peer_mac: packed.dae0peer_mac,
        has_bpf_get_current_task: packed.has_bpf_get_current_task == 1,
        padding: packed.padding,
    }
}

pub fn direct_tc_object_loader_rewrites_param() -> bool {
    false
}

pub fn dae_param_runtime_values_present(payload: &DaeParamPayload) -> bool {
    payload.tproxy_port_host != 0
        && payload.control_plane_pid != 0
        && payload.dae0_ifindex != 0
        && payload.dae_netns_id != 0
        && payload.dae0peer_mac != [0; 6]
}

pub fn param_aware_load_admitted(
    rust_loader_proven: bool,
    object_param_symbol_found: bool,
    object_param_symbol_size: Option<usize>,
    payload: &DaeParamPayload,
) -> bool {
    rust_loader_proven
        && object_param_symbol_found
        && object_param_symbol_size == Some(DAE_PARAM_SYMBOL_SIZE)
        && dae_param_runtime_values_present(payload)
}
