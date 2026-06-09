use std::env;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use dae_config::Config;
use dae_ebpf_support::{
    AttachBackend, LiveLoadedTproxyListenSocketMap, RuntimeMapCapacity, dae_cgroup_attach_matrix,
    map_capacity_by_id, map_catalog, map_ids, map_info,
    open_live_loaded_tproxy_listen_socket_map_in_netns, open_map_fd,
};
use serde_json::{Value, json};

use super::command::{
    bpf_dae_snapshot, path_string, runtime_resource_leftovers, wait_for_loaded_map_cleanup,
};
use super::native_ebpf::{NativeEbpfRuntimeState, prepare_native_param_object};
use super::netns_link::resolve_netns_link_mode_from_env;
use super::report::{live_handoff_json, socket_options_verified};
use super::resident_dataplane::{ResidentDataplaneRuntime, start_resident_dataplane_workers};
use super::resident_interfaces::{
    attach_resident_lan_egress_program, attach_resident_wan_programs,
    configure_resident_lan_kernel_parameters, configured_wan_ifaces, interface_link_layer,
};
use super::resident_lan::{
    attach_resident_lan_program, cleanup_resident_lan_programs, configured_lan_ifaces,
    lan_start_plan_json, show_resident_lan_program,
};
use super::resident_routing::{
    seed_resident_outbound_connectivity_maps, update_existing_resident_routing_map,
    update_new_resident_routing_map,
};
use super::topology::{
    attach_host_program, attach_peer_program, cleanup_production_topology, preflight_checks,
    read_topology_values, setup_production_ipv4_datapath, show_host_program, show_peer_program,
    write_param_image,
};
use super::{
    DEFAULT_DAE_NETNS_ID, DEFAULT_HOST_SECTION, DEFAULT_PEER_SECTION, PRODUCTION_NETNS,
    ProductionRuntimeOwnerOptions,
};

mod constants;
use self::constants::*;
mod runtime_handle;
pub use self::runtime_handle::*;
mod start_entry;
pub use self::start_entry::*;
mod interface_policy;
use self::interface_policy::*;
mod start_flow;
use self::start_flow::*;
mod startup_report;
use self::startup_report::*;
mod routing_map_discovery;
use self::routing_map_discovery::*;
mod artifact_env;
use self::artifact_env::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
