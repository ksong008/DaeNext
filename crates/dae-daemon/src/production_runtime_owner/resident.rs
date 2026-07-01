use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use dae_config::Config;
use dae_ebpf_support::{
    AttachBackend, LiveLoadedTproxyListenSocketMap, RuntimeMapCapacity, RuntimeMapSnapshot,
    dae_cgroup_attach_matrix, map_capacity_by_id, map_capacity_fast_by_id, map_catalog, map_ids,
    open_live_loaded_tproxy_listen_socket_map_in_netns, runtime_map_name_matches,
};
use serde_json::{Value, json};

use super::command::{
    bpf_dae_snapshot, cleanup_stale_production_owner_after_crash, path_string,
    runtime_resource_leftovers, wait_for_loaded_map_cleanup,
};
#[cfg(feature = "native-ebpf")]
use super::native_ebpf::EMBEDDED_NATIVE_OBJECT_IDENTITY;
use super::native_ebpf::{
    NativeEbpfRuntimeState, NativeParamObjectPreparation, prepare_native_param_object,
};
use super::netns_link::resolve_netns_link_mode_from_env;
use super::report::{live_handoff_json, socket_options_verified};
use super::resident_dataplane::{
    ResidentDataplaneRuntime, ResidentDnsReloadSnapshot, ResidentManualProbeHandle,
    start_resident_dataplane_workers,
};
use super::resident_interfaces::{
    attach_resident_lan_egress_program, attach_resident_wan_programs,
    configure_resident_kernel_parameters, configured_wan_ifaces, iface_exists_in_sysfs_root,
    interface_arphrd_from_sysfs_root, interface_link_layer, interface_link_layer_from_sysfs_root,
    resident_interface_validation_checks, resident_kernel_feature_checks, sys_class_net_path,
};
use super::resident_lan::{
    attach_resident_lan_program, cleanup_resident_lan_programs, configured_lan_ifaces,
    lan_start_plan_json, show_resident_lan_program,
};
use super::resident_routing::{
    ResidentGeodataStore, ResidentRoutingApplyCache, seed_resident_outbound_connectivity_maps,
    update_existing_resident_routing_map, update_new_resident_routing_map,
};
use super::topology::{
    attach_host_program, attach_peer_program, cleanup_production_topology, preflight_checks,
    read_topology_values, setup_production_ip_datapath, show_host_program, show_peer_program,
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
mod interface_monitor;
use self::interface_monitor::*;
mod start_flow;
use self::start_flow::*;
mod cgroup_attach;
use self::cgroup_attach::*;
mod startup_report;
use self::startup_report::*;
mod routing_map_discovery;
use self::routing_map_discovery::*;
mod artifact_env;
use self::artifact_env::*;
#[cfg(test)]
mod tests;
