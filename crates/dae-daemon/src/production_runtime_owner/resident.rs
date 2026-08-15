use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

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
    NativeEbpfRuntimeReadHandle, NativeEbpfRuntimeState, NativeParamObjectPreparation,
    native_cgroup_attach_preflight, prepare_native_param_object,
};
use super::netns_link::resolve_netns_link_mode_from_env;
use super::report::{live_handoff_json, socket_options_verified};
use super::resident_dataplane::facade::{
    ResidentDataplaneGeneration, ResidentDataplaneReadHandle, ResidentDataplaneRuntime,
    ResidentDataplaneStartContext, ResidentDnsReloadSnapshot, ResidentManualProbeHandle,
    ResidentPreparedDataplane, ResidentTrafficCounters, build_resident_dataplane_plan_with_geodata,
    build_resident_userspace_routing_matcher_with_geodata, next_resident_runtime_generation,
    resident_datapath_postflight_interval_seconds_default,
    resident_dataplane_generation_lifetime_counts, start_resident_dataplane_workers,
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
    attach_host_program, attach_peer_program, cleanup_production_topology, preflight_blockers,
    preflight_checks, production_names_check_failed, read_topology_values,
    refresh_production_names_check, setup_production_ip_datapath, show_host_program,
    show_peer_program, write_param_image,
};
use super::{
    DEFAULT_DAE_NETNS_ID, DEFAULT_HOST_SECTION, DEFAULT_PEER_SECTION, PRODUCTION_NETNS,
    ProductionRuntimeOwnerOptions,
};

mod constants;
use self::constants::*;
mod runtime_handle;
pub use self::runtime_handle::*;
mod runtime_read_view;
pub(crate) use self::runtime_read_view::*;
mod prepared_generation;
pub(crate) use self::prepared_generation::*;
mod start_entry;
pub use self::start_entry::*;
mod candidate_preflight;
pub(crate) use self::candidate_preflight::preflight_resident_runtime_candidate;
mod interface_policy;
use self::interface_policy::*;
mod interface_monitor;
use self::interface_monitor::*;
mod binding_registry;
use self::binding_registry::*;
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
