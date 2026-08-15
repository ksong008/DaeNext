use std::fs;
use std::path::{Path, PathBuf};

use dae_ebpf_support::{
    AttachBackend, map_ids, open_live_loaded_tproxy_listen_socket_map_in_netns,
};
use serde_json::{Value, json};

mod command;
mod deep_area;
mod host_ops;
mod live_dns_probe;
mod live_tcp_probe;
mod live_udp_probe;
mod native_assets;
mod native_ebpf;
mod netns_link;
mod reload_runtime;
mod report;
mod resident;
mod resident_allocator;
pub(crate) use resident_lan::configured_lan_ifaces;
mod resident_dataplane;
mod resident_interfaces;
pub(crate) use resident_interfaces::{configured_wan_ifaces, validate_resident_runtime_interfaces};
mod resident_lan;
mod resident_routing;
mod topology;
mod udp_dns_datapath_contract;
mod udp_io;

use command::{
    bpf_dae_snapshot, ensure_safe_run_root, path_string, runtime_resource_leftovers,
    wait_for_loaded_map_cleanup,
};
use live_dns_probe::{
    ActiveDnsEvidence, DEFAULT_ACTIVE_DNS_QNAME, DEFAULT_ACTIVE_DNS_TARGET_PORT,
    DEFAULT_ACTIVE_DNS_UPSTREAM_IP, DEFAULT_ACTIVE_DNS_UPSTREAM_PORT,
    push_active_dns_preflight_checks, run_active_dns_probe,
};
use live_tcp_probe::{
    ActiveTcpEvidence, DEFAULT_ACTIVE_TCP_CLIENT_IP, DEFAULT_ACTIVE_TCP_MPTCP,
    DEFAULT_ACTIVE_TCP_SO_MARK, DEFAULT_ACTIVE_TCP_TARGET_IP, DEFAULT_ACTIVE_TCP_TARGET_PORT,
    attach_lan_program, cleanup_active_tcp_resources, push_active_tcp_preflight_checks,
    run_active_tcp_probe, run_active_tcp_relay_probe, setup_client_topology,
    setup_production_ipv4_datapath, show_host_program_stats, show_lan_program,
    show_lan_program_stats, show_peer_program_stats, update_existing_routing_map,
    update_routing_map,
};
use live_udp_probe::{
    ActiveUdpEvidence, DEFAULT_ACTIVE_UDP_TARGET_IP, DEFAULT_ACTIVE_UDP_TARGET_PORT,
    active_udp_loopback_target_cidr, active_udp_loopback_target_present,
    add_active_udp_loopback_target, delete_active_udp_loopback_target,
    push_active_udp_preflight_checks, run_active_udp_probe,
};
use native_ebpf::NativeEbpfRuntimeState;
pub use netns_link::{NetnsLinkMode, parse_netns_link_mode};
use reload_runtime::{ReloadRuntimeEvidence, run_reload_runtime_parity_probe};
use report::{live_handoff_json, report_value, socket_options_verified};
pub(crate) use resident::preflight_resident_runtime_candidate;
pub(crate) use resident::{
    ResidentActiveGenerationSnapshot, ResidentPreparedGeneration,
    ResidentProductionRuntimeReadHandle, prepare_resident_production_generation,
    start_prepared_resident_production_runtime,
    start_resident_production_runtime_with_latency_seed_and_dns_reload_snapshot,
};
pub use resident::{ResidentProductionRuntime, start_resident_production_runtime_with_asset_dirs};
pub(crate) use resident_dataplane::facade::{
    RESIDENT_MANUAL_PROBE_TASK_NAME, ResidentDnsReloadSnapshot, ResidentEventLogDecision,
    ResidentEventLogPolicy, ResidentEventLogPrefilter, ResidentEventLogSink, ResidentEventMetadata,
    ResidentManualProbeHandle, ResidentNodeSourceAdmission, ResidentTrafficCounters,
    effective_process_memory_capacity, fetch_http_url_via_default_proxy_async,
    resident_live_adapter_config_assessment, resident_live_adapter_entry_missing,
    resident_live_adapter_entry_remote_live_matrix_ready, resident_live_adapter_matrix_contract,
    resident_live_adapter_udp_probe, resident_live_matrix_evidence_from_env,
    resident_manual_latency_probe_concurrency_from_config, resident_node_source_admissions,
    resident_runtime_defaults_contract, resident_tcp_latency_probe_timeout_from_config,
    run_resident_manual_latency_probe_helper, run_resident_manual_latency_probe_helper_streaming,
};
pub use resident_dataplane::facade::{
    ResidentProxyOwnershipBenchmarkFixture, ResidentTcpSelectionBenchmarkFixture,
    resident_proxy_ownership_benchmark_fixture, resident_tcp_selection_benchmark_fixture,
};
use topology::{
    attach_host_program, attach_peer_program, cleanup_production_topology, preflight_checks,
    read_topology_values, setup_production_topology, show_host_program, show_peer_program,
    write_param_image,
};

#[path = "production_runtime_owner/root/options.rs"]
mod options;
pub use self::options::*;
#[path = "production_runtime_owner/root/owner_report.rs"]
mod owner_report;
pub use self::owner_report::*;
#[path = "production_runtime_owner/root/execute_smoke.rs"]
mod execute_smoke;
use self::execute_smoke::*;
#[path = "production_runtime_owner/root/tests.rs"]
#[cfg(test)]
mod tests;
