pub mod abi;
pub mod admission;
pub mod attach;
#[cfg(feature = "aya-loader")]
pub mod aya_loader;
pub mod capability;
pub mod cgroup;
pub mod connectivity;
pub mod kernel;
pub mod kernel_program;
pub mod kernel_program_packet;
pub mod kernel_program_trace;
pub mod loader;
pub mod maps;
pub mod opt_in;
pub mod param;
pub mod param_loader;
pub mod param_object;
pub mod routing_maps;
pub mod runtime_maps;
pub mod sockmap;
pub mod temporary_map;
pub mod temporary_program;
pub mod tproxy_listener;

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod cgroup_tests;
#[cfg(test)]
mod kernel_program_packet_tests;
#[cfg(test)]
mod kernel_program_tests;
#[cfg(test)]
mod kernel_program_trace_tests;
#[cfg(test)]
mod opt_in_tests;
#[cfg(test)]
mod tests;

pub use abi::{
    BASIC_FEATURE_VERSION, BPF_LOOP_FEATURE_VERSION, BPF_TIMER_FEATURE_VERSION, BpfAbiContract,
    BpfDaeParam, BpfDomainRouting, BpfIpBytes, BpfMatchSet, BpfOutboundConnectivityQuery,
    BpfPidPname, BpfRedirectEntry, BpfRedirectTuple, BpfRoutingResult, BpfTuplesKey,
    BpfUdpConnState, CHECKSUM_FEATURE_VERSION, LINK_HDR_LEN_ETHERNET, LINK_HDR_LEN_NONE,
    MAX_MATCH_SET_LEN, SK_ASSIGN_FEATURE_VERSION, TASK_COMM_LEN, TPROXY_MARK, bpf_abi_contract,
};
pub use admission::{
    NativeBackendAdmissionCheck, NativeBackendAdmissionEvidence, NativeBackendAdmissionReport,
    OptionalAdmissionEvidence, native_backend_admission_report, native_backend_required_checks,
};
pub use attach::{
    AttachBackend, AttachBackendAvailability, AttachBackendPlan, DaeTcAttachLine,
    DaeTcAttachMatrixInput, DaeTcAttachRole, ETH_P_ALL, TCX_ATTACH_FEATURE_VERSION,
    TcAttachBackendReport, TcAttachDirection, TcAttachLayer, TcAttachSectionPrefix, TcAttachTarget,
    TcBpfAttachSpec, TcCommandSpec, TcNativeAttachSpec, TcxAttachOrder, dae_tc_attach_matrix,
    plan_attach_backend, tc_handle,
};
#[cfg(feature = "aya-loader")]
pub use aya_loader::{
    AyaCgroupAttachDetachReport, AyaGoAdoptionPinReport, AyaLoadedMapSpec, AyaMapSpecMismatch,
    AyaPinnedObject, AyaTcAttachDetachReport, AyaTcxProgramOrderEntry,
    AyaTraceAttachRingbufSmokeOptions, AyaTraceAttachRingbufSmokeReport,
    AyaTraceAttachSmokeTrigger, AyaTraceConfig, AyaTraceLoadPinReport, AyaTraceLoaderOptions,
    AyaUserspaceBytesLoaderOptions, AyaUserspaceLoadReport, AyaUserspaceLoadedObject,
    AyaUserspaceLoaderOptions, DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES, PinnedTcAttachOptions,
    PinnedTcAttachReport, TRACE_CORE_SIDELOAD_ENABLED, attach_pin_aya_sched_classifier,
    attach_ringbuf_smoke_aya_trace_object, aya_userspace_load_report,
    load_attach_aya_cgroup_program, load_attach_aya_sched_classifier,
    load_attach_detach_aya_cgroup_program, load_attach_detach_aya_sched_classifier,
    load_aya_userspace_object, load_aya_userspace_object_bytes, load_pin_aya_trace_object,
    pin_aya_loaded_object_for_go_adoption,
};
pub use capability::{EbpfBackendCapabilityReport, report_only_ebpf_backend_capability};
pub use cgroup::{
    DaeCgroupAttachLine, DaeCgroupAttachRole, DaeCgroupProgramKind, PinnedCgroupAttachOptions,
    PinnedCgroupAttachReport, attach_pin_cgroup_monitor, dae_cgroup_attach_matrix,
    detect_cgroup2_mount, detect_cgroup2_mount_from_proc_mounts,
};
pub use connectivity::{
    ConnectivityEvent, ConnectivityKey, ConnectivityMap, ConnectivityMapFdCache,
    ConnectivityWritePlan, connectivity_write_plan, update_connectivity_map_by_id,
};
pub use kernel::{FeatureGateReport, Version};
pub use kernel_program::{
    KernelProgramCoverageLine, KernelProgramCoverageStatus, KernelProgramFallbackRetirementBlocker,
    KernelProgramFallbackRetirementEvidence, KernelProgramFallbackRetirementGateReport,
    KernelProgramFeasibilityReport, KernelProgramParityAdmissionReport, KernelProgramParityCheck,
    KernelProgramParityEvidence, KernelProgramParityEvidenceLine,
    KernelProgramParityEvidenceStatus, KernelProgramSurface, TproxyDataplaneAdmissionReport,
    TraceDiagnosticGateReport, kernel_program_fallback_retirement_gate_report,
    kernel_program_feasibility_report, kernel_program_parity_admission_report,
    kernel_program_parity_evidence_queue, kernel_program_parity_required_checks,
    map_abi_btf_verifier_evidence_admitted, map_abi_btf_verifier_evidence_queue,
    matched_go_rust_benchmark_evidence_admitted, matched_go_rust_benchmark_evidence_queue,
    packet_level_golden_evidence_admitted, packet_level_golden_evidence_queue,
    remote_host_write_runtime_evidence_admitted, remote_host_write_runtime_evidence_queue,
    tproxy_dataplane_admission_report, tproxy_dataplane_evidence_queue,
    tproxy_dataplane_required_checks, tproxy_kernel_program_coverage, trace_diagnostic_gate_report,
    trace_kernel_program_coverage,
};
pub use kernel_program_packet::{
    ETH_HLEN, ETH_P_IP_NETWORK, ETH_P_IPV6_NETWORK, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
    KernelPacketGoldenCase, KernelPacketParseDisposition, KernelPacketParseReport,
    KernelPacketParsed, NDP_REDIRECT, packet_level_golden_cases, parse_kernel_program_packet,
};
pub use kernel_program_trace::{
    TRACE_CORE_SIDELOAD_DISABLED_REASON, TraceConfigRewriteContract, TraceCoreSideloadGateReport,
    TraceEventAbiContract, TraceKprobeProgramSpec, TraceTargetDiscoveryContract,
    trace_config_rewrite_contract, trace_core_sideload_gate_report, trace_event_abi_contract,
    trace_kprobe_evidence_admitted, trace_kprobe_evidence_queue, trace_kprobe_program_specs,
    trace_target_discovery_contract,
};
pub use loader::{
    LoaderBackend, LoaderContract, PinnedMapAction, loader_contract, pinned_map_action,
};
pub use maps::{
    MapSpec, RuntimeMapContract, RuntimeMapRole, map_catalog, pinned_reuse_maps,
    runtime_map_contract,
};
pub use opt_in::{
    NativeBackendOptInDecision, NativeBackendOptInReason, NativeBackendOptInRequest,
    native_backend_opt_in_decision,
};
pub use param::{DaeParamInput, build_dae_param, htons};
pub use param_loader::{
    DAE_PARAM_SYMBOL, DAE_PARAM_SYMBOL_SIZE, DaeParamPayload, DaeParamRequirement,
    build_dae_param_payload, dae_param_requirements, dae_param_runtime_values_present,
    direct_tc_object_loader_rewrites_param, param_aware_load_admitted,
};
pub use param_object::{
    ParamObjectRewriteReport, ParamSymbolLocation, locate_param_symbol_in_object,
    param_from_object_bytes, param_to_object_bytes, read_param_from_object,
    write_param_aware_object,
};
pub use routing_maps::{
    BpfLpmKey, DomainRoutingMapApplyReport, DomainRoutingMapEntry, LpmArrayMapEntry,
    LpmMapBuildSpec, LpmMapEntry, RoutingMapApplyReport, RoutingMapEntry,
    apply_domain_routing_map_by_id, apply_routing_maps_by_id,
    apply_routing_maps_with_lpm_build_by_id,
};
pub use runtime_maps::{
    MAP_USAGE_PRESSURE_RATIO, MAP_USAGE_WARNING_RATIO, RuntimeMapCapacity, RuntimeMapInfo,
    count_map_entries_by_fd, count_map_entries_by_id, delete_map_elem_bytes, lookup_map_elem_bytes,
    map_capacity_by_fd, map_capacity_by_id, map_ids, map_info, open_map_fd, update_map_elem_bytes,
};
pub use sockmap::{
    ListenSocketMapFdSmoke, LiveLoadedTproxyListenSocketMap, LoadedListenSocketMapFdSmoke,
    LoadedTproxyListenSocketMapFdSmoke, open_live_loaded_tproxy_listen_socket_map,
    open_live_loaded_tproxy_listen_socket_map_in_netns,
    open_tproxy_listener_set_and_update_sockmap_by_id, run_listen_socket_map_fd_smoke,
    run_loaded_listen_socket_map_fd_smoke, run_loaded_tproxy_listen_socket_map_fd_smoke,
    update_listen_socket_map_by_id,
};
pub use temporary_map::{
    TemporaryBpfArrayMapSmoke, default_bpffs_mount, run_temporary_array_map_pin_smoke,
};
pub use temporary_program::{
    TemporaryBpfProgramAttachSmoke, run_temporary_socket_filter_attach_smoke,
};
pub use tproxy_listener::{
    TproxyListenerSet, TproxySocketOptions, open_tproxy_listener_set,
    open_tproxy_listener_set_in_netns, open_transparent_udp_socket_bound,
    open_transparent_udp_socket_bound_in_netns,
};
