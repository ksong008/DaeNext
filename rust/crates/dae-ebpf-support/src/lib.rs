pub mod abi;
pub mod admission;
pub mod attach;
#[cfg(feature = "aya-loader")]
pub mod aya_loader;
pub mod capability;
pub mod cgroup;
pub mod connectivity;
pub mod kernel;
pub mod loader;
pub mod maps;
pub mod opt_in;
pub mod param;
pub mod param_loader;
pub mod param_object;
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
mod opt_in_tests;
#[cfg(test)]
mod tests;

pub use abi::{
    BASIC_FEATURE_VERSION, BPF_LOOP_FEATURE_VERSION, BPF_TIMER_FEATURE_VERSION, BpfAbiContract,
    BpfDaeParam, BpfDomainRouting, BpfMatchSet, BpfOutboundConnectivityQuery, BpfPidPname,
    BpfRedirectEntry, BpfRedirectTuple, BpfRoutingResult, BpfTuplesKey, BpfUdpConnState,
    CHECKSUM_FEATURE_VERSION, LINK_HDR_LEN_ETHERNET, LINK_HDR_LEN_NONE, MAX_MATCH_SET_LEN,
    SK_ASSIGN_FEATURE_VERSION, TASK_COMM_LEN, TPROXY_MARK, bpf_abi_contract,
};
pub use admission::{
    NativeBackendAdmissionCheck, NativeBackendAdmissionEvidence, NativeBackendAdmissionReport,
    OptionalAdmissionEvidence, native_backend_admission_report, native_backend_required_checks,
};
pub use attach::{
    AttachBackend, AttachBackendAvailability, AttachBackendPlan, DaeTcAttachLine,
    DaeTcAttachMatrixInput, DaeTcAttachRole, ETH_P_ALL, TCX_ATTACH_FEATURE_VERSION,
    TcAttachBackendReport, TcAttachDirection, TcAttachLayer, TcAttachSectionPrefix, TcAttachTarget,
    TcBpfAttachSpec, TcCommandSpec, TcNativeAttachSpec, dae_tc_attach_matrix, plan_attach_backend,
    tc_handle,
};
#[cfg(feature = "aya-loader")]
pub use aya_loader::{
    AyaCgroupAttachDetachReport, AyaTcAttachDetachReport, AyaUserspaceLoadReport,
    AyaUserspaceLoadedObject, AyaUserspaceLoaderOptions, aya_userspace_load_report,
    load_attach_aya_cgroup_program, load_attach_aya_sched_classifier,
    load_attach_detach_aya_cgroup_program, load_attach_detach_aya_sched_classifier,
    load_aya_userspace_object,
};
pub use capability::{EbpfBackendCapabilityReport, report_only_ebpf_backend_capability};
pub use cgroup::{
    DaeCgroupAttachLine, DaeCgroupAttachRole, DaeCgroupProgramKind, dae_cgroup_attach_matrix,
    detect_cgroup2_mount, detect_cgroup2_mount_from_proc_mounts,
};
pub use connectivity::{ConnectivityEvent, ConnectivityKey, ConnectivityMap};
pub use kernel::{FeatureGateReport, Version};
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
pub use runtime_maps::{RuntimeMapInfo, map_ids, map_info, open_map_fd, update_map_elem_bytes};
pub use sockmap::{
    ListenSocketMapFdSmoke, LiveLoadedTproxyListenSocketMap, LoadedListenSocketMapFdSmoke,
    LoadedTproxyListenSocketMapFdSmoke, open_live_loaded_tproxy_listen_socket_map,
    open_live_loaded_tproxy_listen_socket_map_in_netns, run_listen_socket_map_fd_smoke,
    run_loaded_listen_socket_map_fd_smoke, run_loaded_tproxy_listen_socket_map_fd_smoke,
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
