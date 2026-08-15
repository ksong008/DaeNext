pub(crate) use super::geodata::{
    GeodataResolver as ResidentGeodataStore, SharedResidentIpPrefixSet, geodata_report_json,
};
pub(crate) use super::host_routing_plan::{
    MatchSetBytes, ResidentRoutingPlan, build_resident_userspace_routing_matcher_with_geodata,
    build_routing_plan_with_geodata_resolver, domain_set_json,
};
#[cfg(test)]
pub(crate) use super::host_routing_plan::{
    ResidentDomainSet, build_resident_userspace_routing_matcher, build_routing_plan,
    build_routing_plan_with_asset_dirs,
};
pub(crate) use super::{
    RESIDENT_MANUAL_PROBE_TASK_NAME, ResidentAllocatorBusyKind, ResidentAllocatorHooks,
    ResidentAllocatorReclaimReason, ResidentAllocatorRuntimeHooks, ResidentAllocatorWorkerKind,
    ResidentDataplaneGeneration, ResidentDataplaneReadHandle, ResidentDataplaneRuntime,
    ResidentDataplaneStartContext, ResidentDnsReloadSnapshot, ResidentEventLogDecision,
    ResidentEventLogPolicy, ResidentEventLogPrefilter, ResidentEventLogSink, ResidentEventMetadata,
    ResidentManualProbeHandle, ResidentNodeSourceAdmission, ResidentPreparedDataplane,
    ResidentTrafficCounters, build_resident_dataplane_plan_with_geodata,
    effective_process_memory_capacity, fetch_http_url_via_default_proxy_async,
    next_resident_runtime_generation, resident_datapath_postflight_interval_seconds_default,
    resident_dataplane_generation_lifetime_counts, resident_live_adapter_config_assessment,
    resident_live_adapter_entry_missing, resident_live_adapter_entry_remote_live_matrix_ready,
    resident_live_adapter_matrix_contract, resident_live_adapter_udp_probe,
    resident_live_matrix_evidence_from_env, resident_manual_latency_probe_concurrency_from_config,
    resident_node_source_admissions, resident_runtime_defaults_contract,
    resident_tcp_latency_probe_timeout_from_config, run_resident_manual_latency_probe_helper,
    run_resident_manual_latency_probe_helper_streaming, selected_resident_runtime_profile_name,
    set_event_log_policies, set_event_log_sink, set_resident_allocator_hooks,
    start_resident_dataplane_workers,
};
pub use super::{
    ResidentProxyOwnershipBenchmarkFixture, ResidentTcpSelectionBenchmarkFixture,
    resident_proxy_ownership_benchmark_fixture, resident_tcp_selection_benchmark_fixture,
};
