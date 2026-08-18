pub use super::RESIDENT_MANUAL_PROBE_TASK_NAME;
pub use super::adapter_matrix::{
    resident_live_adapter_entry_missing, resident_live_adapter_entry_remote_live_matrix_ready,
    resident_live_adapter_matrix_contract, resident_live_matrix_evidence_from_env,
};
pub use super::allocator_hooks::{
    ResidentAllocatorBusyKind, ResidentAllocatorHooks, ResidentAllocatorReclaimReason,
    ResidentAllocatorRuntimeHooks, ResidentAllocatorWorkerKind, set_resident_allocator_hooks,
};
pub use super::defaults::{
    next_resident_runtime_generation, resident_manual_latency_probe_concurrency_from_config,
    resident_runtime_defaults_contract, resident_tcp_latency_probe_timeout_from_config,
};
pub use super::dns::ResidentDnsReloadSnapshot;
pub use super::events::{
    ResidentEventLogDecision, ResidentEventLogPolicy, ResidentEventLogPrefilter,
    ResidentEventLogSink, ResidentEventMetadata, set_event_log_policies, set_event_log_sink,
};
pub use super::generation::{
    ResidentDataplaneGeneration, resident_dataplane_generation_lifetime_counts,
};
pub use super::geodata::{
    GeodataResolver as ResidentGeodataStore, SharedResidentIpPrefixSet, geodata_report_json,
};
pub use super::host_routing_plan::{
    MatchSetBytes, ResidentRoutingPlan, build_resident_userspace_routing_matcher_with_geodata,
    build_routing_plan_with_geodata_resolver, domain_set_json,
};
#[cfg(feature = "benchmark-support")]
pub use super::memory_bench::{
    ResidentTcpSelectionBenchmarkFixture, resident_tcp_selection_benchmark_fixture,
};
#[cfg(feature = "benchmark-support")]
pub use super::ownership_bench::{
    ResidentProxyOwnershipBenchmarkFixture, resident_proxy_ownership_benchmark_fixture,
};
pub use super::plan::{
    ResidentNodeSourceAdmission, ResidentPreparedDataplane,
    build_resident_prepared_dataplane_with_geodata, resident_node_source_admissions,
};
pub use super::read_view::ResidentDataplaneReadHandle;
pub use super::remote_strategy_live_tests::{
    resident_live_adapter_config_assessment, resident_live_adapter_udp_probe,
};
pub use super::runtime::ResidentDataplaneRuntime;
pub use super::runtime_owner::{
    ResidentManualProbeHandle, run_resident_manual_latency_probe_helper,
    run_resident_manual_latency_probe_helper_streaming,
};
pub use super::subscription_fetch::fetch_http_url_via_default_proxy_async;
pub use super::workers::{ResidentDataplaneStartContext, start_resident_dataplane_workers};
pub use dae_resident_core::ResidentTrafficCounters;
pub use dae_resident_core::{
    effective_process_memory_capacity, resident_datapath_postflight_interval_seconds_default,
    selected_resident_runtime_profile_name,
};

#[cfg(any(test, feature = "test-support"))]
pub use super::host_routing_plan::{
    ResidentDomainSet, build_resident_userspace_routing_matcher, build_routing_plan,
    build_routing_plan_with_asset_dirs,
};
