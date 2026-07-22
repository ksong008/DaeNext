use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dae_config::Config;
use dae_ebpf_support::LiveLoadedTproxyListenSocketMap;
use dae_outbound::{
    NetworkType, SourceShapeRegistryRow, canonical_link_without_display_name,
    source_shape_registry_contract, source_shape_registry_rows,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::udp_payload_admission::ResidentUdpPayloadAdmission;

pub(crate) use self::adapter_matrix::{
    resident_live_adapter_entry_missing, resident_live_adapter_entry_remote_live_matrix_ready,
    resident_live_adapter_matrix_contract, resident_live_adapter_matrix_entries,
    resident_live_matrix_evidence_from_env,
};
pub(crate) use self::events::{
    ResidentEventLogDecision, ResidentEventLogPolicy, ResidentEventLogSink,
    ResidentEventWriterRuntime, set_event_log_policy, set_event_log_sink,
};
use self::events::{append_event, path_string};
pub(crate) use self::plan::{ResidentNodeSourceAdmission, resident_node_source_admissions};
use self::plan::{build_resident_dataplane_plan, build_resident_dataplane_plan_with_geodata};
use self::probe::*;
use self::tcp::{ResidentTcpRouter, ResidentTcpRuntimeConfig, resident_tcp_accept_loop_async};
use self::udp::{
    probe_resident_proxy_udp_async, resident_udp_loop_async, resident_udp_proxy_handler_name,
};
use super::resident_routing::{
    ResidentGeodataStore, build_resident_userspace_routing_matcher_with_geodata,
};

mod adapter_matrix;
mod client;
mod direct;
mod display;
mod dns;
mod dns_listener;
mod events;
mod execution;
mod execution_types;
mod memory_bench;
mod ownership_bench;
mod plan;
mod probe;
mod resolver;
mod runtime_owner;
mod subscription_fetch;
mod tcp;
mod udp;
mod vision;
pub(crate) use self::dns::ResidentDnsReloadSnapshot;
pub use self::memory_bench::{
    ResidentTcpSelectionBenchmarkFixture, resident_tcp_selection_benchmark_fixture,
};
pub use self::ownership_bench::{
    ResidentProxyOwnershipBenchmarkFixture, resident_proxy_ownership_benchmark_fixture,
};
pub(in crate::production_runtime_owner::resident_dataplane) use self::resolver::{
    ResolvedHostAddrs, authority_from_host_port,
    resolve_host_addrs_with_configured_fallback_dns_ttl, resolve_socket_addr_candidates,
    try_socket_addr_candidates,
};

#[path = "runtime/defaults.rs"]
mod defaults;
pub(crate) use self::defaults::*;
#[path = "runtime/runtime.rs"]
mod runtime;
pub(super) use self::runtime::*;
#[path = "runtime/executor.rs"]
mod executor;
use self::executor::*;
#[path = "runtime/stop_signal.rs"]
mod stop_signal;
pub(crate) use self::stop_signal::*;
#[path = "runtime/relay_deadline.rs"]
mod relay_deadline;
pub(crate) use self::relay_deadline::*;
#[path = "runtime/group_selector_summary.rs"]
mod group_selector_summary;
pub(super) use self::group_selector_summary::*;
#[path = "runtime/metrics.rs"]
mod metrics;
pub(crate) use self::metrics::ResidentTrafficCounters;
pub(super) use self::metrics::{ResidentDataplaneMetrics, ResidentTcpConnectionGuard};
#[path = "runtime/workers.rs"]
mod workers;
use self::display::*;
use self::dns_listener::*;
pub(super) use self::workers::*;
#[path = "runtime/socket_buffers.rs"]
mod socket_buffers;
pub(crate) use self::socket_buffers::*;
#[path = "runtime/resources.rs"]
mod resources;
use self::resources::*;
#[path = "runtime/udp_resources.rs"]
mod udp_resources;
use self::udp_resources::*;
#[path = "runtime/resource_profile.rs"]
mod resource_profile;
use self::resource_profile::*;
pub(crate) use self::resource_profile::{
    EffectiveProcessMemoryCapacity, effective_process_memory_capacity,
};
pub(super) use self::resource_profile::{
    resident_datapath_postflight_interval_seconds_default, selected_resident_runtime_profile_name,
};
#[path = "runtime/hysteria2_owner.rs"]
mod hysteria2_owner;
pub(crate) use self::hysteria2_owner::{
    Hysteria2OwnerRegistryHandle, Hysteria2TransportLease, Hysteria2UdpSessionLease,
    start_hysteria2_owner_registry, start_hysteria2_owner_registry_on,
};
#[path = "runtime/tuic_owner.rs"]
mod tuic_owner;
pub(crate) use self::tuic_owner::{
    TuicOwnerRegistryHandle, TuicTransportLease, TuicUdpAssociationLease,
    start_tuic_owner_registry, start_tuic_owner_registry_on,
};
#[path = "runtime/juicity_owner.rs"]
mod juicity_owner;
pub(crate) use self::juicity_owner::{
    JuicityOwnerRegistryHandle, JuicityTransportLease, start_juicity_owner_registry,
    start_juicity_owner_registry_on,
};
#[path = "runtime/anytls_owner.rs"]
mod anytls_owner;
pub(crate) use self::anytls_owner::{
    AnyTlsLogicalStreamLease, AnyTlsOwnerRegistryHandle, start_anytls_owner_registry,
    start_anytls_owner_registry_on,
};
#[path = "runtime/h2_carrier_owner.rs"]
mod h2_carrier_owner;
#[path = "runtime/transport_identity.rs"]
mod transport_identity;
pub(crate) use self::h2_carrier_owner::{
    H2CarrierGenerationOwnerHandle, H2CarrierLease, acquire_h2_carrier,
    start_h2_carrier_generation_owner, start_h2_carrier_generation_owner_on,
};
#[cfg(test)]
#[path = "runtime/h2_carrier_owner_live_tests.rs"]
mod h2_carrier_owner_live_tests;
#[path = "runtime/meek_transport_owner.rs"]
mod meek_transport_owner;
#[cfg(test)]
pub(crate) use self::meek_transport_owner::start_meek_transport_generation_owner_for_test;
pub(crate) use self::meek_transport_owner::{
    MeekTransportGenerationOwnerHandle, acquire_meek_transport,
    start_meek_transport_generation_owner, start_meek_transport_generation_owner_on,
};
#[cfg(test)]
#[path = "runtime/meek_transport_owner_live_tests.rs"]
mod meek_transport_owner_live_tests;
#[path = "runtime/vless_mux_owner.rs"]
mod vless_mux_owner;
#[cfg(test)]
pub(crate) use self::vless_mux_owner::start_vless_mux_generation_owner_for_test;
pub(crate) use self::vless_mux_owner::{
    VlessMuxGenerationOwnerHandle, acquire_vless_mux_logical_stream,
    start_vless_mux_generation_owner, start_vless_mux_generation_owner_on,
};
#[cfg(test)]
#[path = "runtime/vless_mux_owner_live_tests.rs"]
mod vless_mux_owner_live_tests;

#[derive(Clone, Default)]
pub(crate) struct ResidentTransportOwnerRegistries {
    hysteria2: Option<Hysteria2OwnerRegistryHandle>,
    tuic: Option<TuicOwnerRegistryHandle>,
    juicity: Option<JuicityOwnerRegistryHandle>,
    anytls: Option<AnyTlsOwnerRegistryHandle>,
}

impl ResidentTransportOwnerRegistries {
    pub(crate) fn new(
        hysteria2: Option<Hysteria2OwnerRegistryHandle>,
        tuic: Option<TuicOwnerRegistryHandle>,
        juicity: Option<JuicityOwnerRegistryHandle>,
    ) -> Self {
        Self {
            hysteria2,
            tuic,
            juicity,
            anytls: None,
        }
    }

    pub(crate) fn with_anytls(mut self, anytls: Option<AnyTlsOwnerRegistryHandle>) -> Self {
        self.anytls = anytls;
        self
    }

    pub(crate) fn hysteria2(&self) -> Option<Hysteria2OwnerRegistryHandle> {
        self.hysteria2.clone()
    }

    pub(crate) fn tuic(&self) -> Option<TuicOwnerRegistryHandle> {
        self.tuic.clone()
    }

    pub(crate) fn juicity(&self) -> Option<JuicityOwnerRegistryHandle> {
        self.juicity.clone()
    }

    pub(crate) fn anytls(&self) -> Option<AnyTlsOwnerRegistryHandle> {
        self.anytls.clone()
    }
}
#[cfg(test)]
#[path = "runtime/anytls_owner_live_tests.rs"]
mod anytls_owner_live_tests;
#[path = "runtime/health_checks.rs"]
mod health_checks;
#[cfg(test)]
#[path = "runtime/juicity_owner_live_tests.rs"]
mod juicity_owner_live_tests;
#[cfg(test)]
#[path = "runtime/tuic_owner_live_tests.rs"]
mod tuic_owner_live_tests;
pub(super) use self::health_checks::*;
#[path = "runtime/health_scheduler.rs"]
mod health_scheduler;
pub(super) use self::health_scheduler::*;
#[path = "runtime/remote_strategy_live_tests.rs"]
mod remote_strategy_live_tests;
pub(crate) use self::remote_strategy_live_tests::*;
#[path = "runtime/matrix.rs"]
mod matrix;
use self::matrix::*;
pub(crate) use self::runtime_owner::*;
pub(crate) use self::subscription_fetch::fetch_http_url_via_default_proxy;
