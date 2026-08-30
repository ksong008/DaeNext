#![recursion_limit = "256"]

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
use dae_outbound_core::{
    NetworkType, SourceShapeRegistryRow, source_shape_registry_contract, source_shape_registry_rows,
};
use serde_json::{Value, json};

use self::events::ResidentEventWriterHandle;
pub(crate) use self::events::ResidentEventWriterRuntime;
use self::events::{append_event, path_string};
pub(crate) use self::plan::ResidentPreparedDataplane;
use self::plan::build_resident_dataplane_plan;
use self::probe::*;
use self::tcp::{ResidentTcpRouter, ResidentTcpRuntimeConfig, resident_tcp_accept_loop_async};
use self::udp::{
    probe_resident_proxy_udp_async, resident_udp_loop_async, resident_udp_proxy_handler_name,
};
pub(crate) use dae_resident_plan::{
    resident_live_adapter_entry_missing, resident_live_adapter_entry_remote_live_matrix_ready,
    resident_live_adapter_matrix_contract, resident_live_adapter_matrix_entries,
    resident_live_matrix_evidence_from_env,
};

mod allocator_hooks;
mod client;
mod control_transport_owners;
mod direct;
mod dns;
mod dns_listener;
mod events;
mod execution;
pub mod facade;
pub(crate) mod geodata;
pub(crate) mod host_routing_plan;
#[cfg(feature = "benchmark-support")]
mod memory_bench;
#[cfg(feature = "benchmark-support")]
mod ownership_bench;
mod plan;
mod probe;
mod runtime_owner;
mod subscription_fetch;
mod tcp;
mod transport;
mod udp;
#[cfg(test)]
pub(crate) use self::allocator_hooks::resident_allocator_stats_json;
pub(crate) use self::allocator_hooks::{
    ResidentAllocatorBusyKind, ResidentAllocatorReclaimReason, ResidentAllocatorRuntimeHooks,
    ResidentAllocatorWorkerKind, resident_allocator_enter_busy, resident_allocator_request_reclaim,
    resident_allocator_runtime_hooks,
};
pub(crate) use self::dns::ResidentDnsReloadSnapshot;
pub(crate) use self::dns::{
    ResidentDnsDispatcher, ResidentDnsResolver, ResidentDnsUdpActorCompletion,
    ResidentDnsUdpActorLifecycle, ResidentDnsUdpActorRegistration,
};
#[cfg(test)]
pub(crate) use self::geodata::GeodataResolver as ResidentGeodataStore;
#[cfg(feature = "benchmark-support")]
pub use self::memory_bench::{
    ResidentTcpSelectionBenchmarkFixture, resident_tcp_selection_benchmark_fixture,
};
#[cfg(feature = "benchmark-support")]
pub use self::ownership_bench::{
    ResidentProxyOwnershipBenchmarkFixture, resident_proxy_ownership_benchmark_fixture,
};
pub(crate) use self::tcp::resident_dns_proxy_tcp_transport;
#[cfg(test)]
pub(crate) use self::transport::dns_tcp_wire::read_dns_tcp_payload_async;
pub(crate) use self::transport::dns_tcp_wire::{DnsTcpFrameReader, write_dns_tcp_payload_async};
#[cfg(test)]
pub(crate) use self::transport::quic_endpoint::quic_endpoint_metrics_snapshot;
pub(crate) use self::udp::resident_dns_proxy_udp_transport;
pub(crate) use dae_resident_core::*;
pub(crate) use dae_resident_dns::ResidentDnsUdpRuntimeConfig;
pub(crate) use dae_resident_plan::{
    display_name_from_link, execution_link_hash, graph_id_from_link_hash, link_hash,
    redacted_link_source,
};
pub(crate) use dae_resident_runtime::ResidentRuntimeCoordinator;
pub(crate) use dae_resident_runtime::{
    ResidentAsyncRuntimeShutdown, ResidentAsyncRuntimeTask, ResidentRuntimeExecutor,
    ResidentRuntimeExecutorConfig, ResidentRuntimeTaskRole, registered_resident_async_runtime_task,
};
pub(crate) use dae_resident_transport::resolve_host_addrs_with_configured_fallback_dns_ttl;
pub(crate) use dae_resident_transport::{
    ProxyDnsPendingRequestBytes, ProxyDnsQueuedRequestBytes, ProxyDnsRequestContext,
    ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestOutcome, ProxyDnsRequestStage,
    ProxyDnsResponseBytes,
};

#[path = "runtime/defaults.rs"]
mod defaults;
pub(crate) use self::defaults::*;
#[path = "runtime/runtime.rs"]
mod runtime;
pub(crate) use self::runtime::*;
#[path = "runtime/generation.rs"]
mod generation;
pub(crate) use self::generation::ResidentDataplaneGeneration;
use self::generation::{
    ResidentDataplaneGenerationLifetime, ResidentGenerationDrainControl,
    next_resident_dataplane_generation_id,
};
#[path = "runtime/generation_builder.rs"]
mod generation_builder;
use self::generation_builder::*;
pub(crate) use dae_resident_runtime::{
    ResidentDrainControl, ResidentDrainableGeneration, ResidentGenerationDrain,
    ResidentGenerationDrainHooks, ResidentGenerationDrainPolicy, ResidentRuntimeCleanupInventory,
    ResidentRuntimeCleanupReporter,
};
#[path = "runtime/read_view.rs"]
mod read_view;
pub(crate) use self::read_view::ResidentDataplaneReadHandle;
use self::read_view::ResidentRuntimeOwnerReadHandle;
#[path = "runtime/group_selector_summary.rs"]
mod group_selector_summary;
pub(crate) use self::group_selector_summary::*;
#[path = "runtime/workers.rs"]
mod workers;
use self::dns_listener::*;
#[path = "runtime/socket_buffers.rs"]
mod socket_buffers;
pub(crate) use self::socket_buffers::*;
#[path = "runtime/resources.rs"]
mod resources;
use self::resources::*;
#[path = "runtime/udp_resources.rs"]
mod udp_resources;
use self::udp_resources::*;
pub const RESIDENT_MANUAL_PROBE_TASK_NAME: &str = "daed-latency";
#[path = "runtime/hysteria2_owner.rs"]
mod hysteria2_owner;
pub(crate) use self::hysteria2_owner::{
    Hysteria2OwnerRegistryHandle, Hysteria2TransportLease, start_hysteria2_owner_registry,
    start_hysteria2_owner_registry_on,
};
#[cfg(test)]
pub(crate) use dae_resident_transport::Hysteria2UdpSessionLease;
#[path = "runtime/tuic_owner.rs"]
mod tuic_owner;
pub(crate) use self::tuic_owner::{
    TuicOwnerRegistryHandle, TuicTransportLease, start_tuic_owner_registry,
    start_tuic_owner_registry_on,
};
#[cfg(test)]
pub(crate) use dae_resident_transport::TuicUdpAssociationLease;
#[path = "runtime/juicity_owner.rs"]
mod juicity_owner;
pub(crate) use self::juicity_owner::{
    JuicityOwnerRegistryHandle, JuicityTransportLease, start_juicity_owner_registry,
    start_juicity_owner_registry_on,
};
#[path = "runtime/anytls_owner.rs"]
mod anytls_owner;
pub(crate) use self::anytls_owner::{
    AnyTlsOwnerRegistryHandle, start_anytls_owner_registry, start_anytls_owner_registry_on,
};
#[cfg(test)]
pub(crate) use dae_resident_transport::AnyTlsLogicalStreamLease;
#[path = "runtime/h2_carrier_owner.rs"]
mod h2_carrier_owner;
#[path = "runtime/transport_identity.rs"]
#[cfg(any(test, feature = "benchmark-support"))]
mod transport_identity;
#[cfg(test)]
pub(crate) use self::h2_carrier_owner::acquire_h2_carrier;
pub(crate) use self::h2_carrier_owner::{
    H2CarrierGenerationOwnerHandle, start_h2_carrier_generation_owner_on,
};
#[cfg(test)]
pub(crate) use dae_resident_transport::H2CarrierLease;
#[cfg(test)]
#[path = "runtime/h2_carrier_owner_live_tests.rs"]
mod h2_carrier_owner_live_tests;
#[path = "runtime/meek_transport_owner.rs"]
mod meek_transport_owner;
#[cfg(test)]
pub(crate) use self::meek_transport_owner::acquire_meek_transport;
pub(crate) use self::meek_transport_owner::{
    MeekTransportGenerationOwnerHandle, start_meek_transport_generation_owner_on,
};
#[cfg(test)]
#[path = "runtime/meek_transport_owner_live_tests.rs"]
mod meek_transport_owner_live_tests;
#[path = "runtime/vless_mux_owner.rs"]
mod vless_mux_owner;
pub(crate) use self::vless_mux_owner::{
    VlessMuxGenerationOwnerHandle, acquire_vless_mux_logical_stream,
    start_vless_mux_generation_owner_on,
};
#[cfg(test)]
#[path = "runtime/vless_mux_owner_live_tests.rs"]
mod vless_mux_owner_live_tests;
pub(crate) use dae_resident_transport::ResidentTransportOwnerRegistries;
#[cfg(test)]
#[path = "runtime/anytls_owner_live_tests.rs"]
mod anytls_owner_live_tests;
#[path = "runtime/health_checks.rs"]
mod health_checks;
#[cfg(test)]
#[path = "runtime/hysteria2_owner_live_tests.rs"]
mod hysteria2_owner_live_tests;
#[cfg(test)]
#[path = "runtime/juicity_owner_live_tests.rs"]
mod juicity_owner_live_tests;
#[cfg(test)]
#[path = "runtime/quic_owner_external_live_tests.rs"]
mod quic_owner_external_live_tests;
#[cfg(test)]
#[path = "runtime/tuic_owner_live_tests.rs"]
mod tuic_owner_live_tests;
pub(crate) use self::health_checks::*;
#[path = "runtime/health_scheduler.rs"]
mod health_scheduler;
pub(crate) use self::health_scheduler::*;
#[path = "runtime/matrix.rs"]
mod matrix;
#[path = "runtime/remote_strategy_live_tests.rs"]
mod remote_strategy_live_tests;
use self::matrix::*;
pub(crate) use self::runtime_owner::*;
