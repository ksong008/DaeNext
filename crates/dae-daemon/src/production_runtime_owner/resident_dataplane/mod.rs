use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dae_config::Config;
use dae_ebpf_support::LiveLoadedTproxyListenSocketMap;
use dae_outbound::{
    NetworkType, SourceShapeRegistryRow, source_shape_registry_contract, source_shape_registry_rows,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
use self::plan::{build_resident_dataplane_plan, build_resident_dataplane_plan_with_geodata};
use self::probe::*;
use self::tcp::{ResidentTcpRouter, resident_tcp_accept_loop};
use self::udp::{
    probe_resident_proxy_dns_udp_async, probe_resident_proxy_udp_async, resident_udp_loop,
    resident_udp_proxy_handler_name,
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
pub(in crate::production_runtime_owner::resident_dataplane) use self::resolver::{
    ResolvedHostAddrs, resolve_host_addrs_with_configured_fallback_dns_ttl,
    resolve_host_with_configured_fallback_dns, resolve_socket_addr_candidates,
    try_socket_addr_candidates,
};

#[path = "runtime/defaults.rs"]
mod defaults;
pub(crate) use self::defaults::*;
#[path = "runtime/runtime.rs"]
mod runtime;
pub(super) use self::runtime::*;
#[path = "runtime/group_selector_summary.rs"]
mod group_selector_summary;
pub(super) use self::group_selector_summary::*;
#[path = "runtime/metrics.rs"]
mod metrics;
pub(super) use self::metrics::*;
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
#[path = "runtime/health_checks.rs"]
mod health_checks;
pub(super) use self::health_checks::*;
#[path = "runtime/remote_strategy_live_tests.rs"]
mod remote_strategy_live_tests;
pub(crate) use self::remote_strategy_live_tests::*;
#[path = "runtime/matrix.rs"]
mod matrix;
use self::matrix::*;
pub(crate) use self::runtime_owner::*;
pub(crate) use self::subscription_fetch::fetch_http_url_via_default_proxy;
