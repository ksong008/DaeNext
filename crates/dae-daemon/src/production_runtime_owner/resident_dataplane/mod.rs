use std::collections::{BTreeMap, HashSet};
use std::fs;
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
use self::plan::build_resident_dataplane_plan;
use self::tcp::{ResidentTcpRouter, probe_resident_proxy_tcp_async, resident_tcp_accept_loop};
use self::udp::{
    probe_resident_proxy_dns_udp_async, probe_resident_proxy_udp_async, resident_udp_handler_name,
    resident_udp_loop,
};
use super::resident_routing::build_resident_userspace_routing_matcher;

mod adapter_matrix;
mod client;
mod direct;
mod display;
mod dns;
mod events;
mod execution;
mod execution_types;
mod plan;
mod runtime_owner;
mod tcp;
mod udp;
mod vision;

#[path = "runtime/defaults.rs"]
mod defaults;
pub(crate) use self::defaults::*;
#[path = "runtime/runtime.rs"]
mod runtime;
pub(super) use self::runtime::*;
#[path = "runtime/metrics.rs"]
mod metrics;
pub(super) use self::metrics::*;
#[path = "runtime/workers.rs"]
mod workers;
use self::display::*;
pub(super) use self::workers::*;
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
pub(super) use self::runtime_owner::*;
