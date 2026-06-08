use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
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
pub(crate) use self::events::{ResidentEventLogSink, set_event_log_sink};
use self::events::{append_event, path_string};
use self::plan::build_resident_dataplane_plan;
use self::tcp::{ResidentTcpRouter, probe_resident_proxy_tcp, resident_tcp_accept_loop};
use self::udp::{probe_resident_proxy_dns_udp, probe_resident_proxy_udp, resident_udp_loop};
use super::resident_routing::build_resident_userspace_routing_matcher;

mod adapter_matrix;
mod client;
mod direct;
mod dns;
mod events;
mod execution;
mod io;
mod plan;
mod tcp;
mod udp;
mod vision;

include!("runtime/defaults.rs");
include!("runtime/runtime.rs");
include!("runtime/metrics.rs");
include!("runtime/workers.rs");
include!("runtime/health_checks.rs");
include!("runtime/remote_strategy_live_tests.rs");
include!("runtime/matrix.rs");
include!("runtime/env.rs");
