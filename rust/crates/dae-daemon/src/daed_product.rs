use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use dae_config::parser::parse_config;
use dae_config::schema::build_config;
use dae_config::{Config, Function, Param};
use dae_datapath::{
    ANYFROM_TIMEOUT_MS, DEFAULT_NAT_TIMEOUT_MS, DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
    DNS_NAT_TIMEOUT_MS, MAX_RETRY, PACKET_SNIFFER_POOL_MAX_ENTRIES, PACKET_SNIFFER_TTL_MS,
    UDP_TASK_POOL_MAX_QUEUES, UDP_TASK_QUEUE_LENGTH, udp_endpoint_pool_trim_target,
};
use regex::Regex;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::allocator::{
    AllocatorReclaimReason, allocator_live_heap_bytes, allocator_profile, allocator_reclaim,
    allocator_reclaim_snapshot_json, allocator_stats_json,
};
use crate::config_validate::{load_config_file, validate_config_file};
use crate::production_runtime_owner::{
    ResidentEventLogDecision, ResidentProductionRuntime, resident_live_adapter_config_assessment,
    resident_live_adapter_udp_probe, resident_runtime_defaults_contract,
    resident_runtime_environment_defaults, set_resident_event_log_policy,
    set_resident_event_log_sink, start_resident_production_runtime,
};

const DEFAULT_CONFIG_DIR: &str = "/etc/daed";
const DEFAULT_LISTEN: &str = "0.0.0.0:2023";
const DEFAULT_WEB_ROOT: &str = "/usr/share/daed/web";
const PRIMARY_STATE_STORE: &str = crate::service_contract::DAED_PRIMARY_STATE_STORE;
const PROTECTED_ROLLBACK_STATE_STORE: &str =
    crate::service_contract::DAED_PROTECTED_ROLLBACK_STATE_STORE;
const MAX_BODY_BYTES: usize = 1 << 20;
const TOKEN_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_LOG_MAX_ENTRIES: i64 = 10_000;
const DEFAULT_LOG_MAX_BYTES: i64 = 50 * 1024 * 1024;
const MIN_LOG_MAX_ENTRIES: i64 = 500;
const MAX_LOG_MAX_ENTRIES: i64 = 50_000;
const MIN_LOG_MAX_BYTES: i64 = 5 * 1024 * 1024;
const MAX_LOG_MAX_BYTES: i64 = 200 * 1024 * 1024;
const DEFAULT_LOG_QUERY_LIMIT: usize = 500;
const MAX_LOG_QUERY_LIMIT: usize = 2_000;
const MAX_LOG_LINE_BYTES: usize = 16 * 1024;
const MAX_LOG_FIELD_VALUE_LEN: usize = 1024;
const LOG_TAIL_ID_SCAN_BYTES: u64 = 1024 * 1024;
const LOG_PRUNE_INTERVAL: u64 = 256;
const LOG_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(500);
const LOG_STREAM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const LOG_STREAM_RETRY_MS: u64 = 3_000;
const PRODUCT_LOG_DIR: &str = "logs";
const PRODUCT_LOG_FILE: &str = "current.jsonl";
const PRODUCT_HTTP_WORKERS_ENV: &str = "HTTP_WORKERS";
const PRODUCT_HTTP_WORKERS_LEGACY_ENV: &str = "DAED_HTTP_WORKERS";
const PRODUCT_HTTP_QUEUE_ENV: &str = "HTTP_QUEUE";
const PRODUCT_HTTP_QUEUE_LEGACY_ENV: &str = "DAED_HTTP_QUEUE";
const PRODUCT_HTTP_WORKER_STACK_BYTES_ENV: &str = "HTTP_WORKER_STACK_BYTES";
const PRODUCT_HTTP_WORKER_STACK_BYTES_LEGACY_ENV: &str = "DAED_HTTP_WORKER_STACK_BYTES";
const PRODUCT_HTTP_WORKER_DEFAULT_MIN: usize = 4;
const PRODUCT_HTTP_WORKER_DEFAULT_MAX: usize = 16;
const PRODUCT_HTTP_WORKER_MIN: usize = 1;
const PRODUCT_HTTP_WORKER_MAX: usize = 128;
const PRODUCT_HTTP_QUEUE_DEFAULT: usize = 256;
const PRODUCT_HTTP_QUEUE_MIN: usize = 16;
const PRODUCT_HTTP_QUEUE_MAX: usize = 16_384;
const PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT: usize = 1024 * 1024;
const PRODUCT_HTTP_WORKER_STACK_BYTES_MIN: usize = 256 * 1024;
const PRODUCT_HTTP_WORKER_STACK_BYTES_MAX: usize = 8 * 1024 * 1024;
const PRODUCT_HTTP_WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(100);
const PRODUCT_MALLOC_ARENA_MAX_ENV: &str = "MALLOC_ARENA_MAX";
const PRODUCT_MALLOC_ARENA_MAX_DEFAULT: &str = "2";
const PRODUCT_JEMALLOC_CONF_ENV: &str = "MALLOC_CONF";
const PRODUCT_JEMALLOC_CONF_DEFAULT: &str =
    "background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,narenas:2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaedProductOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl DaedProductOutput {
    fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}

#[derive(Clone, Debug)]
struct RunOptions {
    config_dir: PathBuf,
    listen: String,
    state: PathBuf,
    web_root: PathBuf,
    api_only: bool,
}

#[derive(Clone, Debug)]
struct AppState {
    config_dir: PathBuf,
    state: PathBuf,
    web_root: PathBuf,
    api_only: bool,
    runtime: Arc<ProductRuntimeManager>,
    http_metrics: Arc<ProductHttpMetrics>,
}

#[derive(Debug, Default)]
struct ProductHttpMetrics {
    configured_workers: AtomicU64,
    queue_capacity: AtomicU64,
    worker_stack_bytes: AtomicU64,
    active_connections: AtomicU64,
    accepted_total: AtomicU64,
    enqueued_total: AtomicU64,
    rejected_total: AtomicU64,
    queue_depth: AtomicU64,
}

impl ProductHttpMetrics {
    fn configure(&self, config: ProductHttpWorkerConfig) {
        self.configured_workers
            .store(config.worker_count as u64, Ordering::Relaxed);
        self.queue_capacity
            .store(config.queue_capacity as u64, Ordering::Relaxed);
        self.worker_stack_bytes
            .store(config.worker_stack_bytes as u64, Ordering::Relaxed);
    }

    fn accepted(&self) {
        self.accepted_total.fetch_add(1, Ordering::Relaxed);
    }

    fn enqueued(&self) {
        self.enqueued_total.fetch_add(1, Ordering::Relaxed);
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    fn dequeued(&self) {
        let _ = self
            .queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    fn rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    fn opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Value {
        json!({
            "configuredWorkers": self.configured_workers.load(Ordering::Relaxed),
            "queueCapacity": self.queue_capacity.load(Ordering::Relaxed),
            "workerStackBytes": self.worker_stack_bytes.load(Ordering::Relaxed),
            "activeConnections": self.active_connections.load(Ordering::Relaxed),
            "acceptedTotal": self.accepted_total.load(Ordering::Relaxed),
            "enqueuedTotal": self.enqueued_total.load(Ordering::Relaxed),
            "rejectedTotal": self.rejected_total.load(Ordering::Relaxed),
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ProductHttpWorkerConfig {
    worker_count: usize,
    queue_capacity: usize,
    worker_stack_bytes: usize,
}

impl ProductHttpWorkerConfig {
    fn from_env() -> Self {
        let default_workers = thread::available_parallelism()
            .map(|parallelism| parallelism.get().saturating_mul(2))
            .unwrap_or(PRODUCT_HTTP_WORKER_DEFAULT_MIN)
            .clamp(
                PRODUCT_HTTP_WORKER_DEFAULT_MIN,
                PRODUCT_HTTP_WORKER_DEFAULT_MAX,
            );
        Self {
            worker_count: env_usize_with_legacy(
                PRODUCT_HTTP_WORKERS_ENV,
                PRODUCT_HTTP_WORKERS_LEGACY_ENV,
                default_workers,
                PRODUCT_HTTP_WORKER_MIN,
                PRODUCT_HTTP_WORKER_MAX,
            ),
            queue_capacity: env_usize_with_legacy(
                PRODUCT_HTTP_QUEUE_ENV,
                PRODUCT_HTTP_QUEUE_LEGACY_ENV,
                PRODUCT_HTTP_QUEUE_DEFAULT,
                PRODUCT_HTTP_QUEUE_MIN,
                PRODUCT_HTTP_QUEUE_MAX,
            ),
            worker_stack_bytes: env_usize_with_legacy(
                PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
                PRODUCT_HTTP_WORKER_STACK_BYTES_LEGACY_ENV,
                PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT,
                PRODUCT_HTTP_WORKER_STACK_BYTES_MIN,
                PRODUCT_HTTP_WORKER_STACK_BYTES_MAX,
            ),
        }
    }
}

fn env_usize_with_legacy(
    name: &str,
    legacy_name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> usize {
    std::env::var(name)
        .or_else(|_| std::env::var(legacy_name))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn product_runtime_defaults() -> Value {
    json!({
        "allocator": {
            "profile": allocator_profile(),
            "systemAllocatorArenaCap": {
                "env": PRODUCT_MALLOC_ARENA_MAX_ENV,
                "default": PRODUCT_MALLOC_ARENA_MAX_DEFAULT,
                "scope": "glibc/system allocator compatibility; ignored by jemalloc builds",
            },
            "jemallocPolicy": {
                "env": PRODUCT_JEMALLOC_CONF_ENV,
                "default": PRODUCT_JEMALLOC_CONF_DEFAULT,
                "scope": "jemalloc builds; keeps background purging and bounded arenas explicit",
            },
            "reclaim": {
                "startupControlBuilt": true,
                "reloadOldOwnerClosed": true,
                "reloadScopedResourcesFlushed": true,
                "idleAfterReload": true,
                "stopRuntime": true,
            },
        },
        "http": {
            "workers": {
                "env": PRODUCT_HTTP_WORKERS_ENV,
                "defaultPolicy": format!(
                    "available_parallelism * 2 clamped to {}..{}",
                    PRODUCT_HTTP_WORKER_DEFAULT_MIN, PRODUCT_HTTP_WORKER_DEFAULT_MAX
                ),
                "min": PRODUCT_HTTP_WORKER_MIN,
                "max": PRODUCT_HTTP_WORKER_MAX,
            },
            "queue": {
                "env": PRODUCT_HTTP_QUEUE_ENV,
                "default": PRODUCT_HTTP_QUEUE_DEFAULT,
                "min": PRODUCT_HTTP_QUEUE_MIN,
                "max": PRODUCT_HTTP_QUEUE_MAX,
            },
            "workerStackBytes": {
                "env": PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
                "default": PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT,
                "min": PRODUCT_HTTP_WORKER_STACK_BYTES_MIN,
                "max": PRODUCT_HTTP_WORKER_STACK_BYTES_MAX,
            },
        },
        "residentDataplane": resident_runtime_defaults_contract(),
    })
}

fn c10_final_blockers() -> Vec<String> {
    crate::c10_go_free_evidence::c10_go_free_product_chain_evidence_from_env().blockers
}

fn c10_final_gate_evidence() -> Value {
    crate::c10_go_free_evidence::c10_go_free_product_chain_evidence_from_env().report
}

fn c10_final_admission() -> Value {
    let evidence = crate::c10_go_free_evidence::c10_go_free_product_chain_evidence_from_env();
    json!({
        "liveDefaultSwitchApplied": evidence.report["liveDefaultSwitchApplied"].as_bool().unwrap_or(false),
        "rollbackValidationAppliedOnLiveHost": evidence.report["rollbackValidationAppliedOnLiveHost"].as_bool().unwrap_or(false),
        "releaseDefaultSwitchAdmission": evidence.report["releaseDefaultSwitchAdmission"].as_bool().unwrap_or(false),
        "productionPackageAdmission": evidence.report["productionPackageAdmission"].as_bool().unwrap_or(false),
        "goDaewingDefaultPathRemoved": evidence.report["goDaewingDefaultPathRemoved"].as_bool().unwrap_or(false),
        "fullGoFreeProductChainReady": evidence.ready,
        "evidence": evidence.report,
        "blockers": evidence.blockers,
    })
}

mod runtime_manager;
use self::runtime_manager::*;

#[derive(Clone, Debug)]
struct UserRecord {
    id: i64,
    username: String,
    password_hash: String,
    jwt_secret: String,
    json_storage: String,
    avatar: Option<String>,
    name: Option<String>,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, Vec<String>>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    extra_headers: Vec<(String, String)>,
}

impl HttpResponse {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json".to_owned(),
            body: format!("{value}\n").into_bytes(),
            extra_headers: Vec::new(),
        }
    }

    fn text(status: u16, content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
            extra_headers: Vec::new(),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8".to_owned(),
            body: Vec::new(),
            extra_headers: Vec::new(),
        }
    }
}

mod cli_commands;
pub use self::cli_commands::*;
mod service_metadata;
use self::service_metadata::*;
mod state_schema;
use self::state_schema::*;
mod http_server;
use self::http_server::*;
mod api_routes;
use self::api_routes::*;
mod runtime_overview;
use self::runtime_overview::*;
mod runtime_api;
use self::runtime_api::*;
mod resources;
use self::resources::*;
mod nodes_subscriptions_groups;
use self::nodes_subscriptions_groups::*;
mod runtime_materialization;
use self::runtime_materialization::*;
mod logs;
use self::logs::*;
mod latency;
use self::latency::*;
mod bundle;
use self::bundle::*;
mod package;
use self::package::*;
mod process_metrics;
use self::process_metrics::*;
mod common_helpers;
use self::common_helpers::*;
mod auth_storage;
use self::auth_storage::*;
mod http_io;
use self::http_io::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
