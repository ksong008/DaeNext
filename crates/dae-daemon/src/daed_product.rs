use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
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
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::allocator::{
    AllocatorReclaimReason, allocator_derived_stats_json_from, allocator_live_heap_bytes,
    allocator_profile, allocator_reclaim, allocator_reclaim_snapshot_json,
    allocator_stats_json_from, allocator_stats_snapshot,
};
use crate::config_validate::{load_config_file, validate_config_file};
use crate::production_runtime_owner::{
    ResidentEventLogDecision, ResidentManualProbeHandle, ResidentProductionRuntime,
    resident_live_adapter_config_assessment, resident_live_adapter_udp_probe,
    resident_runtime_defaults_contract, set_resident_event_log_policy, set_resident_event_log_sink,
    start_resident_production_runtime,
};

const DEFAULT_CONFIG_DIR: &str = "/etc/daed";
const DEFAULT_LISTEN: &str = "0.0.0.0:2023";
const DEFAULT_WEB_ROOT: &str = "/usr/share/daed/web";
const PRODUCT_LISTEN_ENV: &str = "PRODUCT_LISTEN";
const PRODUCT_LISTEN_LEGACY_ENV: &str = "DAED_LISTEN";
const PRODUCT_WEB_ROOT_ENV: &str = "PRODUCT_WEB_ROOT";
const PRODUCT_WEB_ROOT_LEGACY_ENV: &str = "DAED_WEB_ROOT";
const PRIMARY_STATE_STORE: &str = crate::service_contract::DAED_PRIMARY_STATE_STORE;
const LEGACY_IMPORT_STATE_STORE: &str = crate::service_contract::DAED_LEGACY_IMPORT_STATE_STORE;
const MAX_BODY_BYTES: usize = 1 << 20;
const TOKEN_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const STATE_DB_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
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
const PRODUCT_HTTP_PROFILE_ENV: &str = "HTTP_PROFILE";
const PRODUCT_HTTP_PROFILE_LEGACY_ENV: &str = "DAED_HTTP_PROFILE";
const PRODUCT_HTTP_PROFILE_STANDARD: &str = "standard";
const PRODUCT_HTTP_PROFILE_LOW_MEMORY: &str = "low-memory";
const PRODUCT_HTTP_WORKER_DEFAULT_MIN: usize = 4;
const PRODUCT_HTTP_WORKER_DEFAULT_MAX: usize = 16;
const PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MIN: usize = 2;
const PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MAX: usize = 4;
const PRODUCT_HTTP_WORKER_MIN: usize = 1;
const PRODUCT_HTTP_WORKER_MAX: usize = 128;
const PRODUCT_HTTP_QUEUE_DEFAULT: usize = 256;
const PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT: usize = 128;
const PRODUCT_HTTP_QUEUE_MIN: usize = 16;
const PRODUCT_HTTP_QUEUE_MAX: usize = 16_384;
const PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT: usize = 1024 * 1024;
const PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT: usize = 512 * 1024;
const PRODUCT_HTTP_WORKER_STACK_BYTES_MIN: usize = 256 * 1024;
const PRODUCT_HTTP_WORKER_STACK_BYTES_MAX: usize = 8 * 1024 * 1024;
const PRODUCT_HTTP_WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(100);
const PRODUCT_MALLOC_ARENA_MAX_ENV: &str = "MALLOC_ARENA_MAX";
const PRODUCT_MALLOC_ARENA_MAX_DEFAULT: &str = "2";
const PRODUCT_JEMALLOC_CONF_ENV: &str = "MALLOC_CONF";
const PRODUCT_JEMALLOC_BUILD_CONF_ENV: &str = "JEMALLOC_SYS_WITH_MALLOC_CONF";
const PRODUCT_JEMALLOC_BUILD_CONF_SOURCE: &str = ".cargo/config.toml";
const PRODUCT_JEMALLOC_CONF_DEFAULT: &str =
    "background_thread:true,dirty_decay_ms:30000,muzzy_decay_ms:30000,percpu_arena:percpu";
const ALLOCATOR_IDLE_RECLAIM_ENABLED_ENV: &str = "ALLOCATOR_IDLE_RECLAIM_ENABLED";
const ALLOCATOR_IDLE_RECLAIM_ENABLED_DEFAULT: bool = true;
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_ENV: &str =
    "ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS";
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_DEFAULT: u64 = 60;
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_MIN: u64 = 10;
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_MAX: u64 = 300;
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_ENV: &str =
    "ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS";
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_DEFAULT: u64 = 300;
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_MIN: u64 = 60;
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_MAX: u64 = 3_600;
const ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_ENV: &str =
    "ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS";
const ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_DEFAULT: u64 = 300;
const ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_MIN: u64 = 60;
const ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_MAX: u64 = 3_600;
const ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_ENV: &str = "ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES";
const ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT: u64 = 32 * 1024 * 1024;
const ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN: u64 = 4 * 1024 * 1024;
const ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MAX: u64 = 1024 * 1024 * 1024;
const ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_ENV: &str =
    "ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND";
const ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_DEFAULT: u64 = 32 * 1024;
const ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_MAX: u64 = 16 * 1024 * 1024;

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
    latency_jobs: Arc<LatencyJobManager>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductHttpProfile {
    Standard,
    LowMemory,
}

impl ProductHttpProfile {
    fn from_env() -> (Self, &'static str) {
        if let Some(profile) = std::env::var(PRODUCT_HTTP_PROFILE_ENV)
            .ok()
            .and_then(|value| Self::parse(&value))
        {
            return (profile, "env");
        }
        if let Some(profile) = std::env::var(PRODUCT_HTTP_PROFILE_LEGACY_ENV)
            .ok()
            .and_then(|value| Self::parse(&value))
        {
            return (profile, "compatibility-env");
        }
        (Self::Standard, "default")
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | PRODUCT_HTTP_PROFILE_STANDARD => Some(Self::Standard),
            "low" | "low_memory" | PRODUCT_HTTP_PROFILE_LOW_MEMORY => Some(Self::LowMemory),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Standard => PRODUCT_HTTP_PROFILE_STANDARD,
            Self::LowMemory => PRODUCT_HTTP_PROFILE_LOW_MEMORY,
        }
    }

    fn worker_default_bounds(self) -> (usize, usize) {
        match self {
            Self::Standard => (
                PRODUCT_HTTP_WORKER_DEFAULT_MIN,
                PRODUCT_HTTP_WORKER_DEFAULT_MAX,
            ),
            Self::LowMemory => (
                PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MIN,
                PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MAX,
            ),
        }
    }

    fn queue_default(self) -> usize {
        match self {
            Self::Standard => PRODUCT_HTTP_QUEUE_DEFAULT,
            Self::LowMemory => PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT,
        }
    }

    fn worker_stack_bytes_default(self) -> usize {
        match self {
            Self::Standard => PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT,
            Self::LowMemory => PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ProductHttpWorkerConfig {
    profile: ProductHttpProfile,
    worker_count: usize,
    queue_capacity: usize,
    worker_stack_bytes: usize,
    profile_source: &'static str,
    worker_count_source: &'static str,
    queue_capacity_source: &'static str,
    worker_stack_bytes_source: &'static str,
}

impl ProductHttpWorkerConfig {
    fn from_config(config: Option<&Config>) -> Self {
        let (profile, profile_source) = ProductHttpProfile::from_env();
        Self::from_config_with_profile_and_env(config, profile, profile_source, &|name| {
            std::env::var(name).ok()
        })
    }

    #[cfg(test)]
    fn from_config_with_profile(
        config: Option<&Config>,
        profile: ProductHttpProfile,
        profile_source: &'static str,
    ) -> Self {
        Self::from_config_with_profile_and_env(config, profile, profile_source, &|_| None)
    }

    fn from_config_with_profile_and_env(
        config: Option<&Config>,
        profile: ProductHttpProfile,
        profile_source: &'static str,
        env_value: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let global = config.map(|config| &config.global);
        let (default_worker_min, default_worker_max) = profile.worker_default_bounds();
        let default_workers = thread::available_parallelism()
            .map(|parallelism| parallelism.get().saturating_mul(2))
            .unwrap_or(default_worker_min)
            .clamp(default_worker_min, default_worker_max);
        let (worker_count, worker_count_source) = effective_product_usize_with_legacy(
            env_value,
            PRODUCT_HTTP_WORKERS_ENV,
            PRODUCT_HTTP_WORKERS_LEGACY_ENV,
            global.and_then(|global| global.http_workers),
            default_workers,
            PRODUCT_HTTP_WORKER_MIN,
            PRODUCT_HTTP_WORKER_MAX,
        );
        let (queue_capacity, queue_capacity_source) = effective_product_usize_with_legacy(
            env_value,
            PRODUCT_HTTP_QUEUE_ENV,
            PRODUCT_HTTP_QUEUE_LEGACY_ENV,
            global.and_then(|global| global.http_queue),
            profile.queue_default(),
            PRODUCT_HTTP_QUEUE_MIN,
            PRODUCT_HTTP_QUEUE_MAX,
        );
        let (worker_stack_bytes, worker_stack_bytes_source) = effective_product_usize_with_legacy(
            env_value,
            PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
            PRODUCT_HTTP_WORKER_STACK_BYTES_LEGACY_ENV,
            global.and_then(|global| global.http_worker_stack_bytes),
            profile.worker_stack_bytes_default(),
            PRODUCT_HTTP_WORKER_STACK_BYTES_MIN,
            PRODUCT_HTTP_WORKER_STACK_BYTES_MAX,
        );
        Self {
            profile,
            worker_count,
            queue_capacity,
            worker_stack_bytes,
            profile_source,
            worker_count_source,
            queue_capacity_source,
            worker_stack_bytes_source,
        }
    }

    fn sources_json(self) -> Value {
        json!({
            "profile": self.profile_source,
            "profileName": self.profile.name(),
            "workers": self.worker_count_source,
            "queue": self.queue_capacity_source,
            "workerStackBytes": self.worker_stack_bytes_source,
        })
    }
}

fn effective_product_usize_with_legacy(
    env_value: &dyn Fn(&str) -> Option<String>,
    name: &str,
    legacy_name: &str,
    configured: Option<u64>,
    default: usize,
    min: usize,
    max: usize,
) -> (usize, &'static str) {
    if let Some(value) = env_value(name).and_then(|value| value.trim().parse::<usize>().ok()) {
        return (value.clamp(min, max), "env");
    }
    if let Some(value) = env_value(legacy_name).and_then(|value| value.trim().parse::<usize>().ok())
    {
        return (value.clamp(min, max), "compatibility-env");
    }
    if let Some(value) = configured {
        return ((value as usize).clamp(min, max), "config");
    }
    (default.clamp(min, max), "default")
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
                "buildEnv": PRODUCT_JEMALLOC_BUILD_CONF_ENV,
                "defaultSource": PRODUCT_JEMALLOC_BUILD_CONF_SOURCE,
                "default": PRODUCT_JEMALLOC_CONF_DEFAULT,
                "runtimeOverride": true,
                "serviceUnitSetsEnv": false,
                "scope": "jemalloc builds; built in by default from the workspace Cargo config as a fallback; operators may set MALLOC_CONF in the service environment to override runtime allocator behavior",
            },
            "reclaim": {
                "startupControlBuilt": true,
                "reloadCompleted": true,
                "stopRuntime": true,
                "hotPathPeriodicPurge": false,
                "idleMemoryPressure": {
                    "enabledConfigKey": "allocator_idle_reclaim_enabled",
                    "enabledEnv": ALLOCATOR_IDLE_RECLAIM_ENABLED_ENV,
                    "enabledDefault": ALLOCATOR_IDLE_RECLAIM_ENABLED_DEFAULT,
                    "idleDetection": "traffic-rate-only",
                    "sessionCountGate": false,
                    "sampleIntervalConfigKey": "allocator_idle_reclaim_sample_interval",
                    "sampleIntervalSecondsEnv": ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_ENV,
                    "sampleIntervalSecondsDefault": ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_DEFAULT,
                    "minIntervalConfigKey": "allocator_idle_reclaim_min_interval",
                    "minIntervalSecondsEnv": ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_ENV,
                    "minIntervalSecondsDefault": ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_DEFAULT,
                    "lowTrafficConfigKey": "allocator_idle_reclaim_low_traffic_duration",
                    "lowTrafficSecondsEnv": ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_ENV,
                    "lowTrafficSecondsDefault": ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_DEFAULT,
                    "pressureBytesConfigKey": "allocator_idle_reclaim_pressure_threshold_bytes",
                    "pressureBytesEnv": ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_ENV,
                    "pressureBytesDefault": ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT.to_string(),
                    "maxTrafficRateBytesPerSecondConfigKey": "allocator_idle_reclaim_max_traffic_rate_bytes_per_second",
                    "maxTrafficRateBytesPerSecondEnv": ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_ENV,
                    "maxTrafficRateBytesPerSecondDefault": ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_DEFAULT.to_string(),
                },
            },
        },
        "http": {
            "profile": {
                "env": PRODUCT_HTTP_PROFILE_ENV,
                "default": PRODUCT_HTTP_PROFILE_STANDARD,
                "supported": [
                    PRODUCT_HTTP_PROFILE_STANDARD,
                    PRODUCT_HTTP_PROFILE_LOW_MEMORY,
                ],
                "lowMemory": {
                    "workerDefaultPolicy": format!(
                        "available_parallelism * 2 clamped to {}..{}",
                        PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MIN,
                        PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MAX
                    ),
                    "queueDefault": PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT,
                    "workerStackBytesDefault": PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT,
                },
            },
            "workers": {
                "configKey": "http_workers",
                "env": PRODUCT_HTTP_WORKERS_ENV,
                "defaultPolicy": format!(
                    "available_parallelism * 2 clamped to {}..{}",
                    PRODUCT_HTTP_WORKER_DEFAULT_MIN, PRODUCT_HTTP_WORKER_DEFAULT_MAX
                ),
                "min": PRODUCT_HTTP_WORKER_MIN,
                "max": PRODUCT_HTTP_WORKER_MAX,
            },
            "queue": {
                "configKey": "http_queue",
                "env": PRODUCT_HTTP_QUEUE_ENV,
                "default": PRODUCT_HTTP_QUEUE_DEFAULT,
                "min": PRODUCT_HTTP_QUEUE_MIN,
                "max": PRODUCT_HTTP_QUEUE_MAX,
            },
            "workerStackBytes": {
                "configKey": "http_worker_stack_bytes",
                "env": PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
                "default": PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT,
                "min": PRODUCT_HTTP_WORKER_STACK_BYTES_MIN,
                "max": PRODUCT_HTTP_WORKER_STACK_BYTES_MAX,
            },
        },
        "residentDataplane": resident_runtime_defaults_contract(),
    })
}

fn runtime_state_blockers() -> Vec<String> {
    crate::runtime_state_evidence::runtime_state_evidence_from_env().blockers
}

fn runtime_state_gate_evidence() -> Value {
    crate::runtime_state_evidence::runtime_state_evidence_from_env().report
}

fn production_admission() -> Value {
    let evidence = crate::runtime_state_evidence::runtime_state_evidence_from_env();
    json!({
        "liveHostReplacementApplied": evidence.report["liveHostReplacementApplied"].as_bool().unwrap_or(false),
        "finalStateValidationAppliedOnLiveHost": evidence.report["finalStateValidationAppliedOnLiveHost"].as_bool().unwrap_or(false),
        "productPackageReady": evidence.product_package_ready,
        "nativeProductShellReady": evidence.native_product_shell_ready,
        "nativeOutboundDependencyReady": evidence.native_outbound_dependency_ready,
        "userlandNativeAbiReady": evidence.userland_native_abi_ready,
        "rustProductBinaryContractReady": evidence.rust_product_binary_contract_ready,
        "rustProductLifecycleContractReady": evidence.rust_product_lifecycle_contract_ready,
        "rustProductWebApiPackageReleaseContractReady": evidence.rust_product_web_api_package_release_contract_ready,
        "runtimeStateReady": evidence.ready,
        "fullRuntimeStateReady": evidence.ready,
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
mod product_net;
use self::product_net::*;
mod runtime_materialization;
use self::runtime_materialization::*;
mod logs;
use self::logs::*;
mod latency;
use self::latency::*;
mod geodata;
use self::geodata::*;
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
