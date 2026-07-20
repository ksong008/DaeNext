use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
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
    AllocatorReclaimReason, AllocatorStatsSnapshot, allocator_bind_control_plane_thread,
    allocator_derived_stats_json_from, allocator_flush_current_thread_cache, allocator_profile,
    allocator_purge_control_plane_arena, allocator_reclaim, allocator_reclaim_snapshot_json,
    allocator_request_reclaim, allocator_stats_json_from, allocator_stats_snapshot,
};
use crate::allocator_bootstrap::{
    JEMALLOC_AUTOMATIC_ARENA_MAX, JEMALLOC_BUILD_CONF_ENV, JEMALLOC_BUILD_CONF_SOURCE,
    JEMALLOC_BUILD_FALLBACK, JEMALLOC_RUNTIME_CONF_ENV, JEMALLOC_RUNTIME_DEFAULT_SOURCE,
    jemalloc_automatic_arena_count, jemalloc_process_default_configuration,
};
use crate::config_validate::{load_config_file, validate_config_file};
use crate::production_runtime_owner::{
    ResidentDnsReloadSnapshot, ResidentEventLogDecision, ResidentManualProbeHandle,
    ResidentNodeSourceAdmission, ResidentProductionRuntime,
    resident_live_adapter_config_assessment, resident_live_adapter_udp_probe,
    resident_node_source_admissions, resident_runtime_defaults_contract,
    set_resident_event_log_policy, set_resident_event_log_sink,
    start_resident_production_runtime_with_latency_seed_and_dns_reload_snapshot,
};

mod benchmark;
pub use benchmark::{
    ProductGlobalNormalizeBenchmarkFixture, product_global_normalize_benchmark_fixture,
};

const DEFAULT_CONFIG_DIR: &str = "/etc/daed";
const DEFAULT_LISTEN: &str = "0.0.0.0:2023";
const DEFAULT_WEB_ROOT: &str = "/usr/share/daed/web";
const DEFAULT_CONTROL_SOCKET: &str = "/run/daed/control.sock";
const PRODUCT_CONTROL_SOCKET_ENV: &str = "DAED_CONTROL_SOCKET";
const PRODUCT_LISTEN_ENV: &str = "PRODUCT_LISTEN";
const PRODUCT_LISTEN_LEGACY_ENV: &str = "DAED_LISTEN";
const PRODUCT_WEB_ROOT_ENV: &str = "PRODUCT_WEB_ROOT";
const PRODUCT_WEB_ROOT_LEGACY_ENV: &str = "DAED_WEB_ROOT";
const PRIMARY_STATE_STORE: &str = crate::service_contract::DAED_PRIMARY_STATE_STORE;
const LEGACY_IMPORT_STATE_STORE: &str = crate::service_contract::DAED_LEGACY_IMPORT_STATE_STORE;
const MAX_BODY_BYTES: usize = 1 << 20;
const MAX_BUNDLE_BODY_BYTES: usize = 16 << 20;
const MAX_HTTP_HEADER_BYTES: usize = 64 << 10;
const MAX_HTTP_HEADER_COUNT: usize = 128;
const PRODUCT_HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_HTTP_HEADER_RATE_GRACE: Duration = Duration::from_secs(2);
const PRODUCT_HTTP_HEADER_MIN_BYTES_PER_SECOND: usize = 64;
const PRODUCT_HTTP_BODY_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const PRODUCT_HTTP_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const PRODUCT_HTTP_BUNDLE_BODY_READ_TIMEOUT: Duration = Duration::from_secs(300);
const PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const PRODUCT_HTTP_REJECT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const DAE_BUNDLE_IMPORT_PATH: &str = "/api/user/me/dae-bundle";
const TOKEN_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const STATE_DB_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const STATE_SCHEMA_VERSION: i64 = 2;
const DEFAULT_LOG_MAX_ENTRIES: i64 = 10_000;
const DEFAULT_LOG_MAX_BYTES: i64 = 50 * 1024 * 1024;
const MIN_LOG_MAX_ENTRIES: i64 = 500;
const MAX_LOG_MAX_ENTRIES: i64 = 50_000;
const MIN_LOG_MAX_BYTES: i64 = 5 * 1024 * 1024;
const MAX_LOG_MAX_BYTES: i64 = 200 * 1024 * 1024;
const DEFAULT_RUNTIME_LOG_LEVEL: &str = dae_config::DEFAULT_LOG_LEVEL;
const DEFAULT_LOG_QUERY_LIMIT: usize = 500;
const MAX_LOG_QUERY_LIMIT: usize = 2_000;
const MAX_LOG_LINE_BYTES: usize = 16 * 1024;
const MAX_LOG_FIELD_VALUE_LEN: usize = 1024;
const LOG_TAIL_ID_SCAN_BYTES: u64 = 1024 * 1024;
const LOG_PRUNE_INTERVAL: u64 = 256;
const LOG_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(500);
const LOG_STREAM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const LOG_STREAM_RETRY_MS: u64 = 3_000;
const PRODUCT_LOG_DIR_ENV: &str = "DAED_PRODUCT_LOG_DIR";
const PRODUCT_LOG_DIR: &str = "logs";
const PRODUCT_LOG_FILE: &str = "current.jsonl";
const RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY: &str = "runtime_external_input_version";
const LEGACY_GEODATA_RELOAD_PENDING_METADATA_KEY: &str = "geodata_reload_pending";
const DEFAULT_PRODUCT_CONFIG_NAME: &str = "global";
const DEFAULT_PRODUCT_DNS_NAME: &str = "default";
const DEFAULT_PRODUCT_ROUTING_NAME: &str = "default";
const DEFAULT_PRODUCT_GROUP_NAME: &str = "default";
const GROUP_POLICY_RANDOM: &str = "random";
const GROUP_POLICY_FIXED: &str = "fixed";
const GROUP_POLICY_MIN: &str = "min";
const GROUP_POLICY_MIN_AVG10: &str = "min_avg10";
const GROUP_POLICY_MIN_MOVING_AVG: &str = "min_moving_avg";
const DEFAULT_PRODUCT_GROUP_POLICY: &str = GROUP_POLICY_RANDOM;
const SUPPORTED_GROUP_POLICIES: &[&str] = &[
    GROUP_POLICY_RANDOM,
    GROUP_POLICY_FIXED,
    GROUP_POLICY_MIN,
    GROUP_POLICY_MIN_AVG10,
    GROUP_POLICY_MIN_MOVING_AVG,
];
const DEFAULT_PRODUCT_MODE: &str = "rule";
const DEFAULT_GLOBAL_RESOURCE_TEXT: &str = "global {}";
const DEFAULT_SUBSCRIPTION_CRON_EXP: &str = "10 */6 * * *";
const DEFAULT_SUBSCRIPTION_CRON_ENABLE: bool = true;
const DEFAULT_SUBSCRIPTION_STATUS: &str = "imported";
const DEFAULT_IMPORTED_CONFIG_NAME_PREFIX: &str = "imported";
const IMPORTED_CONFIG_NAME_SUFFIX: &str = "global";
const IMPORTED_DNS_NAME_SUFFIX: &str = "dns";
const IMPORTED_ROUTING_NAME_SUFFIX: &str = "routing";
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
const PRODUCT_HTTP_SSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_MALLOC_ARENA_MAX_ENV: &str = "MALLOC_ARENA_MAX";
const PRODUCT_MALLOC_ARENA_MAX_DEFAULT: &str = "2";
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
const ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_CAPACITY_DIVISOR: u64 = 256;
const ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_MAX_BYTES: u64 =
    ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT;
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
    control_socket: PathBuf,
}

#[derive(Clone, Debug)]
struct AppState {
    config_dir: PathBuf,
    state: PathBuf,
    web_root: PathBuf,
    api_only: bool,
    control_socket: PathBuf,
    shutdown: Arc<ProductShutdown>,
    runtime: Arc<ProductRuntimeManager>,
    runtime_sampler: Option<Arc<ProductRuntimeSampler>>,
    latency_jobs: Arc<LatencyJobManager>,
    http_metrics: Arc<ProductHttpMetrics>,
    ui_runtime: Arc<ProductUiRuntime>,
    auth_runtime: Arc<ProductAuthRuntime>,
    geodata_updates: Arc<geodata::ProductGeodataUpdateCoordinator>,
    geodata_status_cache: Arc<Mutex<GeodataStatusCache>>,
    geodata_update_runtime: Option<Arc<geodata::ProductGeodataUpdateRuntime>>,
}

#[derive(Debug, Default)]
struct GeodataStatusCache {
    geosite: Option<geodata::GeodataStatusCacheEntry>,
    geoip: Option<geodata::GeodataStatusCacheEntry>,
}

#[derive(Debug, Default)]
struct ProductHttpMetrics {
    configured_workers: AtomicU64,
    queue_capacity: AtomicU64,
    worker_stack_bytes: AtomicU64,
    active_connections: AtomicU64,
    active_sse_connections: AtomicU64,
    accepted_total: AtomicU64,
    enqueued_total: AtomicU64,
    rejected_total: AtomicU64,
    queue_depth: AtomicU64,
    sse_connection_limit: AtomicU64,
    sse_per_user_limit: AtomicU64,
    sse_queue_capacity: AtomicU64,
    sse_worker_stack_bytes: AtomicU64,
    sse_queue_depth: AtomicU64,
    sse_submitted_total: AtomicU64,
    sse_completed_total: AtomicU64,
    sse_rejected_limit_total: AtomicU64,
    sse_rejected_capacity_total: AtomicU64,
    sse_rejected_unavailable_total: AtomicU64,
    sse_runtime_joined_total: AtomicU64,
    sse_runtime_detached_total: AtomicU64,
    request_read: ProductHttpRequestReadMetrics,
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

    fn configure_sse(
        &self,
        connection_limit: usize,
        per_user_limit: usize,
        queue_capacity: usize,
        worker_stack_bytes: usize,
    ) {
        self.sse_connection_limit
            .store(connection_limit as u64, Ordering::Relaxed);
        self.sse_per_user_limit
            .store(per_user_limit as u64, Ordering::Relaxed);
        self.sse_queue_capacity
            .store(queue_capacity as u64, Ordering::Relaxed);
        self.sse_worker_stack_bytes
            .store(worker_stack_bytes as u64, Ordering::Relaxed);
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

    fn sse_opened(&self) {
        self.active_sse_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn sse_closed(&self) {
        let _ = self.active_sse_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |connections| Some(connections.saturating_sub(1)),
        );
    }

    fn sse_enqueued(&self) {
        self.sse_submitted_total.fetch_add(1, Ordering::Relaxed);
        self.sse_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    fn sse_dequeued(&self) {
        let _ = self
            .sse_queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
        self.sse_opened();
    }

    fn sse_submission_rollback(&self) {
        let _ = self
            .sse_queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    fn sse_completed(&self) {
        self.sse_closed();
        self.sse_completed_total.fetch_add(1, Ordering::Relaxed);
    }

    fn sse_rejected_limit(&self) {
        self.sse_rejected_limit_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn sse_rejected_capacity(&self) {
        self.sse_rejected_capacity_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn sse_rejected_unavailable(&self) {
        self.sse_rejected_unavailable_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn sse_runtime_joined(&self) {
        self.sse_runtime_joined_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn sse_runtime_detached(&self) {
        self.sse_runtime_detached_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Value {
        json!({
            "configuredWorkers": self.configured_workers.load(Ordering::Relaxed),
            "queueCapacity": self.queue_capacity.load(Ordering::Relaxed),
            "workerStackBytes": self.worker_stack_bytes.load(Ordering::Relaxed),
            "activeConnections": self.active_connections.load(Ordering::Relaxed),
            "activeSseConnections": self.active_sse_connections.load(Ordering::Relaxed),
            "acceptedTotal": self.accepted_total.load(Ordering::Relaxed),
            "enqueuedTotal": self.enqueued_total.load(Ordering::Relaxed),
            "rejectedTotal": self.rejected_total.load(Ordering::Relaxed),
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
            "requestRead": self.request_read.snapshot(),
            "sseRuntime": {
                "connectionLimit": self.sse_connection_limit.load(Ordering::Relaxed),
                "perUserLimit": self.sse_per_user_limit.load(Ordering::Relaxed),
                "queueCapacity": self.sse_queue_capacity.load(Ordering::Relaxed),
                "workerStackBytes": self.sse_worker_stack_bytes.load(Ordering::Relaxed),
                "queueDepth": self.sse_queue_depth.load(Ordering::Relaxed),
                "submittedTotal": self.sse_submitted_total.load(Ordering::Relaxed),
                "completedTotal": self.sse_completed_total.load(Ordering::Relaxed),
                "rejectedLimitTotal": self.sse_rejected_limit_total.load(Ordering::Relaxed),
                "rejectedCapacityTotal": self.sse_rejected_capacity_total.load(Ordering::Relaxed),
                "rejectedUnavailableTotal": self.sse_rejected_unavailable_total.load(Ordering::Relaxed),
                "runtimeJoinedTotal": self.sse_runtime_joined_total.load(Ordering::Relaxed),
                "runtimeDetachedTotal": self.sse_runtime_detached_total.load(Ordering::Relaxed),
            },
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    fn transition_json(self, desired: Self) -> Value {
        json!({
            "state": "pending-process-transition",
            "owner": "product-http-runtime",
            "active": {
                "profile": self.profile.name(),
                "workers": self.worker_count,
                "queueCapacity": self.queue_capacity,
                "workerStackBytes": self.worker_stack_bytes,
                "sources": self.sources_json(),
            },
            "desired": {
                "profile": desired.profile.name(),
                "workers": desired.worker_count,
                "queueCapacity": desired.queue_capacity,
                "workerStackBytes": desired.worker_stack_bytes,
                "sources": desired.sources_json(),
            },
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
    let available_parallelism = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1);
    let jemalloc_default = jemalloc_process_default_configuration();
    let jemalloc_process_configuration = if cfg!(feature = "allocator-jemalloc") {
        std::env::var_os(JEMALLOC_RUNTIME_CONF_ENV)
            .map(|configuration| configuration.to_string_lossy().into_owned())
    } else {
        None
    };
    json!({
        "allocator": {
            "profile": allocator_profile(),
            "systemAllocatorArenaCap": {
                "env": PRODUCT_MALLOC_ARENA_MAX_ENV,
                "default": PRODUCT_MALLOC_ARENA_MAX_DEFAULT,
                "scope": "glibc/system allocator compatibility; ignored by jemalloc builds",
            },
            "jemallocPolicy": {
                "env": JEMALLOC_RUNTIME_CONF_ENV,
                "buildEnv": JEMALLOC_BUILD_CONF_ENV,
                "buildFallbackSource": JEMALLOC_BUILD_CONF_SOURCE,
                "buildFallback": JEMALLOC_BUILD_FALLBACK,
                "defaultSource": JEMALLOC_RUNTIME_DEFAULT_SOURCE,
                "default": jemalloc_default,
                "defaultAutomaticArenas": jemalloc_automatic_arena_count(available_parallelism),
                "automaticArenaPolicy": format!(
                    "available_parallelism clamped to 1..{JEMALLOC_AUTOMATIC_ARENA_MAX}"
                ),
                "effectiveParallelism": available_parallelism,
                "effectiveParallelismSource": "std::thread::available_parallelism (affinity/cgroup aware)",
                "processConfiguration": jemalloc_process_configuration,
                "startupApplication": "one-time same-PID process replacement before normal product startup",
                "runtimeOverride": cfg!(feature = "allocator-jemalloc"),
                "serviceUnitSetsEnv": false,
                "scope": "prefixed jemalloc builds; the bounded workspace build policy protects the first image, then the startup bootstrap applies the effective operator override or affinity-aware default",
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
                    "pressureBytesDefaultPolicy": "explicit config or env; otherwise effective memory capacity divided by the automatic divisor and clamped to the automatic bounds",
                    "pressureBytesPrecedence": ["env", "config", "auto-capacity", "default"],
                    "pressureBytesAutoCapacityDivisor": ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_CAPACITY_DIVISOR,
                    "pressureBytesAutoMin": ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN.to_string(),
                    "pressureBytesAutoMax": ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_MAX_BYTES.to_string(),
                    "pressureMetric": "allocator-resident-minus-active",
                    "retainedMetric": "diagnostic-virtual-address-space",
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
            "auth": product_auth_defaults_json(),
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

#[derive(Clone, Copy, Debug, Default)]
struct ProductHttpRequestContext {
    peer_ip: Option<IpAddr>,
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
mod product_shutdown;
use self::product_shutdown::*;
mod state_connection;
use self::state_connection::*;
mod state_integrity;
use self::state_integrity::*;
mod state_migration;
use self::state_migration::*;
mod state_schema;
use self::state_schema::*;
mod http_connections;
use self::http_connections::*;
mod ui_runtime;
use self::ui_runtime::*;
mod http_server;
use self::http_server::*;
mod sse_runtime;
use self::sse_runtime::*;
mod local_control;
use self::local_control::*;
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
mod runtime_reload;
use self::runtime_reload::*;
mod runtime_apply;
use self::runtime_apply::*;
mod logs;
use self::logs::*;
mod latency;
use self::latency::*;
mod geodata;
use self::geodata::*;
mod bundle;
use self::bundle::*;
mod dae_file_import;
use self::dae_file_import::*;
mod package;
use self::package::*;
mod process_metrics;
use self::process_metrics::*;
mod common_helpers;
use self::common_helpers::*;
mod auth_storage;
use self::auth_storage::*;
mod auth_runtime;
use self::auth_runtime::*;
mod http_request;
use self::http_request::*;
mod http_io;
use self::http_io::*;
#[cfg(test)]
mod tests;
