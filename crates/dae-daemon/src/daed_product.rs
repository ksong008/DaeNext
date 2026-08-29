use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
#[cfg(not(unix))]
use std::time::SystemTime;
use std::time::{Duration, Instant};

use dae_config::Config;
#[cfg(test)]
use dae_config::parser::parse_config;
#[cfg(test)]
use dae_config::schema::build_config;
pub use dae_product_core::*;
use dae_product_core::{product_iso8601_utc as iso8601_utc, product_now_text as now_text};
#[cfg(test)]
use dae_product_subscription::{count_nodes_for_subscription, list_all_nodes_value};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Map, Value, json};

use crate::allocator::{
    AllocatorReclaimBusyKind, AllocatorReclaimReason, AllocatorReclaimScope,
    AllocatorReclaimWorker, AllocatorRuntimeReclaimHooks, AllocatorStatsSnapshot,
    AllocatorWorkerKind, allocator_derived_stats_json_from, allocator_effective_configuration_json,
    allocator_notify_reclaim_monitor, allocator_pending_reclaim_scope, allocator_profile,
    allocator_reclaim, allocator_reclaim_busy, allocator_reclaim_busy_completion_count,
    allocator_reclaim_busy_count, allocator_reclaim_control_plane,
    allocator_reclaim_request_wake_epoch, allocator_reclaim_snapshot_json,
    allocator_reclaimable_page_bytes, allocator_record_publication_reclaim,
    allocator_record_trailing_reclaim_evaluation, allocator_register_reclaim_worker,
    allocator_request_reclaim, allocator_request_reclaim_for_publication,
    allocator_restore_reclaim_requests, allocator_stats_json_from, allocator_stats_snapshot,
    allocator_wait_for_reclaim_request_since,
};
use crate::allocator_bootstrap::{
    JEMALLOC_AUTOMATIC_ARENA_MAX, JEMALLOC_BUILD_CONF_ENV, JEMALLOC_BUILD_CONF_SOURCE,
    JEMALLOC_BUILD_FALLBACK, JEMALLOC_RUNTIME_CONF_ENV, JEMALLOC_RUNTIME_DEFAULT_SOURCE,
    jemalloc_automatic_arena_count, jemalloc_process_default_configuration,
};
use crate::config_validate::{load_config_file, validate_config_file};
use crate::production_runtime_owner::{
    ResidentActiveGenerationSnapshot, ResidentDnsReloadSnapshot, ResidentEventLogDecision,
    ResidentEventMetadata, ResidentManualProbeHandle, ResidentNodeSourceAdmission,
    ResidentPreparedGeneration, ResidentProductionRuntime, ResidentProductionRuntimeReadHandle,
    ResidentTrafficCounters, prepare_resident_production_generation,
    resident_live_adapter_config_assessment, resident_live_adapter_udp_probe,
    resident_node_source_admissions, resident_runtime_defaults_contract,
    set_resident_event_log_policies, set_resident_event_log_sink,
    start_prepared_resident_production_runtime,
    start_resident_production_runtime_with_latency_seed_and_dns_reload_snapshot,
};

pub use dae_product_runtime::{
    ProductGlobalNormalizeBenchmarkFixture, product_global_normalize_benchmark_fixture,
};

const DEFAULT_CONFIG_DIR: &str = "/etc/daed";
const DEFAULT_LISTEN: &str = "0.0.0.0:2023";
const DEFAULT_WEB_ROOT: &str = "/usr/share/daed/web";
const DEFAULT_CONTROL_SOCKET: &str = DEFAULT_PRODUCT_CONTROL_SOCKET;
const PRODUCT_WEB_ROOT_ENV: &str = "PRODUCT_WEB_ROOT";
const PRODUCT_WEB_ROOT_LEGACY_ENV: &str = "DAED_WEB_ROOT";
const PRIMARY_STATE_STORE: &str = crate::service_contract::DAED_PRIMARY_STATE_STORE;
const LEGACY_IMPORT_STATE_STORE: &str = crate::service_contract::DAED_LEGACY_IMPORT_STATE_STORE;
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
const RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY: &str = "runtime_active_fingerprint";
const DEFAULT_SUBSCRIPTION_CRON_EXP: &str = "10 */6 * * *";
const DEFAULT_SUBSCRIPTION_CRON_ENABLE: bool = true;
const DEFAULT_SUBSCRIPTION_STATUS: &str = "imported";
const DEFAULT_IMPORTED_CONFIG_NAME_PREFIX: &str = "imported";
const PRODUCT_HTTP_WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(100);
const PRODUCT_HTTP_SSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_MALLOC_ARENA_MAX_ENV: &str = "MALLOC_ARENA_MAX";
const PRODUCT_MALLOC_ARENA_MAX_DEFAULT: &str = "2";
const ALLOCATOR_IDLE_RECLAIM_ENABLED_ENV: &str = "ALLOCATOR_IDLE_RECLAIM_ENABLED";
const ALLOCATOR_IDLE_RECLAIM_ENABLED_DEFAULT: bool = true;
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_ENV: &str =
    "ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS";
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_DEFAULT: u64 = 30;
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_MIN: u64 = 5;
const ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_MAX: u64 = 300;
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_ENV: &str =
    "ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS";
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_DEFAULT: u64 = 120;
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_MIN: u64 = 60;
const ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_MAX: u64 = 3_600;
const ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_ENV: &str =
    "ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS";
const ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_DEFAULT: u64 = 60;
const ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_MIN: u64 = 10;
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
    control_runtime: Arc<ProductControlRuntime>,
}

#[derive(Debug)]
struct ProductUiAllocatorHooks;

impl ProductUiReclaimHooks for ProductUiAllocatorHooks {
    fn bind_control_plane_thread(&self) -> Result<Option<u32>, String> {
        crate::allocator::allocator_bind_control_plane_thread()
    }

    fn flush_current_thread_cache(&self) -> io::Result<()> {
        crate::allocator::allocator_flush_current_thread_cache().map_err(io::Error::other)
    }

    fn request_control_plane_reclaim(&self) -> Value {
        crate::allocator::allocator_request_control_plane_reclaim()
    }
}

fn product_ui_runtime() -> Arc<ProductUiRuntime> {
    Arc::new(ProductUiRuntime::with_default_reclaim_hooks(Arc::new(
        ProductUiAllocatorHooks,
    )))
}

struct ProductControlAllocatorHooks {
    inner: AllocatorRuntimeReclaimHooks,
}

impl ProductControlRuntimeHooks for ProductControlAllocatorHooks {
    fn on_thread_start(&self) {
        self.inner.thread_start();
    }

    fn on_thread_stop(&self) {
        self.inner.thread_stop();
    }

    fn activate(&self, handle: tokio::runtime::Handle) {
        self.inner.activate(handle);
    }

    fn deactivate(&self) {
        self.inner.deactivate();
    }
}

fn product_control_runtime_hooks(worker_threads: usize) -> Arc<dyn ProductControlRuntimeHooks> {
    Arc::new(ProductControlAllocatorHooks {
        inner: AllocatorRuntimeReclaimHooks::new(
            AllocatorWorkerKind::ProductControl,
            worker_threads,
        ),
    })
}

fn start_product_control_runtime(
    http_config: ProductHttpWorkerConfig,
) -> io::Result<Arc<ProductControlRuntime>> {
    let config = ProductControlRuntimeConfig::from_http_config(http_config);
    let hooks = product_control_runtime_hooks(config.worker_threads);
    ProductControlRuntime::start_with_config_and_hooks(config, hooks)
}

fn start_product_control_helper_runtime(
    thread_name: &'static str,
) -> io::Result<Arc<ProductControlRuntime>> {
    let config = ProductControlRuntimeConfig::for_helper(thread_name);
    let hooks = product_control_runtime_hooks(config.worker_threads);
    ProductControlRuntime::start_with_config_and_hooks(config, hooks)
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
                "effectiveOptions": allocator_effective_configuration_json(),
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
                    "idleDetection": "traffic-rate-plus-busy-leases-and-allocator-state",
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
                    "pressureBytesDefaultPolicy": "explicit config or env; otherwise application live excluding tcache divided by eight and clamped to 4-16 MiB",
                    "pressureBytesPrecedence": ["env", "config", "application-live-working-set"],
                    "pressureBytesAutoCapacityDivisor": ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_CAPACITY_DIVISOR,
                    "pressureBytesAutoMin": ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN.to_string(),
                    "pressureBytesAutoMax": ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_MAX_BYTES.to_string(),
                    "pressureMetric": "maximum-of-arena-dirty-plus-muzzy-pages-and-worker-tcache",
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

mod cli_commands;
pub use self::cli_commands::*;
mod service_metadata;
use self::service_metadata::*;
use dae_product_http::*;
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
use dae_product_runtime::*;
mod pprof_runtime;
use self::pprof_runtime::*;
mod runtime_reconcile;
use self::runtime_reconcile::*;
use dae_product_persistence::*;
type UserRecord = ProductUserRecord;
mod runtime_apply;
use self::runtime_apply::*;
mod logs;
use self::logs::*;
mod latency;
use self::latency::*;
mod geodata;
use self::geodata::*;
mod bundle;
use self::bundle::{export_bundle, import_bundle};
fn product_package_context() -> ProductPackageContext {
    ProductPackageContext::new(
        PRIMARY_STATE_STORE,
        LEGACY_IMPORT_STATE_STORE,
        DEFAULT_WEB_ROOT,
        production_admission(),
        product_runtime_defaults(),
        runtime_state_gate_evidence(),
        runtime_state_blockers(),
    )
}
mod common_helpers;
use self::common_helpers::*;
mod auth_storage;
use self::auth_storage::*;
#[cfg(test)]
pub use dae_product_control::ensure_default_resources;
pub use dae_product_control::ensure_default_resources_for_user;
use dae_product_control::*;
pub use dae_product_control::{ProductControlBenchmarkFixture, product_control_benchmark_fixture};
#[cfg(test)]
fn product_test_auth_runtime() -> Arc<ProductAuthRuntime> {
    ProductAuthRuntime::start_for_test_config().unwrap()
}
#[cfg(test)]
fn product_test_control_runtime() -> Arc<ProductControlRuntime> {
    ProductControlRuntime::start(ProductControlRuntimeConfig::for_benchmark()).unwrap()
}
#[cfg(test)]
mod tests;
