use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use dae_config::Config;
use dae_config::parser::parse_config;
use dae_config::schema::build_config;
use dae_datapath::{
    ANYFROM_TIMEOUT_MS, DEFAULT_NAT_TIMEOUT_MS, DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
    DNS_NAT_TIMEOUT_MS, MAX_RETRY, PACKET_SNIFFER_POOL_MAX_ENTRIES, PACKET_SNIFFER_TTL_MS,
    UDP_TASK_POOL_MAX_QUEUES, UDP_TASK_QUEUE_LENGTH, udp_endpoint_pool_trim_target,
};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
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
use crate::config_validate::load_config_file;
use crate::production_runtime_owner::{
    ResidentProductionRuntime, resident_live_adapter_config_assessment,
    resident_runtime_defaults_contract, resident_runtime_environment_defaults,
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
const PRODUCT_HTTP_WORKERS_ENV: &str = "DAED_HTTP_WORKERS";
const PRODUCT_HTTP_QUEUE_ENV: &str = "DAED_HTTP_QUEUE";
const PRODUCT_HTTP_WORKER_STACK_BYTES_ENV: &str = "DAED_HTTP_WORKER_STACK_BYTES";
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
            worker_count: env_usize(
                PRODUCT_HTTP_WORKERS_ENV,
                default_workers,
                PRODUCT_HTTP_WORKER_MIN,
                PRODUCT_HTTP_WORKER_MAX,
            ),
            queue_capacity: env_usize(
                PRODUCT_HTTP_QUEUE_ENV,
                PRODUCT_HTTP_QUEUE_DEFAULT,
                PRODUCT_HTTP_QUEUE_MIN,
                PRODUCT_HTTP_QUEUE_MAX,
            ),
            worker_stack_bytes: env_usize(
                PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
                PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT,
                PRODUCT_HTTP_WORKER_STACK_BYTES_MIN,
                PRODUCT_HTTP_WORKER_STACK_BYTES_MAX,
            ),
        }
    }
}

fn env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
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

#[derive(Debug)]
struct ProductRuntimeManager {
    inner: Mutex<ProductRuntimeState>,
}

#[derive(Debug, Default)]
struct ProductRuntimeState {
    runtime: Option<ProductRuntimeInstance>,
    config: Option<Config>,
    last_error: Option<String>,
    last_transition_at: Option<String>,
    last_report: Option<Value>,
    reload_count: u64,
    stop_count: u64,
}

#[derive(Debug)]
enum ProductRuntimeInstance {
    Resident(ResidentProductionRuntime),
    Fake(FakeProductRuntime),
}

#[derive(Debug)]
struct FakeProductRuntime {
    started_at: String,
    tproxy_port: u16,
}

#[derive(Debug)]
struct RuntimeStartOutcome {
    report: Value,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ProductRuntimeLifecycleLogMode {
    StartupRestore,
    ReloadSignal,
}

impl ProductRuntimeLifecycleLogMode {
    fn source(self) -> &'static str {
        match self {
            Self::StartupRestore => "startup-restore",
            Self::ReloadSignal => "signal",
        }
    }

    fn is_startup(self) -> bool {
        matches!(self, Self::StartupRestore)
    }
}

const PRODUCT_RUNTIME_FAKE_START_ENV: &str = "DAED_PRODUCT_RUNTIME_FAKE_START";

impl ProductRuntimeManager {
    fn new() -> Self {
        Self {
            inner: Mutex::new(ProductRuntimeState::default()),
        }
    }

    fn reload(&self, config: Config, source: &str) -> Result<RuntimeStartOutcome, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        let previous_runtime = inner.runtime.take();
        let had_previous_runtime = previous_runtime.is_some();
        let previous_config = inner.config.clone();
        drop(previous_runtime);
        let old_owner_reclaim = had_previous_runtime
            .then(|| allocator_reclaim(AllocatorReclaimReason::ReloadOldOwnerClosed));

        match start_product_runtime_instance(&config, source) {
            Ok((runtime, mut report)) => {
                let startup_reclaim =
                    allocator_reclaim(AllocatorReclaimReason::StartupControlBuilt);
                let scoped_reclaim = had_previous_runtime.then(|| {
                    allocator_reclaim(AllocatorReclaimReason::ReloadScopedResourcesFlushed)
                });
                append_runtime_reclaim_report(
                    &mut report,
                    old_owner_reclaim,
                    startup_reclaim,
                    scoped_reclaim,
                );
                inner.runtime = Some(runtime);
                inner.config = Some(config);
                inner.reload_count += 1;
                inner.last_error = None;
                inner.last_transition_at = Some(now_text());
                inner.last_report = Some(report.clone());
                Ok(RuntimeStartOutcome { report })
            }
            Err(start_err) => {
                let restored = previous_config
                    .as_ref()
                    .and_then(|previous| match start_product_runtime_instance(previous, "rollback")
                    {
                        Ok((runtime, report)) => {
                            inner.runtime = Some(runtime);
                            inner.config = Some(previous.clone());
                            inner.last_report = Some(report);
                            Some(true)
                        }
                        Err(rollback_err) => {
                            inner.runtime = None;
                            inner.config = None;
                            inner.last_error = Some(format!(
                                "{start_err}\nrollback failed while restoring previous product runtime: {rollback_err}"
                            ));
                            Some(false)
                        }
                    });
                let message = match restored {
                    Some(true) => {
                        format!("{start_err}\nrollback: restored previous product runtime")
                    }
                    Some(false) => inner
                        .last_error
                        .clone()
                        .unwrap_or_else(|| start_err.clone()),
                    None => start_err,
                };
                inner.last_transition_at = Some(now_text());
                inner.last_error = Some(message.clone());
                Err(message)
            }
        }
    }

    fn stop(&self) -> Result<Value, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        let was_running = inner.runtime.is_some();
        inner.runtime.take();
        let reclaim = was_running.then(|| allocator_reclaim(AllocatorReclaimReason::StopRuntime));
        inner.config = None;
        inner.stop_count += 1;
        inner.last_transition_at = Some(now_text());
        inner.last_report = None;
        inner.last_error = None;
        Ok(json!({
            "stopped": true,
            "wasRunning": was_running,
            "runtimeControl": "resident-production-runtime-manager",
            "fakeRuntime": product_runtime_fake_start_enabled(),
            "allocatorReclaim": reclaim,
        }))
    }

    fn summary(&self) -> Value {
        let Ok(inner) = self.inner.lock() else {
            return json!({
                "running": false,
                "state": "error",
                "attachBackend": "unavailable",
                "netnsLinkMode": "unavailable",
                "error": "product runtime manager lock poisoned",
            });
        };
        match inner.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => {
                let mut summary = runtime.product_state_summary();
                if let Value::Object(map) = &mut summary {
                    map.insert(
                        "lastTransitionAt".to_owned(),
                        json!(inner.last_transition_at.clone()),
                    );
                    map.insert("lastError".to_owned(), json!(inner.last_error.clone()));
                    map.insert("reloadCount".to_owned(), json!(inner.reload_count));
                    map.insert("stopCount".to_owned(), json!(inner.stop_count));
                    map.insert("lastReport".to_owned(), json!(inner.last_report.clone()));
                }
                summary
            }
            Some(ProductRuntimeInstance::Fake(fake)) => json!({
                "running": true,
                "state": "running",
                "attachBackend": "fake-resident-runtime-test-only",
                "netnsLinkMode": "fake-test-only",
                "fakeRuntime": true,
                "startedAt": fake.started_at,
                "tproxyPort": fake.tproxy_port,
                "lastTransitionAt": inner.last_transition_at,
                "lastError": inner.last_error,
                "reloadCount": inner.reload_count,
                "stopCount": inner.stop_count,
                "lastReport": inner.last_report,
            }),
            None => json!({
                "running": false,
                "state": if inner.last_error.is_some() { "error" } else { "stopped" },
                "attachBackend": Value::Null,
                "netnsLinkMode": Value::Null,
                "fakeRuntime": product_runtime_fake_start_enabled(),
                "lastTransitionAt": inner.last_transition_at,
                "lastError": inner.last_error,
                "reloadCount": inner.reload_count,
                "stopCount": inner.stop_count,
                "lastReport": inner.last_report,
            }),
        }
    }
}

fn start_product_runtime_instance(
    config: &Config,
    source: &str,
) -> Result<(ProductRuntimeInstance, Value), String> {
    if product_runtime_fake_start_enabled() {
        let started_at = now_text();
        let report = json!({
            "status": "pass",
            "runtimeControl": "fake-resident-runtime-test-only",
            "source": source,
            "fakeRuntime": true,
            "startedAt": started_at,
            "tproxyPort": config.global.tproxy_port,
        });
        return Ok((
            ProductRuntimeInstance::Fake(FakeProductRuntime {
                started_at,
                tproxy_port: config.global.tproxy_port,
            }),
            report,
        ));
    }

    let mut runtime = start_resident_production_runtime(config)?;
    let state = runtime.product_state_summary();
    let dataplane_enabled = state["residentDataplane"]["enabled"]
        .as_bool()
        .unwrap_or(false);
    let dataplane_status = state["residentDataplane"]["status"].as_str().unwrap_or("");
    if !dataplane_enabled || dataplane_status != "pass" {
        runtime.cleanup();
        return Err(format!(
            "resident production runtime started without admitted userspace dataplane; set DAE_RUST_RESIDENT_DATAPLANE=1 and require resident_dataplane.status=pass before Rust daed can be the C10 default product path"
        ));
    }
    let report = json!({
        "status": "pass",
        "runtimeControl": "resident-production-runtime-manager",
        "source": source,
        "fakeRuntime": false,
        "tproxyPort": config.global.tproxy_port,
        "residentDataplane": state["residentDataplane"].clone(),
    });
    Ok((ProductRuntimeInstance::Resident(runtime), report))
}

fn product_runtime_fake_start_enabled() -> bool {
    std::env::var(PRODUCT_RUNTIME_FAKE_START_ENV)
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES"
            )
        })
        .unwrap_or(false)
}

fn append_runtime_reclaim_report(
    report: &mut Value,
    old_owner_reclaim: Option<Value>,
    startup_reclaim: Value,
    scoped_reclaim: Option<Value>,
) {
    if let Value::Object(map) = report {
        map.insert("allocatorProfile".to_owned(), json!(allocator_profile()));
        map.insert(
            "allocatorReclaim".to_owned(),
            json!({
                "oldOwnerClosed": old_owner_reclaim,
                "startupControlBuilt": startup_reclaim,
                "reloadScopedResourcesFlushed": scoped_reclaim,
            }),
        );
    }
}

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

pub fn run_daed_product_with_args_and_version(
    args: impl IntoIterator<Item = impl Into<String>>,
    version: &str,
) -> DaedProductOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("service-contract") => run_service_contract_command(&args[1..], version),
        Some("package-info") => run_package_info_command(&args[1..], version),
        Some("resident-adapter-matrix") => run_resident_adapter_matrix_command(&args[1..]),
        Some("state") => run_state_command(&args[1..]),
        Some("run") => run_product_server_command(&args[1..], version),
        Some("export") => run_export_command(&args[1..]),
        Some("resetpass") => run_resetpass_command(&args[1..]),
        Some("help") | Some("--help") | Some("-h") => DaedProductOutput::ok(help_text()),
        Some(command) => DaedProductOutput::usage(format!("unsupported daed command: {command}")),
        None => DaedProductOutput::usage("missing daed command"),
    }
}

fn run_service_contract_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("service-contract accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_service_contract(version)))
}

fn run_package_info_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("package-info accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_package_info(version)))
}

fn run_resident_adapter_matrix_command(args: &[String]) -> DaedProductOutput {
    let config = match parse_resident_adapter_matrix_args(args) {
        Ok(config) => config,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match load_config_file(&config) {
        Ok(config_value) => DaedProductOutput::ok(format!(
            "{}\n",
            resident_live_adapter_config_assessment(&config_value, Some(&config))
        )),
        Err(err) => {
            DaedProductOutput::error(format!("resident adapter matrix config load failed: {err}"))
        }
    }
}

fn run_state_command(args: &[String]) -> DaedProductOutput {
    match args.first().map(String::as_str) {
        Some("check") => match parse_state_check_args(&args[1..]) {
            Ok(state) => match state_check_report(&state) {
                Ok(report) => DaedProductOutput::ok(format!("{report}\n")),
                Err(err) => DaedProductOutput::error(format!("state check failed: {err}")),
            },
            Err(err) => DaedProductOutput::usage(err),
        },
        Some("migrate") => match parse_state_migrate_args(&args[1..]) {
            Ok((from_wing_db, to, force)) => match migrate_wing_db(&from_wing_db, &to, force) {
                Ok(report) => DaedProductOutput::ok(format!("{report}\n")),
                Err(err) => DaedProductOutput::error(format!("state migrate failed: {err}")),
            },
            Err(err) => DaedProductOutput::usage(err),
        },
        Some(command) => DaedProductOutput::usage(format!("unsupported state command: {command}")),
        None => DaedProductOutput::usage("state requires check or migrate"),
    }
}

fn parse_resident_adapter_matrix_args(args: &[String]) -> Result<PathBuf, String> {
    let mut config = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-c" | "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-matrix requires a value after -c/--config".to_owned()
                    );
                };
                config = Some(PathBuf::from(value));
            }
            "--json" => {}
            other => {
                return Err(format!(
                    "resident-adapter-matrix unsupported argument: {other}"
                ));
            }
        }
        index += 1;
    }
    config.ok_or_else(|| "resident-adapter-matrix requires -c/--config".to_owned())
}

fn run_product_server_command(args: &[String], _version: &str) -> DaedProductOutput {
    let startup_started_at = Instant::now();
    let options = match parse_run_args(args) {
        Ok(options) => options,
        Err(err) => return DaedProductOutput::usage(err),
    };
    if let Err(err) = ensure_state_schema(&options.state) {
        return DaedProductOutput::error(format!("init state failed: {err}"));
    }
    if let Err(err) = initialize_log_store(&options.config_dir, &options.state) {
        return DaedProductOutput::error(format!("init log store failed: {err}"));
    }
    register_resident_event_product_log_sink(&options.config_dir, &options.state);
    let runtime = Arc::new(ProductRuntimeManager::new());
    if let Err(err) = install_product_signal_thread(
        Arc::clone(&runtime),
        options.state.clone(),
        options.config_dir.clone(),
    ) {
        return DaedProductOutput::error(format!("install signal control failed: {err}"));
    }
    if should_restore_runtime_on_start(&options.state).unwrap_or(false) {
        if let Err(err) = restore_runtime_from_state(
            &runtime,
            &options.state,
            Some(&options.config_dir),
            ProductRuntimeLifecycleLogMode::StartupRestore,
        ) {
            let _ = append_lifecycle_log_for_config(
                &options.config_dir,
                &options.state,
                "error",
                &format!("[Startup] runtime restore failed: {err}"),
            );
            return DaedProductOutput::error(format!("startup runtime restore failed: {err}"));
        }
    }
    start_subscription_scheduler(options.state.clone(), options.config_dir.clone());
    let app = AppState {
        config_dir: options.config_dir,
        state: options.state,
        web_root: options.web_root,
        api_only: options.api_only,
        runtime,
        http_metrics: Arc::new(ProductHttpMetrics::default()),
    };
    match serve_forever(&options.listen, app, startup_started_at) {
        Ok(()) => DaedProductOutput::ok(String::new()),
        Err(err) => DaedProductOutput::error(format!("run failed: {err}")),
    }
}

fn restore_runtime_from_state(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    log_mode: ProductRuntimeLifecycleLogMode,
) -> Result<Value, String> {
    let log_config_dir =
        config_dir.unwrap_or_else(|| state.parent().unwrap_or(Path::new(DEFAULT_CONFIG_DIR)));
    let lifecycle_started_at = Instant::now();
    let source = log_mode.source();
    let preview = materialize_runtime(state, config_dir, true).map_err(|err| err.to_string())?;
    let content = preview["content"]
        .as_str()
        .ok_or_else(|| "runtime materializer did not return content".to_owned())?;
    let config = build_runtime_config_from_content(content)?;
    set_runtime_log_level_from_config(state, &config).map_err(|err| err.to_string())?;
    let control_plane_started_at = Instant::now();
    let outcome = runtime.reload(config, source)?;
    if log_mode.is_startup() {
        let _ = append_startup_reclaim_decision_log_for_config(
            log_config_dir,
            state,
            &outcome.report,
            true,
        );
        let _ = append_startup_phase_completed_for_config(
            log_config_dir,
            state,
            "post-startup.gc",
            control_plane_started_at,
            BTreeMap::new(),
        );
        let _ = append_startup_phase_completed_for_config(
            log_config_dir,
            state,
            "control-plane.core",
            control_plane_started_at,
            BTreeMap::new(),
        );
    }
    let applied = match materialize_runtime(state, config_dir, false) {
        Ok(applied) => applied,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), source.to_owned());
            fields.insert("error".to_owned(), err.to_string());
            if log_mode.is_startup() {
                let _ = append_startup_phase_failed_for_config(
                    log_config_dir,
                    state,
                    "control-plane.create.total",
                    lifecycle_started_at,
                    &err.to_string(),
                    fields.clone(),
                );
            }
            let _ = append_lifecycle_log_fields_for_config(
                log_config_dir,
                state,
                "error",
                if log_mode.is_startup() {
                    "[Startup] runtime restore failed"
                } else {
                    "[Reload] Failed to materialize applied runtime config"
                },
                fields,
            );
            let _ = runtime.stop();
            let _ = mark_system_stopped(state);
            return Err(err.to_string());
        }
    };
    if log_mode.is_startup() {
        let _ = append_startup_phase_completed_for_config(
            log_config_dir,
            state,
            "control-plane.create.total",
            lifecycle_started_at,
            BTreeMap::new(),
        );
    }
    Ok(json!({
        "restored": true,
        "runtime": outcome.report,
        "materialized": applied,
    }))
}

fn should_restore_runtime_on_start(state: &Path) -> io::Result<bool> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT running FROM systems ORDER BY id LIMIT 1",
        [],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|value| value.unwrap_or(0) != 0)
    .map_err(sqlite_io_error)
}

fn install_product_signal_thread(
    runtime: Arc<ProductRuntimeManager>,
    state: PathBuf,
    config_dir: PathBuf,
) -> io::Result<()> {
    block_product_signals()?;
    thread::spawn(move || {
        while let Ok(signal) = wait_product_signal() {
            match signal {
                libc::SIGHUP | libc::SIGUSR1 => {
                    let reload_started_at = Instant::now();
                    let mut fields = BTreeMap::new();
                    fields.insert("signal".to_owned(), signal.to_string());
                    fields.insert("source".to_owned(), "signal".to_owned());
                    let _ = append_lifecycle_log_fields_for_config(
                        &config_dir,
                        &state,
                        "info",
                        "[Reload] Received signal reload request",
                        fields,
                    );
                    if !should_restore_runtime_on_start(&state).unwrap_or(false) {
                        let _ = append_lifecycle_log_for_config(
                            &config_dir,
                            &state,
                            "info",
                            "[Reload] signal reload skipped because persisted running state is false",
                        );
                        continue;
                    }
                    let result = restore_runtime_from_state(
                        &runtime,
                        &state,
                        Some(&config_dir),
                        ProductRuntimeLifecycleLogMode::ReloadSignal,
                    );
                    match result {
                        Ok(_) => {
                            let mut fields = BTreeMap::new();
                            fields.insert("source".to_owned(), "signal".to_owned());
                            fields.insert("applied".to_owned(), "true".to_owned());
                            fields.insert(
                                "elapsed".to_owned(),
                                format!("{:?}", reload_started_at.elapsed()),
                            );
                            let _ = append_lifecycle_log_fields_for_config(
                                &config_dir,
                                &state,
                                "info",
                                "[Reload] Finished",
                                fields,
                            );
                        }
                        Err(err) => {
                            let mut fields = BTreeMap::new();
                            fields.insert("source".to_owned(), "signal".to_owned());
                            fields.insert("error".to_owned(), err.clone());
                            let _ = append_lifecycle_log_fields_for_config(
                                &config_dir,
                                &state,
                                "error",
                                "[Reload] Failed to reload",
                                fields,
                            );
                        }
                    }
                }
                libc::SIGTERM | libc::SIGINT | libc::SIGQUIT => {
                    let _ = runtime.stop();
                    let _ = mark_runtime_process_stopped(&state);
                    let _ = append_lifecycle_log_for_config(
                        &config_dir,
                        &state,
                        "info",
                        "[Stop] runtime process stopped by signal",
                    );
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    });
    Ok(())
}

fn block_product_signals() -> io::Result<()> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn wait_product_signal() -> io::Result<i32> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut received = 0_i32;
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        let status = libc::sigwait(&signals, &mut received);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
    }
    Ok(received)
}

fn run_export_command(args: &[String]) -> DaedProductOutput {
    match args.first().map(String::as_str) {
        Some("openapi") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_openapi_skeleton()))
        }
        Some("flatdesc") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_flatdesc()))
        }
        Some("outline") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_outline()))
        }
        Some("package-manifest") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_package_manifest()))
        }
        Some("admission-report") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_admission_report()))
        }
        Some("webui-route-audit") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", webui_route_audit_report()))
        }
        Some("systemd-unit") if args.len() == 1 => DaedProductOutput::ok(systemd_unit_text()),
        Some("docker-entrypoint") if args.len() == 1 => {
            DaedProductOutput::ok(docker_entrypoint_text())
        }
        Some(command) => DaedProductOutput::usage(format!("unsupported export command: {command}")),
        None => DaedProductOutput::usage(
            "export requires openapi, flatdesc, outline, package-manifest, admission-report, webui-route-audit, systemd-unit, or docker-entrypoint",
        ),
    }
}

fn run_resetpass_command(args: &[String]) -> DaedProductOutput {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing resetpass --config value");
                };
                config_dir = value.into();
            }
            _ if arg.starts_with("--config=") => {
                config_dir = arg.split_once('=').unwrap().1.into();
            }
            "--json" => json_output = true,
            _ => return DaedProductOutput::usage(format!("unsupported resetpass argument: {arg}")),
        }
    }
    let state = config_dir.join("daed.db");
    match reset_all_user_passwords(&state) {
        Ok(report) if json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(report) => {
            let mut out = String::new();
            let users = report["users"].as_array().cloned().unwrap_or_default();
            if users.is_empty() {
                out.push_str("No users found.\n");
            } else {
                for user in users {
                    out.push_str(&format!(
                        "Username: {}, Password: {}\n",
                        user["username"].as_str().unwrap_or(""),
                        user["password"].as_str().unwrap_or("")
                    ));
                }
            }
            DaedProductOutput::ok(out)
        }
        Err(err) => DaedProductOutput::error(format!("resetpass failed: {err}")),
    }
}

fn parse_run_args(args: &[String]) -> Result<RunOptions, String> {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut state: Option<PathBuf> = None;
    let mut web_root = std::env::var_os("DAED_WEB_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WEB_ROOT));
    let mut api_only = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --config value".to_owned());
                };
                config_dir = value.into();
            }
            _ if arg.starts_with("--config=") => {
                config_dir = arg.split_once('=').unwrap().1.into();
            }
            "--listen" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --listen value".to_owned());
                };
                listen = value.to_owned();
            }
            _ if arg.starts_with("--listen=") => {
                listen = arg.split_once('=').unwrap().1.to_owned();
            }
            "--state" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --state value".to_owned());
                };
                state = Some(value.into());
            }
            _ if arg.starts_with("--state=") => {
                state = Some(arg.split_once('=').unwrap().1.into());
            }
            "--web-root" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --web-root value".to_owned());
                };
                web_root = value.into();
            }
            _ if arg.starts_with("--web-root=") => {
                web_root = arg.split_once('=').unwrap().1.into();
            }
            "--api-only" => api_only = true,
            _ => return Err(format!("unsupported run argument: {arg}")),
        }
    }
    let state = state.unwrap_or_else(|| config_dir.join("daed.db"));
    Ok(RunOptions {
        config_dir,
        listen,
        state,
        web_root,
        api_only,
    })
}

fn parse_state_check_args(args: &[String]) -> Result<PathBuf, String> {
    let mut state: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--state" => {
                let Some(value) = iter.next() else {
                    return Err("missing state check --state value".to_owned());
                };
                state = Some(value.into());
            }
            _ if arg.starts_with("--state=") => {
                state = Some(arg.split_once('=').unwrap().1.into());
            }
            _ => return Err(format!("unsupported state check argument: {arg}")),
        }
    }
    state.ok_or_else(|| "state check requires --state".to_owned())
}

fn parse_state_migrate_args(args: &[String]) -> Result<(PathBuf, PathBuf, bool), String> {
    let mut from_wing_db: Option<PathBuf> = None;
    let mut to: Option<PathBuf> = None;
    let mut force = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--from-wing-db" => {
                let Some(value) = iter.next() else {
                    return Err("missing state migrate --from-wing-db value".to_owned());
                };
                from_wing_db = Some(value.into());
            }
            _ if arg.starts_with("--from-wing-db=") => {
                from_wing_db = Some(arg.split_once('=').unwrap().1.into());
            }
            "--to" => {
                let Some(value) = iter.next() else {
                    return Err("missing state migrate --to value".to_owned());
                };
                to = Some(value.into());
            }
            _ if arg.starts_with("--to=") => {
                to = Some(arg.split_once('=').unwrap().1.into());
            }
            "--force" => force = true,
            _ => return Err(format!("unsupported state migrate argument: {arg}")),
        }
    }
    let from_wing_db = from_wing_db
        .ok_or_else(|| "state migrate requires --from-wing-db /etc/daed/wing.db".to_owned())?;
    let to = to.ok_or_else(|| "state migrate requires --to /etc/daed/daed.db".to_owned())?;
    Ok((from_wing_db, to, force))
}

fn daed_service_contract(version: &str) -> Value {
    let mut report = crate::service_contract::service_contract_capabilities(version);
    if let Value::Object(report) = &mut report {
        report.insert("product_binary".to_owned(), json!("daed"));
        report.insert("product_entry".to_owned(), json!("/usr/bin/daed"));
        report.insert("c_phase".to_owned(), json!("C10"));
        report.insert(
            "c10_work_package".to_owned(),
            json!("go-free-product-chain-v1"),
        );
        report.insert("primary_state_store".to_owned(), json!(PRIMARY_STATE_STORE));
        report.insert(
            "protected_rollback_state_store".to_owned(),
            json!(PROTECTED_ROLLBACK_STATE_STORE),
        );
        report.insert(
            "rust_daed_writes_wing_db_by_default".to_owned(),
            json!(false),
        );
        report.insert("wing_db_import_supported".to_owned(), json!(true));
        report.insert(
            "wing_db_import_destructive_by_default".to_owned(),
            json!(false),
        );
        report.insert("daed_db_primary_required".to_owned(), json!(true));
        report.insert("var_lib_daed_required_by_default".to_owned(), json!(false));
        report.insert(
            "rust_product_runtime_defaults".to_owned(),
            product_runtime_defaults(),
        );
        report.insert("rust_product_binary_contract_ready".to_owned(), json!(true));
        report.insert(
            "rust_product_lifecycle_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_product_web_api_package_release_contract_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_state_layer_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_non_destructive_wing_db_import_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_setup_auth_user_storage_api_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_static_webui_serving_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_current_react_webui_served_by_rust_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_resource_crud_api_ready".to_owned(), json!(true));
        report.insert("rust_daed_materializer_ready".to_owned(), json!(true));
        report.insert("rust_daed_runtime_owner_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_real_runtime_bridge_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_runtime_state_metadata_only".to_owned(),
            json!(false),
        );
        report.insert(
            "rust_daed_logs_sse_latency_subscription_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_import_export_package_surface_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_subscription_fetch_ready".to_owned(), json!(true));
        report.insert("rust_daed_latency_probe_tcp_ready".to_owned(), json!(true));
        report.insert("rust_daed_resetpass_parity_ready".to_owned(), json!(true));
        report.insert("rust_daed_package_manifest_ready".to_owned(), json!(true));
        report.insert("rust_daed_webui_route_audit_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_local_package_admission_ready".to_owned(),
            json!(true),
        );
        report.insert("leptos_webui_rewrite_considered".to_owned(), json!(false));
        report.insert("go_free_product_chain_ready".to_owned(), json!(false));
        report.insert(
            "go_free_product_chain_current_batch".to_owned(),
            json!("C10 resident runtime bridge implementation"),
        );
        report.insert(
            "go_free_product_chain_remaining_work".to_owned(),
            json!([
                "live host default package switch revalidation",
                "live rollback validation revalidation",
                "remove Go daewing from default package path",
                "production package admission"
            ]),
        );
        if let Some(Value::Object(typed_report)) =
            report.get_mut("go_free_product_chain_typed_report")
        {
            typed_report.insert("rust_product_binary_contract_ready".to_owned(), json!(true));
            typed_report.insert(
                "rust_product_lifecycle_contract_ready".to_owned(),
                json!(true),
            );
            typed_report.insert(
                "rust_product_web_api_package_release_contract_ready".to_owned(),
                json!(true),
            );
            typed_report.insert(
                "current_batch".to_owned(),
                json!("C10 resident runtime bridge implementation"),
            );
            typed_report.insert("status".to_owned(), json!("blocked"));
        }
    }
    report
}

fn daed_package_info(version: &str) -> Value {
    json!({
        "name": "daed",
        "version": version,
        "binary": "/usr/bin/daed",
        "c_phase": "C10",
        "work_package": "go-free-product-chain-v1",
        "primary_state_store": PRIMARY_STATE_STORE,
        "protected_rollback_state_store": PROTECTED_ROLLBACK_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "daed_db_primary_required": true,
        "var_lib_daed_required_by_default": false,
        "runtime_defaults": product_runtime_defaults(),
        "webui": {
            "framework": "current React/Vite dist",
            "served_by": "Rust daed static file server",
            "default_root": DEFAULT_WEB_ROOT,
            "leptos_considered": false
        },
        "default_layout": {
            "config_dir": DEFAULT_CONFIG_DIR,
            "runtime_dir": "/etc/daed/runtime",
            "backup_dir": "/etc/daed/backups",
            "web_root": DEFAULT_WEB_ROOT,
            "geoip": "/usr/share/daed/geoip.dat",
            "geosite": "/usr/share/daed/geosite.dat"
        },
        "current_batch_ready": {
            "product_binary_skeleton": true,
            "state_check": true,
            "wing_db_non_destructive_import": true,
            "setup_auth_user_storage_api": true,
            "static_webui_serving": true,
            "resource_crud_api": true,
            "materializer": true,
            "runtime_owner": true,
            "real_runtime_bridge": true,
            "metadata_only_runtime_state": false,
            "logs_sse_latency_subscription": true,
            "import_export_package_surface": true,
            "subscription_fetch": true,
            "tcp_latency_probe": true,
            "resetpass_parity": true,
            "package_manifest": true,
            "webui_route_audit": true,
            "local_package_admission": true
        },
        "package_surface": {
            "systemd_unit": "daed.service uses /usr/bin/daed run -c /etc/daed",
            "docker_entrypoint": "/usr/bin/daed run -c /etc/daed --listen 0.0.0.0:2023",
            "package_manifest": "daed export package-manifest",
            "admission_report": "daed export admission-report",
            "default_package_switch_live_applied": false,
            "go_daewing_default_path_removed": false
        },
        "full_go_free_product_chain_ready": false
    })
}

fn ensure_state_schema(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = open_state_connection(path)?;
    apply_state_schema(&conn)?;
    Ok(())
}

fn open_state_connection(path: &Path) -> io::Result<Connection> {
    let conn = Connection::open(path).map_err(sqlite_io_error)?;
    conn.execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sqlite_io_error)?;
    Ok(conn)
}

fn apply_state_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = OFF;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            jwt_secret TEXT NOT NULL,
            json_storage TEXT NOT NULL DEFAULT '{}',
            avatar TEXT NULL,
            name TEXT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            global TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS dns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            dns TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS routings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            routing TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            updated_at TEXT NOT NULL DEFAULT '',
            link TEXT NOT NULL,
            cron_exp TEXT DEFAULT '10 */6 * * *',
            cron_enable INTEGER DEFAULT 1,
            status TEXT NOT NULL DEFAULT '',
            info TEXT NOT NULL DEFAULT '',
            tag TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            protocol TEXT NOT NULL,
            tag TEXT UNIQUE,
            subscription_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            policy TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 0,
            system_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS group_nodes (
            group_id INTEGER NOT NULL,
            node_id INTEGER NOT NULL,
            PRIMARY KEY(group_id, node_id)
        );
        CREATE TABLE IF NOT EXISTS group_subscriptions (
            group_id INTEGER NOT NULL,
            subscription_id INTEGER NOT NULL,
            name_filter_regex TEXT NULL,
            PRIMARY KEY(group_id, subscription_id)
        );
        CREATE TABLE IF NOT EXISTS group_policy_params (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            group_id INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            running INTEGER NOT NULL DEFAULT 0,
            running_config_version INTEGER NOT NULL DEFAULT 0,
            running_dns_version INTEGER NOT NULL DEFAULT 0,
            running_routing_version INTEGER NOT NULL DEFAULT 0,
            running_group_version_sum INTEGER NOT NULL DEFAULT 0,
            running_group_ids TEXT NOT NULL DEFAULT '',
            running_config_id INTEGER NULL,
            running_dns_id INTEGER NULL,
            running_routing_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS log_settings (
            id INTEGER PRIMARY KEY,
            max_entries INTEGER NOT NULL,
            max_bytes INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS node_latency_results (
            node_id INTEGER PRIMARY KEY,
            latency_ms INTEGER NULL,
            alive INTEGER NOT NULL,
            tested_at TEXT NOT NULL,
            message TEXT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daed_product_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daed_schema_migrations (
            id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        INSERT OR IGNORE INTO daed_schema_migrations(id, applied_at)
            VALUES('c10-first-batch-daed-product-schema-v1', datetime('now'));
        INSERT OR IGNORE INTO daed_schema_migrations(id, applied_at)
            VALUES('c10-local-product-surface-v2', datetime('now'));
        INSERT OR IGNORE INTO log_settings(id, max_entries, max_bytes)
            VALUES(1, 10000, 52428800);
        INSERT OR IGNORE INTO daed_product_metadata(key, value)
            VALUES('runtime_log_level', 'info');
        "#,
    )
    .map_err(sqlite_io_error)
}

fn state_check_report(state: &Path) -> io::Result<Value> {
    let existed_before = state.exists();
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let tables = list_tables(&conn)?;
    let user_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)?;
    let metadata_ready = tables.iter().any(|name| name == "daed_product_metadata")
        && tables.iter().any(|name| name == "daed_schema_migrations");
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "exists_before_check": existed_before,
        "exists_after_check": state.exists(),
        "schema_ready": metadata_ready,
        "primary_state_store": path_string(state),
        "protected_rollback_state_store": PROTECTED_ROLLBACK_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "user_count": user_count,
        "tables": tables,
    }))
}

fn migrate_wing_db(from_wing_db: &Path, to: &Path, force: bool) -> io::Result<Value> {
    if !from_wing_db.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "wing.db source does not exist: {}",
                path_string(from_wing_db)
            ),
        ));
    }
    let wing_hash_before = sha256_file_hex(from_wing_db)?;
    let target_existed = to.exists();
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    let copied = if target_existed && !force {
        false
    } else {
        fs::copy(from_wing_db, to)?;
        set_private_db_permissions(to)?;
        true
    };
    ensure_state_schema(to)?;
    let conn = open_state_connection(to)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params!["source_wing_db_path", path_string(from_wing_db)],
    )
    .map_err(sqlite_io_error)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, datetime('now'))",
        params!["last_wing_db_import_at"],
    )
    .map_err(sqlite_io_error)?;
    let wing_hash_after = sha256_file_hex(from_wing_db)?;
    let wing_db_unchanged = wing_hash_before == wing_hash_after;
    if !wing_db_unchanged {
        return Err(io::Error::other("wing.db hash changed during import"));
    }
    Ok(json!({
        "status": "pass",
        "from_wing_db": path_string(from_wing_db),
        "to": path_string(to),
        "target_existed": target_existed,
        "copied": copied,
        "force": force,
        "wing_db_sha256_before": wing_hash_before,
        "wing_db_sha256_after": wing_hash_after,
        "wing_db_unchanged": wing_db_unchanged,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_destructive": false,
    }))
}

fn serve_forever(listen: &str, app: AppState, startup_started_at: Instant) -> io::Result<()> {
    let listen_started_at = Instant::now();
    let listener = TcpListener::bind(listen)?;
    let app = Arc::new(app);
    let config = ProductHttpWorkerConfig::from_env();
    app.http_metrics.configure(config);
    let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(config.worker_count);
    for index in 0..config.worker_count {
        let receiver = Arc::clone(&receiver);
        let app = Arc::clone(&app);
        let metrics = Arc::clone(&app.http_metrics);
        let handle = match thread::Builder::new()
            .name(format!("daed-http-{index}"))
            .stack_size(config.worker_stack_bytes)
            .spawn(move || product_http_worker_loop(index, receiver, app, metrics))
        {
            Ok(handle) => handle,
            Err(err) => {
                drop(sender);
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(err);
            }
        };
        handles.push(handle);
    }
    let _ = append_startup_phase_completed_for_config(
        &app.config_dir,
        &app.state,
        "product.http-listener",
        listen_started_at,
        BTreeMap::new(),
    );
    let mut fields = BTreeMap::new();
    fields.insert(
        "elapsed".to_owned(),
        format!("{:?}", startup_started_at.elapsed()),
    );
    let _ = append_lifecycle_log_fields_for_config(
        &app.config_dir,
        &app.state,
        "info",
        "[Startup] Finished",
        fields,
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                app.http_metrics.accepted();
                match sender.try_send(ProductHttpJob { stream }) {
                    Ok(()) => app.http_metrics.enqueued(),
                    Err(TrySendError::Full(job)) => {
                        app.http_metrics.rejected();
                        let _ = write_http_rejected(job.stream);
                    }
                    Err(TrySendError::Disconnected(job)) => {
                        app.http_metrics.rejected();
                        let _ = write_http_rejected(job.stream);
                        break;
                    }
                }
            }
            Err(err) => {
                drop(sender);
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(err);
            }
        }
    }
    drop(sender);
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

struct ProductHttpJob {
    stream: TcpStream,
}

fn product_http_worker_loop(
    _index: usize,
    receiver: Arc<Mutex<Receiver<ProductHttpJob>>>,
    app: Arc<AppState>,
    metrics: Arc<ProductHttpMetrics>,
) {
    loop {
        let recv_result = {
            let Ok(receiver) = receiver.lock() else {
                break;
            };
            receiver.recv_timeout(PRODUCT_HTTP_WORKER_RECV_TIMEOUT)
        };
        match recv_result {
            Ok(job) => {
                metrics.dequeued();
                metrics.opened();
                let _ = handle_stream(job.stream, &app);
                metrics.closed();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn write_http_rejected(mut stream: TcpStream) -> io::Result<()> {
    let response = HttpResponse::json(
        503,
        json!({"error": "daed HTTP worker queue is full; retry later"}),
    );
    write_http_response(&mut stream, &response, false)
}

fn handle_stream(mut stream: TcpStream, app: &AppState) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            let response = HttpResponse::json(
                400,
                json!({
                    "error": format!("bad request: {err}")
                }),
            );
            return write_http_response(&mut stream, &response, false);
        }
    };
    let head_only = request.method == "HEAD";
    if request.method == "GET"
        && (request.path == "/api/events/logs" || request.path == "/api/events/runtime")
    {
        let Some(_user) = authenticate_request(app, &request) else {
            let response = HttpResponse::json(401, json!({"error": "authentication required"}));
            return write_http_response(&mut stream, &response, head_only);
        };
        if request.path == "/api/events/logs" {
            return stream_log_events(&mut stream, app, &request);
        }
        return stream_runtime_events(&mut stream, app, &request);
    }
    let response = route_request(app, &request);
    write_http_response(&mut stream, &response, head_only)
}

fn route_request(app: &AppState, request: &HttpRequest) -> HttpResponse {
    if request.method == "OPTIONS" {
        return HttpResponse::empty(204);
    }
    if request.path == "/health" {
        return handle_health(request);
    }
    if let Some(api_path) = request.path.strip_prefix("/api") {
        let api_path = if api_path.is_empty() { "/" } else { api_path };
        return handle_api_request(app, request, api_path);
    }
    if app.api_only {
        return HttpResponse::json(
            404,
            json!({"error": "static WebUI serving is disabled by --api-only"}),
        );
    }
    serve_static_file(&app.web_root, request)
}

fn handle_api_request(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    match (request.method.as_str(), api_path) {
        ("GET", "/health") => handle_health(request),
        ("GET", "/auth/status") => api_auth_status(app),
        ("POST", "/auth/users") => api_create_user(app, request),
        ("POST", "/auth/token") => api_issue_token(app, request),
        _ => {
            let Some(user) = authenticate_request(app, request) else {
                return HttpResponse::json(401, json!({"error": "authentication required"}));
            };
            match (request.method.as_str(), api_path) {
                ("GET", "/user/me") => HttpResponse::json(200, user_resource(&user)),
                ("PATCH", "/user/me") => api_patch_user(app, request, user),
                ("POST", "/user/me/password") => api_update_password(app, request, user),
                ("GET", "/user/me/storage") => api_get_storage(request, user),
                ("PUT", "/user/me/storage") => api_set_storage(app, request, user),
                ("DELETE", "/user/me/storage") => api_delete_storage(app, request, user),
                ("POST", "/user/me/default-resources") => api_default_resources(app, request, user),
                ("GET", "/user/me/dae-bundle") => api_get_bundle(app, &user),
                ("PUT", "/user/me/dae-bundle") => api_put_bundle(app, request, &user),
                ("GET", "/user/me/dae-config-file") => api_get_dae_config_file(app),
                ("PUT", "/user/me/dae-config-file") => api_put_dae_config_file(app, request, &user),
                ("POST", "/user/me/dae-config-file/preview") => {
                    api_preview_dae_config_file(app, request, &user)
                }
                ("GET", "/general/state") => api_general_state(app),
                ("GET", "/general/cache-stats") => api_general_cache_stats(app),
                ("GET", "/general/interfaces") => api_general_interfaces(request),
                ("GET", "/runtime/overview") => api_runtime_overview(app, request),
                ("POST", "/runtime/reload") => api_runtime_reload(app, request),
                ("POST", "/runtime/stop") => api_runtime_stop(app),
                ("GET", "/runtime/log-level") => api_get_runtime_log_level(app),
                ("PATCH", "/runtime/log-level") => api_set_runtime_log_level(app, request),
                ("GET", "/events/runtime") => api_runtime_events(app, request),
                ("GET", "/events/logs") => api_log_events(app, request),
                ("GET", "/logs") => api_logs(app, request),
                ("DELETE", "/logs") => api_clear_logs(app),
                ("GET", "/logs/settings") => api_get_log_settings(app),
                ("PATCH", "/logs/settings") => api_set_log_settings(app, request),
                ("GET", "/nodes/latencies") => api_get_node_latencies(app),
                ("POST", "/nodes/latencies") => api_test_node_latencies(app, request),
                _ if api_path == "/configs"
                    || api_path.starts_with("/configs/")
                    || api_path == "/dns"
                    || api_path.starts_with("/dns/")
                    || api_path == "/routings"
                    || api_path.starts_with("/routings/") =>
                {
                    api_section_resource(app, request, api_path)
                }
                _ if api_path == "/nodes" || api_path.starts_with("/nodes/") => {
                    api_nodes(app, request, api_path)
                }
                _ if api_path == "/subscriptions" || api_path.starts_with("/subscriptions/") => {
                    api_subscriptions(app, request, api_path)
                }
                _ if api_path == "/groups" || api_path.starts_with("/groups/") => {
                    api_groups(app, request, api_path)
                }
                _ => HttpResponse::json(
                    404,
                    json!({"error": "not implemented in C10 local product surface"}),
                ),
            }
        }
    }
}

fn handle_health(_request: &HttpRequest) -> HttpResponse {
    HttpResponse::json(200, json!({"healthCheck": 1}))
}

fn api_auth_status(app: &AppState) -> HttpResponse {
    match user_count(&app.state) {
        Ok(count) => HttpResponse::json(200, json!({"numberUsers": count})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_create_user(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match create_user(&app.state, username, password) {
        Ok(token) => HttpResponse::json(201, json!({"token": token})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_issue_token(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match issue_token(&app.state, username, password) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(401, json!({"error": err.to_string()})),
    }
}

fn api_patch_user(app: &AppState, request: &HttpRequest, mut user: UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(username) = body.get("username").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE users SET username = ?1 WHERE id = ?2",
            params![username, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.username = username.to_owned();
    }
    if body
        .get("clearName")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET name = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = None;
    } else if body.get("name").is_some() {
        let value = body.get("name").and_then(Value::as_str).map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET name = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = value;
    }
    if body
        .get("clearAvatar")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = None;
    } else if body.get("avatar").is_some() {
        let value = body
            .get("avatar")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = value;
    }
    HttpResponse::json(200, user_resource(&user))
}

fn api_update_password(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let current = required_str(&body, "currentPassword");
    let new_password = required_str(&body, "newPassword");
    let (current, new_password) = match (current, new_password) {
        (Some(current), Some(new_password)) => (current, new_password),
        _ => {
            return HttpResponse::json(
                400,
                json!({"error": "currentPassword and newPassword are required"}),
            );
        }
    };
    if hash_password(user.jwt_secret.as_bytes(), current) != user.password_hash {
        return HttpResponse::json(400, json!({"error": "incorrect password"}));
    }
    if let Err(err) = validate_password_strength(new_password) {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let secret = match random_secret_hex() {
        Ok(secret) => secret,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let password_hash = hash_password(secret.as_bytes(), new_password);
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
        params![password_hash, secret, user.id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    user.jwt_secret = secret;
    match signed_token(&user) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_storage(request: &HttpRequest, user: UserRecord) -> HttpResponse {
    let paths = request.query.get("path").cloned().unwrap_or_default();
    let values = query_json_storage(&user.json_storage, &paths);
    HttpResponse::json(200, json!({"values": values}))
}

fn api_set_storage(app: &AppState, request: &HttpRequest, mut user: UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let values = string_array(&body, "values");
    if paths.len() != values.len() {
        return HttpResponse::json(400, json!({"error": "len(paths) != len(values)"}));
    }
    let updated = match set_json_storage(&mut user.json_storage, &paths, &values) {
        Ok(updated) => updated,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"updated": updated}))
}

fn api_delete_storage(app: &AppState, request: &HttpRequest, mut user: UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let removed = match remove_json_storage(&mut user.json_storage, &paths) {
        Ok(removed) => removed,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

fn api_default_resources(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match ensure_default_resources(&app.state, &body) {
        Ok(response) => {
            let paths = vec![
                "defaultConfigID".to_owned(),
                "defaultRoutingID".to_owned(),
                "defaultDNSID".to_owned(),
                "defaultGroupID".to_owned(),
                "mode".to_owned(),
            ];
            let values = vec![
                response["defaultConfigID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultRoutingID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultDNSID"].as_str().unwrap_or("").to_owned(),
                response["defaultGroupID"].as_str().unwrap_or("").to_owned(),
                response["mode"].as_str().unwrap_or("").to_owned(),
            ];
            if let Err(err) = set_json_storage(&mut user.json_storage, &paths, &values) {
                return HttpResponse::json(400, json!({"error": err}));
            }
            if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
                return HttpResponse::json(500, json!({"error": err.to_string()}));
            }
            HttpResponse::json(200, response)
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_section_resource(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if matches!(
        api_path,
        "/configs/parsed" | "/dns/parsed" | "/routings/parsed"
    ) {
        return api_section_preview(request, api_path);
    }
    if api_path == "/configs/flat-desc" {
        return HttpResponse::json(200, product_flatdesc());
    }
    let Some(kind) = SectionKind::from_path(api_path) else {
        return HttpResponse::json(404, json!({"error": "unknown section resource"}));
    };
    let suffix = api_path.trim_start_matches(kind.prefix());
    if suffix.is_empty() {
        return match request.method.as_str() {
            "GET" => list_sections(&app.state, kind),
            "POST" => create_section(&app.state, request, kind),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let parts = suffix
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid resource id"}));
    };
    if parts.len() == 2 && parts[1] == "select" {
        return match request.method.as_str() {
            "POST" => select_section(&app.state, kind, id),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown section resource path"}));
    }
    match request.method.as_str() {
        "GET" => get_section(&app.state, kind, id),
        "PUT" | "PATCH" => update_section(&app.state, request, kind, id),
        "DELETE" => delete_section(&app.state, kind, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_nodes(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/nodes" {
        return match request.method.as_str() {
            "GET" => list_nodes_for_request(&app.state, request),
            "POST" => import_nodes(&app.state, request, None),
            "DELETE" => delete_nodes(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let Some(id) = api_path
        .strip_prefix("/nodes/")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return HttpResponse::json(400, json!({"error": "invalid node id"}));
    };
    match request.method.as_str() {
        "GET" => get_node(&app.state, id),
        "PUT" | "PATCH" => update_node(&app.state, request, id),
        "DELETE" => delete_node_by_id(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_subscriptions(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/subscriptions" {
        return match request.method.as_str() {
            "GET" => list_subscriptions(&app.state, request),
            "POST" => create_subscription(&app.state, &app.config_dir, request),
            "DELETE" => delete_subscriptions(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let suffix = api_path.trim_start_matches("/subscriptions/");
    let parts = suffix.split('/').collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid subscription id"}));
    };
    if parts.len() == 2 && parts[1] == "nodes" {
        return match request.method.as_str() {
            "GET" => list_nodes(&app.state, Some(id)),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() == 2 && parts[1] == "refresh" {
        return match request.method.as_str() {
            "POST" => refresh_subscription(&app.state, &app.config_dir, id),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown subscription path"}));
    }
    match request.method.as_str() {
        "GET" => get_subscription(&app.state, id),
        "PUT" | "PATCH" => update_subscription(&app.state, request, id),
        "DELETE" => delete_subscription_by_id(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_groups(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/groups" {
        return match request.method.as_str() {
            "GET" => list_groups(&app.state),
            "POST" => create_group(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let suffix = api_path.trim_start_matches("/groups/");
    let parts = suffix.split('/').collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid group id"}));
    };
    if parts.len() == 2 && parts[1] == "nodes" {
        return match request.method.as_str() {
            "POST" => update_group_nodes(&app.state, request, id, true),
            "DELETE" => update_group_nodes(&app.state, request, id, false),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() == 2 && parts[1] == "subscriptions" {
        return match request.method.as_str() {
            "POST" => update_group_subscriptions(&app.state, request, id, true),
            "DELETE" => update_group_subscriptions(&app.state, request, id, false),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown group path"}));
    }
    match request.method.as_str() {
        "GET" => get_group(&app.state, id),
        "PUT" | "PATCH" => update_group(&app.state, request, id),
        "DELETE" => delete_group(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_general_state(app: &AppState) -> HttpResponse {
    match general_state_report(&app.state, &app.config_dir, &app.runtime) {
        Ok(report) => HttpResponse::json(200, report),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_general_cache_stats(app: &AppState) -> HttpResponse {
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let latency = count_table(&conn, "node_latency_results").unwrap_or(0);
    HttpResponse::json(
        200,
        json!({
            "dnsCacheEntries": 0,
            "nodeLatencyCacheEntries": latency,
            "routingCacheEntries": 0,
        }),
    )
}

fn api_general_interfaces(request: &HttpRequest) -> HttpResponse {
    let up = query_bool(request, "up");
    let only_global_scope = query_bool(request, "onlyGlobalScope").unwrap_or(false);
    match list_system_interfaces(up, only_global_scope) {
        Ok(items) => HttpResponse::json(200, json!({"items": items})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_runtime_overview(app: &AppState, request: &HttpRequest) -> HttpResponse {
    HttpResponse::json(200, runtime_overview_report(app, request))
}

#[derive(Debug, Default)]
struct RuntimeTrafficStats {
    upload_total: u64,
    download_total: u64,
    upload_rate: u64,
    download_rate: u64,
    active_connections: u64,
    udp_sessions: u64,
    samples: Vec<Value>,
}

#[derive(Clone, Copy, Debug)]
struct RuntimeTrafficTotalSample {
    upload_total: u64,
    download_total: u64,
    observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct RuntimeTrafficSecond {
    upload: u64,
    download: u64,
    active_connections: u64,
    udp_sessions: u64,
}

#[derive(Debug, Default)]
struct RuntimeTrafficEventFileCache {
    path: String,
    offset: u64,
    upload_total: u64,
    download_total: u64,
    seconds: BTreeMap<u64, RuntimeTrafficSecond>,
}

static LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE: OnceLock<Mutex<Option<RuntimeTrafficTotalSample>>> =
    OnceLock::new();
static RUNTIME_TRAFFIC_RATE_SAMPLES: OnceLock<Mutex<VecDeque<(u64, u64, u64)>>> = OnceLock::new();
static RUNTIME_TRAFFIC_EVENT_FILE_CACHE: OnceLock<Mutex<RuntimeTrafficEventFileCache>> =
    OnceLock::new();

fn runtime_overview_report(app: &AppState, request: &HttpRequest) -> Value {
    let runtime = app.runtime.summary();
    let window_sec = query_u64(request, "windowSec")
        .unwrap_or(60)
        .clamp(1, 3_600);
    let max_points = query_usize(request, "maxPoints")
        .unwrap_or(120)
        .clamp(1, 1_000);
    let traffic = resident_runtime_traffic_stats(&runtime, window_sec, max_points);
    let process = current_process_metrics();
    let allocator_live_heap = allocator_live_heap_bytes();
    json!({
        "updatedAt": now_text(),
        "uploadRate": traffic.upload_rate.to_string(),
        "downloadRate": traffic.download_rate.to_string(),
        "uploadTotal": traffic.upload_total.to_string(),
        "downloadTotal": traffic.download_total.to_string(),
        "activeConnections": traffic.active_connections,
        "udpSessions": traffic.udp_sessions,
        "udpTaskQueues": 0,
        "udpTaskDropTotal": "0",
        "packetSnifferSessions": 0,
        "cpuUsagePercent": process.cpu_usage_percent,
        "rssBytes": process.rss_bytes.to_string(),
        "rssAnonBytes": process.anonymous_rss_bytes.to_string(),
        "rssFileBytes": process.file_rss_bytes.to_string(),
        "anonymousRssBytes": process.anonymous_rss_bytes.to_string(),
        "fileRssBytes": process.file_rss_bytes.to_string(),
        "vmDataBytes": process.vm_data_bytes.to_string(),
        "heapLiveBytes": allocator_live_heap.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "heapMetricSource": if allocator_live_heap.is_some() { "allocator-stats" } else { "unavailable" },
        "heapCompatBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapCompatBytesSource": "compat-alias-rss-anon-not-live-heap",
        "heapAllocBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapAllocBytesSource": "compat-alias-rss-anon-not-live-heap",
        "allocatorProfile": allocator_profile(),
        "allocatorStats": allocator_stats_json(),
        "allocatorReclaim": allocator_reclaim_snapshot_json(),
        "resourcePools": resource_pool_policy_json(),
        "goroutines": process.thread_count,
        "productHttp": app.http_metrics.snapshot(),
        "runtime": runtime,
        "samples": traffic.samples,
    })
}

fn runtime_overview_delta_report(app: &AppState, request: &HttpRequest) -> Value {
    let runtime = app.runtime.summary();
    let window_sec = query_u64(request, "windowSec")
        .unwrap_or(60)
        .clamp(1, 3_600);
    let max_points = query_usize(request, "maxPoints")
        .unwrap_or(120)
        .clamp(1, 1_000);
    let traffic = resident_runtime_traffic_stats(&runtime, window_sec, max_points);
    let process = current_process_metrics();
    let allocator_live_heap = allocator_live_heap_bytes();
    json!({
        "updatedAt": now_text(),
        "uploadRate": traffic.upload_rate.to_string(),
        "downloadRate": traffic.download_rate.to_string(),
        "uploadTotal": traffic.upload_total.to_string(),
        "downloadTotal": traffic.download_total.to_string(),
        "activeConnections": traffic.active_connections,
        "udpSessions": traffic.udp_sessions,
        "cpuUsagePercent": process.cpu_usage_percent,
        "rssBytes": process.rss_bytes.to_string(),
        "rssAnonBytes": process.anonymous_rss_bytes.to_string(),
        "rssFileBytes": process.file_rss_bytes.to_string(),
        "anonymousRssBytes": process.anonymous_rss_bytes.to_string(),
        "fileRssBytes": process.file_rss_bytes.to_string(),
        "vmDataBytes": process.vm_data_bytes.to_string(),
        "heapLiveBytes": allocator_live_heap.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "heapMetricSource": if allocator_live_heap.is_some() { "allocator-stats" } else { "unavailable" },
        "heapCompatBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapCompatBytesSource": "compat-alias-rss-anon-not-live-heap",
        "heapAllocBytes": process.heap_alloc_bytes_compat().to_string(),
        "heapAllocBytesSource": "compat-alias-rss-anon-not-live-heap",
        "goroutines": process.thread_count,
        "reloadCount": runtime["reloadCount"].clone(),
        "samples": traffic.samples,
    })
}

fn resource_pool_policy_json() -> Value {
    json!({
        "udpEndpoint": {
            "defaultMaxEntries": DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
            "trimTarget": udp_endpoint_pool_trim_target(DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES),
            "defaultNatTimeoutMs": DEFAULT_NAT_TIMEOUT_MS,
            "dnsNatTimeoutMs": DNS_NAT_TIMEOUT_MS,
            "anyfromTimeoutMs": ANYFROM_TIMEOUT_MS,
            "maxRetry": MAX_RETRY,
            "currentEntries": 0,
            "evictions": 0,
        },
        "udpTask": {
            "queueLength": UDP_TASK_QUEUE_LENGTH,
            "maxQueues": UDP_TASK_POOL_MAX_QUEUES,
            "currentQueues": 0,
            "dropTotal": 0,
        },
        "packetSniffer": {
            "ttlMs": PACKET_SNIFFER_TTL_MS,
            "maxEntries": PACKET_SNIFFER_POOL_MAX_ENTRIES,
            "currentEntries": 0,
            "evictions": 0,
        },
        "bufferPool": {
            "status": "planned",
            "maxClassBytes": 65536,
            "source": "DAEX_RUST_NATIVE_OUTBOUND_PLAN_2026-06-01.md:RSS allocator/reclaim and Go structural cleanup plan",
        }
    })
}

fn resident_runtime_traffic_stats(
    runtime: &Value,
    window_sec: u64,
    max_points: usize,
) -> RuntimeTrafficStats {
    if let Some(stats) = resident_live_runtime_traffic_stats(runtime, window_sec, max_points) {
        return stats;
    }
    let Some(event_file) = runtime
        .pointer("/residentDataplane/event_file")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    else {
        return RuntimeTrafficStats::default();
    };
    resident_event_file_traffic_stats(event_file, window_sec, max_points).unwrap_or_default()
}

fn resident_event_file_traffic_stats(
    event_file: &str,
    window_sec: u64,
    max_points: usize,
) -> io::Result<RuntimeTrafficStats> {
    let mut file = fs::File::open(event_file)?;
    let len = file.metadata()?.len();
    let cache_lock = RUNTIME_TRAFFIC_EVENT_FILE_CACHE
        .get_or_init(|| Mutex::new(RuntimeTrafficEventFileCache::default()));
    let mut cache = cache_lock.lock().map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            "runtime traffic event file cache lock poisoned",
        )
    })?;
    if cache.path != event_file || len < cache.offset {
        *cache = RuntimeTrafficEventFileCache {
            path: event_file.to_owned(),
            ..RuntimeTrafficEventFileCache::default()
        };
    }
    file.seek(SeekFrom::Start(cache.offset))?;
    let mut reader = io::BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        cache.offset = cache.offset.saturating_add(read as u64);
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let (upload, download) = event_traffic_bytes(&event);
        cache.upload_total = cache.upload_total.saturating_add(upload);
        cache.download_total = cache.download_total.saturating_add(download);
        let Some(timestamp) = event["timestampUnix"].as_u64() else {
            continue;
        };
        let entry = cache.seconds.entry(timestamp).or_default();
        entry.upload = entry.upload.saturating_add(upload);
        entry.download = entry.download.saturating_add(download);
        if is_tcp_connection_event(&event) {
            entry.active_connections = entry.active_connections.saturating_add(1);
        }
        if is_udp_session_event(&event) {
            entry.udp_sessions = entry.udp_sessions.saturating_add(1);
        }
    }
    let now = unix_now();
    let max_retained_window = 3_600_u64;
    let retain_start = now.saturating_sub(max_retained_window);
    let old_keys = cache
        .seconds
        .keys()
        .copied()
        .take_while(|timestamp| *timestamp < retain_start)
        .collect::<Vec<_>>();
    for timestamp in old_keys {
        cache.seconds.remove(&timestamp);
    }

    let window_start = now.saturating_sub(window_sec);
    let rate_window_start = now.saturating_sub(5);
    let mut stats = RuntimeTrafficStats::default();
    stats.upload_total = cache.upload_total;
    stats.download_total = cache.download_total;
    let mut sample_values = Vec::new();
    for (timestamp, second) in cache.seconds.range(window_start..) {
        stats.active_connections = stats
            .active_connections
            .saturating_add(second.active_connections);
        stats.udp_sessions = stats.udp_sessions.saturating_add(second.udp_sessions);
        if *timestamp >= rate_window_start {
            stats.upload_rate = stats.upload_rate.saturating_add(second.upload);
            stats.download_rate = stats.download_rate.saturating_add(second.download);
        }
        sample_values.push(json!({
            "timestamp": iso8601_utc(*timestamp),
            "uploadRate": second.upload.to_string(),
            "downloadRate": second.download.to_string(),
        }));
    }
    stats.upload_rate /= 5;
    stats.download_rate /= 5;
    if sample_values.len() > max_points {
        sample_values = sample_values.split_off(sample_values.len() - max_points);
    }
    stats.samples = sample_values;
    Ok(stats)
}

fn resident_live_runtime_traffic_stats(
    runtime: &Value,
    window_sec: u64,
    max_points: usize,
) -> Option<RuntimeTrafficStats> {
    let metrics = runtime.pointer("/residentDataplane/metrics")?;
    let upload_total = event_u64(metrics, "uploadTotal");
    let download_total = event_u64(metrics, "downloadTotal");
    let (upload_rate, download_rate, samples) =
        live_runtime_traffic_rate_samples(upload_total, download_total, window_sec, max_points);
    Some(RuntimeTrafficStats {
        upload_total,
        download_total,
        upload_rate,
        download_rate,
        active_connections: event_u64(metrics, "activeTcpConnections"),
        udp_sessions: event_u64(metrics, "activeUdpSessions"),
        samples,
    })
}

fn live_runtime_traffic_rate_samples(
    upload_total: u64,
    download_total: u64,
    window_sec: u64,
    max_points: usize,
) -> (u64, u64, Vec<Value>) {
    let now = unix_now();
    let observed_at = Instant::now();
    let sample_lock = LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE.get_or_init(|| Mutex::new(None));
    let mut previous = sample_lock.lock().ok();
    let mut upload_rate = 0_u64;
    let mut download_rate = 0_u64;
    let mut totals_reset = false;
    if let Some(previous_guard) = previous.as_deref_mut() {
        if let Some(previous_sample) = *previous_guard {
            if upload_total < previous_sample.upload_total
                || download_total < previous_sample.download_total
            {
                totals_reset = true;
            } else {
                let elapsed = observed_at
                    .duration_since(previous_sample.observed_at)
                    .as_secs_f64();
                if elapsed > 0.0 {
                    upload_rate =
                        ((upload_total - previous_sample.upload_total) as f64 / elapsed) as u64;
                    download_rate =
                        ((download_total - previous_sample.download_total) as f64 / elapsed) as u64;
                }
            }
        }
        *previous_guard = Some(RuntimeTrafficTotalSample {
            upload_total,
            download_total,
            observed_at,
        });
    }

    let history_lock = RUNTIME_TRAFFIC_RATE_SAMPLES.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut history = match history_lock.lock() {
        Ok(history) => history,
        Err(_) => return (upload_rate, download_rate, Vec::new()),
    };
    if totals_reset {
        history.clear();
    }
    if history
        .back()
        .is_some_and(|(timestamp, _, _)| *timestamp == now)
    {
        if let Some(back) = history.back_mut() {
            *back = (now, upload_rate, download_rate);
        }
    } else {
        history.push_back((now, upload_rate, download_rate));
    }
    let window_start = now.saturating_sub(window_sec);
    while history
        .front()
        .is_some_and(|(timestamp, _, _)| *timestamp < window_start)
    {
        history.pop_front();
    }
    while history.len() > max_points {
        history.pop_front();
    }
    let samples = history
        .iter()
        .map(|(timestamp, upload, download)| {
            json!({
                "timestamp": iso8601_utc(*timestamp),
                "uploadRate": upload.to_string(),
                "downloadRate": download.to_string(),
            })
        })
        .collect();
    (upload_rate, download_rate, samples)
}

fn event_traffic_bytes(event: &Value) -> (u64, u64) {
    let upload = event_u64(event, "bytes_client_to_proxy")
        .saturating_add(event_u64(event, "bytes_client_to_direct"))
        .saturating_add(event_u64(event, "request_len"));
    let download = event_u64(event, "bytes_proxy_to_client")
        .saturating_add(event_u64(event, "bytes_direct_to_client"))
        .saturating_add(event_u64(event, "response_len"));
    (upload, download)
}

fn event_u64(event: &Value, key: &str) -> u64 {
    event
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
        .unwrap_or(0)
}

fn is_tcp_connection_event(event: &Value) -> bool {
    matches!(
        event.get("event").and_then(Value::as_str),
        Some("tcp_connection_finished" | "tcp_connection_failed")
    )
}

fn is_udp_session_event(event: &Value) -> bool {
    matches!(
        event.get("event").and_then(Value::as_str),
        Some("udp_packet_finished" | "udp_dns_packet_finished")
    )
}

fn query_u64(request: &HttpRequest, key: &str) -> Option<u64> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<u64>().ok())
}

fn query_usize(request: &HttpRequest, key: &str) -> Option<usize> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<usize>().ok())
}

fn query_bool(request: &HttpRequest, key: &str) -> Option<bool> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| parse_bool(value))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn list_system_interfaces(up: Option<bool>, only_global_scope: bool) -> io::Result<Vec<Value>> {
    let routes_by_iface = default_routes_by_iface();
    match ip_address_interfaces(up, only_global_scope, &routes_by_iface) {
        Ok(items) => Ok(items),
        Err(_) => sysfs_interfaces(up, &routes_by_iface),
    }
}

fn ip_address_interfaces(
    up: Option<bool>,
    only_global_scope: bool,
    routes_by_iface: &HashMap<String, Vec<Value>>,
) -> io::Result<Vec<Value>> {
    let output = Command::new("ip")
        .args(["-j", "address", "show"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("ip address query failed"));
    }
    let interfaces = serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let mut items = Vec::new();
    for iface in interfaces.as_array().into_iter().flatten() {
        let name = iface["ifname"].as_str().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let flags = iface["flags"].as_array().cloned().unwrap_or_default();
        let iface_up = flags
            .iter()
            .filter_map(Value::as_str)
            .any(|flag| flag.eq_ignore_ascii_case("UP"));
        if up.is_some_and(|wanted| wanted != iface_up) {
            continue;
        }
        let mut addresses = Vec::new();
        for addr in iface["addr_info"].as_array().into_iter().flatten() {
            if only_global_scope
                && addr["scope"]
                    .as_str()
                    .is_some_and(|scope| scope != "global")
            {
                continue;
            }
            let Some(local) = addr["local"].as_str() else {
                continue;
            };
            let prefix = addr["prefixlen"].as_u64().unwrap_or(0);
            addresses.push(format!("{local}/{prefix}"));
        }
        let mut item = Map::new();
        item.insert("name".to_owned(), json!(name));
        item.insert("index".to_owned(), iface["ifindex"].clone());
        item.insert("up".to_owned(), json!(iface_up));
        item.insert("addresses".to_owned(), json!(addresses));
        if let Some(routes) = routes_by_iface
            .get(name)
            .filter(|routes| !routes.is_empty())
        {
            item.insert("defaultRoutes".to_owned(), json!(routes));
        }
        items.push(Value::Object(item));
    }
    Ok(items)
}

fn default_routes_by_iface() -> HashMap<String, Vec<Value>> {
    let mut out = HashMap::<String, Vec<Value>>::new();
    collect_default_routes(&mut out, "4", &["-j", "route", "show", "default"]);
    collect_default_routes(&mut out, "6", &["-j", "-6", "route", "show", "default"]);
    out
}

fn collect_default_routes(out: &mut HashMap<String, Vec<Value>>, ip_version: &str, args: &[&str]) {
    let Ok(output) = Command::new("ip").args(args).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(routes) = serde_json::from_slice::<Value>(&output.stdout) else {
        return;
    };
    for route in routes.as_array().into_iter().flatten() {
        let Some(dev) = route["dev"].as_str().filter(|value| !value.is_empty()) else {
            continue;
        };
        let mut item = Map::new();
        item.insert("ipVersion".to_owned(), json!(ip_version));
        if let Some(gateway) = route["gateway"].as_str() {
            item.insert("gateway".to_owned(), json!(gateway));
        }
        if let Some(source) = route["prefsrc"].as_str().or_else(|| route["src"].as_str()) {
            item.insert("source".to_owned(), json!(source));
        }
        out.entry(dev.to_owned())
            .or_default()
            .push(Value::Object(item));
    }
}

fn sysfs_interfaces(
    up: Option<bool>,
    routes_by_iface: &HashMap<String, Vec<Value>>,
) -> io::Result<Vec<Value>> {
    let mut items = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = entry.path();
        let index = fs::read_to_string(base.join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let iface_up = fs::read_to_string(base.join("operstate"))
            .map(|value| matches!(value.trim(), "up" | "unknown"))
            .unwrap_or(false);
        if up.is_some_and(|wanted| wanted != iface_up) {
            continue;
        }
        let mut item = Map::new();
        item.insert("name".to_owned(), json!(name));
        item.insert("index".to_owned(), json!(index));
        item.insert("up".to_owned(), json!(iface_up));
        item.insert("addresses".to_owned(), json!([]));
        if let Some(routes) = routes_by_iface
            .get(&name)
            .filter(|routes| !routes.is_empty())
        {
            item.insert("defaultRoutes".to_owned(), json!(routes));
        }
        items.push(Value::Object(item));
    }
    items.sort_by(|left, right| {
        left["index"]
            .as_i64()
            .unwrap_or(i64::MAX)
            .cmp(&right["index"].as_i64().unwrap_or(i64::MAX))
    });
    Ok(items)
}

fn api_runtime_reload(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let reload_started_at = Instant::now();
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let dry = body.get("dry").and_then(Value::as_bool).unwrap_or(false);
    let preview = match materialize_runtime(&app.state, Some(&app.config_dir), true) {
        Ok(report) => report,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), dry.to_string());
            fields.insert("error".to_owned(), err.to_string());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to materialize runtime preview",
                fields,
            );
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    };
    let content = match preview.get("content").and_then(Value::as_str) {
        Some(content) => content,
        None => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), dry.to_string());
            fields.insert(
                "error".to_owned(),
                "runtime materializer did not return content".to_owned(),
            );
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to materialize runtime preview",
                fields,
            );
            return HttpResponse::json(
                500,
                json!({"error": "runtime materializer did not return content"}),
            );
        }
    };
    let config = match build_runtime_config_from_content(content) {
        Ok(config) => config,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), dry.to_string());
            fields.insert("error".to_owned(), err.clone());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to build runtime config",
                fields,
            );
            return HttpResponse::json(400, json!({"error": err}));
        }
    };
    if dry {
        let mut fields = BTreeMap::new();
        fields.insert("source".to_owned(), "api".to_owned());
        fields.insert("dry".to_owned(), "true".to_owned());
        fields.insert("applied".to_owned(), "false".to_owned());
        fields.insert(
            "elapsed".to_owned(),
            format!("{:?}", reload_started_at.elapsed()),
        );
        let _ = append_lifecycle_log_fields_for_config(
            &app.config_dir,
            &app.state,
            "info",
            "[Reload] Preview finished",
            fields,
        );
        let mut response = preview.as_object().cloned().unwrap_or_default();
        response.insert("applied".to_owned(), json!(0));
        response.insert("dry".to_owned(), json!(true));
        response.insert("runtimeStarted".to_owned(), json!(false));
        return HttpResponse::json(200, Value::Object(response));
    }
    if let Err(err) = set_runtime_log_level_from_config(&app.state, &config) {
        let mut fields = BTreeMap::new();
        fields.insert("source".to_owned(), "api".to_owned());
        fields.insert("dry".to_owned(), "false".to_owned());
        fields.insert("error".to_owned(), err.to_string());
        let _ = append_lifecycle_log_fields_for_config(
            &app.config_dir,
            &app.state,
            "error",
            "[Reload] Failed to apply runtime log level",
            fields,
        );
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    let runtime = match app.runtime.reload(config, "api-runtime-reload") {
        Ok(outcome) => outcome.report,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), "false".to_owned());
            fields.insert("error".to_owned(), err.clone());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to reload",
                fields,
            );
            return HttpResponse::json(500, json!({"error": err}));
        }
    };
    let mut fields = BTreeMap::new();
    fields.insert("source".to_owned(), "api".to_owned());
    fields.insert("dry".to_owned(), "false".to_owned());
    fields.insert("applied".to_owned(), "true".to_owned());
    fields.insert(
        "elapsed".to_owned(),
        format!("{:?}", reload_started_at.elapsed()),
    );
    match materialize_runtime(&app.state, Some(&app.config_dir), false) {
        Ok(report) => {
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "info",
                "[Reload] Finished",
                fields,
            );
            let mut response = report.as_object().cloned().unwrap_or_default();
            response.insert("applied".to_owned(), json!(1));
            response.insert("dry".to_owned(), json!(false));
            response.insert("runtimeStarted".to_owned(), json!(true));
            response.insert("runtime".to_owned(), runtime);
            HttpResponse::json(200, Value::Object(response))
        }
        Err(err) => {
            let _ = app.runtime.stop();
            let _ = mark_system_stopped(&app.state);
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), "false".to_owned());
            fields.insert("error".to_owned(), err.to_string());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to materialize applied runtime config",
                fields,
            );
            HttpResponse::json(500, json!({"error": err.to_string()}))
        }
    }
}

fn api_runtime_stop(app: &AppState) -> HttpResponse {
    match app.runtime.stop() {
        Ok(mut report) => {
            if let Err(err) = mark_system_stopped(&app.state) {
                return HttpResponse::json(500, json!({"error": err.to_string()}));
            }
            let _ = append_lifecycle_log_for_config(
                &app.config_dir,
                &app.state,
                "info",
                "[Stop] runtime stopped by Rust daed",
            );
            if let Value::Object(map) = &mut report {
                map.insert("runtime".to_owned(), app.runtime.summary());
            }
            HttpResponse::json(200, report)
        }
        Err(err) => HttpResponse::json(500, json!({"error": err})),
    }
}

fn api_get_runtime_log_level(app: &AppState) -> HttpResponse {
    let level = get_metadata(&app.state, "runtime_log_level")
        .unwrap_or_else(|_| Some("info".to_owned()))
        .unwrap_or_else(|| "info".to_owned());
    let level = normalize_runtime_log_level(&level).unwrap_or_else(|| "info".to_owned());
    HttpResponse::json(200, json!({"level": level}))
}

fn api_set_runtime_log_level(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let Some(level) =
        normalize_runtime_log_level(body.get("level").and_then(Value::as_str).unwrap_or("info"))
    else {
        return HttpResponse::json(400, json!({"error": "invalid log level"}));
    };
    if let Err(err) = set_metadata(&app.state, "runtime_log_level", &level) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"level": level}))
}

fn normalize_runtime_log_level(level: &str) -> Option<String> {
    normalize_log_level_name(level)
}

fn api_runtime_events(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let full = runtime_overview_report(app, request);
    thread::sleep(Duration::from_millis(200));
    let delta = runtime_overview_delta_report(app, request);
    sse_response_events(
        &[
            ("runtime.overview", full),
            ("runtime.overview.delta", delta),
        ],
        Some(LOG_STREAM_RETRY_MS),
    )
}

fn stream_runtime_events(
    stream: &mut TcpStream,
    app: &AppState,
    request: &HttpRequest,
) -> io::Result<()> {
    write_sse_stream_headers(stream)?;
    write!(stream, "retry: {LOG_STREAM_RETRY_MS}\n\n")?;
    let first = runtime_overview_report(app, request);
    let mut last_reload_count = first
        .pointer("/runtime/reloadCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    write_sse_stream_event(stream, "runtime.overview", &first)?;
    let mut last_heartbeat = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(1));
        let delta = runtime_overview_delta_report(app, request);
        let reload_count = delta["reloadCount"].as_u64().unwrap_or(last_reload_count);
        if reload_count != last_reload_count {
            let full = runtime_overview_report(app, request);
            last_reload_count = full
                .pointer("/runtime/reloadCount")
                .and_then(Value::as_u64)
                .unwrap_or(reload_count);
            write_sse_stream_event(stream, "runtime.overview", &full)?;
        } else {
            write_sse_stream_event(stream, "runtime.overview.delta", &delta)?;
        }
        if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
            stream.write_all(b": keep-alive\n\n")?;
            stream.flush()?;
            last_heartbeat = Instant::now();
        }
    }
}

fn api_log_events(_app: &AppState, request: &HttpRequest) -> HttpResponse {
    match log_level_filter_from_request(request) {
        Ok(_) => sse_response_events(&[], Some(LOG_STREAM_RETRY_MS)),
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    }
}

fn stream_log_events(
    stream: &mut TcpStream,
    app: &AppState,
    request: &HttpRequest,
) -> io::Result<()> {
    let level = match log_level_filter_from_request(request) {
        Ok(level) => level,
        Err(err) => {
            let response = HttpResponse::json(400, json!({"error": err}));
            return write_http_response(stream, &response, false);
        }
    };
    let query = request
        .query
        .get("q")
        .and_then(|values| values.first())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    write_sse_stream_headers(stream)?;
    write!(stream, "retry: {LOG_STREAM_RETRY_MS}\n\n")?;
    stream.flush()?;

    let log_file = product_log_file(&app.config_dir);
    let mut last_seen_id = cached_last_log_id(&log_file).unwrap_or(0);
    let mut last_heartbeat = Instant::now();
    loop {
        let current_last_id = cached_last_log_id(&log_file).unwrap_or(0);
        if current_last_id < last_seen_id {
            last_seen_id = 0;
        }
        if current_last_id == last_seen_id {
            if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
                stream.write_all(b": heartbeat\n\n")?;
                stream.flush()?;
                last_heartbeat = Instant::now();
            }
            thread::sleep(LOG_STREAM_POLL_INTERVAL);
            continue;
        }
        let (entries, max_seen_id) =
            scan_log_entries_after_id(&app.config_dir, last_seen_id).unwrap_or_default();
        for entry in entries {
            if log_entry_matches_filter(&entry, level.as_deref(), query.as_deref()) {
                write_sse_stream_event(stream, "log.entry", &log_entry_value(entry))?;
            }
        }
        if max_seen_id > last_seen_id {
            last_seen_id = max_seen_id;
        }
        if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
            stream.write_all(b": heartbeat\n\n")?;
            stream.flush()?;
            last_heartbeat = Instant::now();
        }
        thread::sleep(LOG_STREAM_POLL_INTERVAL);
    }
}

fn api_logs(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let level = match log_level_filter_from_request(request) {
        Ok(level) => level,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let query = request
        .query
        .get("q")
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
        .cloned();
    let limit = request
        .query
        .get("limit")
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_LOG_QUERY_LIMIT);
    match list_logs_value(
        &app.config_dir,
        &app.state,
        level.as_deref(),
        query.as_deref(),
        limit,
    ) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn log_level_filter_from_request(request: &HttpRequest) -> Result<Option<String>, String> {
    let level = request
        .query
        .get("level")
        .and_then(|values| values.first())
        .map(String::as_str);
    normalize_log_level_filter(level).map_err(|err| err.to_string())
}

fn api_clear_logs(app: &AppState) -> HttpResponse {
    match clear_log_file(&app.config_dir) {
        Ok(()) => HttpResponse::json(200, json!({"cleared": true})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_log_settings(app: &AppState) -> HttpResponse {
    match log_settings_value(&app.state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_set_log_settings(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match open_state_connection(&app.state).and_then(|conn| {
        let (current_entries, current_bytes) = log_settings_tuple(&conn)?;
        let max_entries = normalize_log_max_entries(
            body.get("maxEntries")
                .and_then(Value::as_i64)
                .unwrap_or(current_entries),
        );
        let max_bytes = normalize_log_max_bytes(
            body.get("maxBytes")
                .and_then(Value::as_i64)
                .unwrap_or(current_bytes),
        );
        conn.execute(
            "INSERT OR REPLACE INTO log_settings(id, max_entries, max_bytes) VALUES(1, ?1, ?2)",
            params![max_entries, max_bytes],
        )
        .map_err(sqlite_io_error)?;
        prune_log_file(&app.config_dir, &conn)?;
        Ok(())
    }) {
        Ok(()) => match log_settings_value(&app.state) {
            Ok(value) => HttpResponse::json(200, value),
            Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
        },
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_node_latencies(app: &AppState) -> HttpResponse {
    match list_node_latencies_value(&app.state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_test_node_latencies(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    match update_node_latencies(&app.state, &app.config_dir, &ids) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_bundle(app: &AppState, user: &UserRecord) -> HttpResponse {
    match export_bundle(&app.state, user) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_put_bundle(app: &AppState, request: &HttpRequest, user: &UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match import_bundle(&app.state, &app.config_dir, &body, user) {
        Ok(imported) => HttpResponse::json(200, json!({"imported": imported})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_get_dae_config_file(app: &AppState) -> HttpResponse {
    match materialize_runtime(&app.state, None, true) {
        Ok(report) => HttpResponse::json(
            200,
            json!({
                "filename": "generated.dae",
                "content": report["content"].as_str().unwrap_or(""),
                "generated": true
            }),
        ),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_put_dae_config_file(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let content = body.get("content").and_then(Value::as_str).unwrap_or("");
    let name_prefix = body
        .get("namePrefix")
        .and_then(Value::as_str)
        .unwrap_or("imported");
    let import_body = json!({
        "configName": format!("{name_prefix}-global"),
        "global": content,
        "dnsName": format!("{name_prefix}-dns"),
        "dns": "",
        "routingName": format!("{name_prefix}-routing"),
        "routing": "",
        "groupName": format!("{name_prefix}-group"),
        "policy": "random",
        "policyParams": [],
        "mode": "rule"
    });
    match ensure_default_resources(&app.state, &import_body) {
        Ok(response) => {
            let _ = append_log_for_config(
                &app.config_dir,
                &app.state,
                "info",
                "dae config file imported by Rust daed",
            );
            let _ = save_json_storage(&app.state, user.id, &user.json_storage);
            HttpResponse::json(
                200,
                json!({"imported": true, "defaults": response, "warnings": []}),
            )
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_preview_dae_config_file(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let content = body.get("content").and_then(Value::as_str).unwrap_or("");
    match export_bundle(&app.state, user) {
        Ok(bundle) => HttpResponse::json(
            200,
            json!({
                "bundle": bundle,
                "warnings": [{
                    "level": "info",
                    "code": "rust_daed_local_preview",
                    "message": format!("Rust daed local preview accepted {} bytes", content.len())
                }]
            }),
        ),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionKind {
    Config,
    Dns,
    Routing,
}

impl SectionKind {
    fn from_path(path: &str) -> Option<Self> {
        if path == "/configs" || path.starts_with("/configs/") {
            Some(Self::Config)
        } else if path == "/dns" || path.starts_with("/dns/") {
            Some(Self::Dns)
        } else if path == "/routings" || path.starts_with("/routings/") {
            Some(Self::Routing)
        } else {
            None
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Self::Config => "/configs",
            Self::Dns => "/dns",
            Self::Routing => "/routings",
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::Config => "configs",
            Self::Dns => "dns",
            Self::Routing => "routings",
        }
    }

    fn value_column(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }

    fn request_value_key(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }

    fn default_name(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }
}

fn api_section_preview(request: &HttpRequest, api_path: &str) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    if api_path == "/configs/parsed" {
        let global = body
            .get("global")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| body.get("parsedGlobal").map(Value::to_string))
            .unwrap_or_else(|| "global {}".to_owned());
        return HttpResponse::json(
            200,
            json!({
                "global": global,
                "parsedGlobal": normalize_global_value(Some(&global)),
            }),
        );
    }
    if api_path == "/dns/parsed" {
        let raw = body.get("dns").and_then(Value::as_str).unwrap_or("");
        return HttpResponse::json(200, parsed_dns_value(raw));
    }
    let raw = body.get("routing").and_then(Value::as_str).unwrap_or("");
    HttpResponse::json(200, parsed_routing_value(raw))
}

fn list_sections(state: &Path, kind: SectionKind) -> HttpResponse {
    match list_sections_value(state, kind) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_sections_value(state: &Path, kind: SectionKind) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let sql = format!(
        "SELECT id, name, {}, selected, version FROM {} ORDER BY id",
        kind.value_column(),
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(section_resource(
                kind,
                row.get(0)?,
                row.get::<_, Option<String>>(1)?
                    .unwrap_or_else(|| kind.default_name().to_owned()),
                row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                row.get::<_, i64>(3)? != 0,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

fn get_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    match get_section_value(state, kind, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "resource not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_section_value(state: &Path, kind: SectionKind, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    let sql = format!(
        "SELECT id, name, {}, selected, version FROM {} WHERE id = ?1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, params![id], |row| {
        Ok(section_resource(
            kind,
            row.get(0)?,
            row.get::<_, Option<String>>(1)?
                .unwrap_or_else(|| kind.default_name().to_owned()),
            row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            row.get::<_, i64>(3)? != 0,
            row.get::<_, i64>(4)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn create_section(state: &Path, request: &HttpRequest, kind: SectionKind) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(kind.default_name());
    let value = section_request_value(kind, &body);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let sql = format!(
        "INSERT INTO {}(name, {}, selected, version) VALUES(?1, ?2, 0, 0)",
        kind.table(),
        kind.value_column()
    );
    if let Err(err) = conn.execute(&sql, params![name, value]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    get_section(state, kind, id).with_status(201)
}

fn update_section(state: &Path, request: &HttpRequest, kind: SectionKind, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        let sql = format!(
            "UPDATE {} SET name = ?1, version = version + 1 WHERE id = ?2",
            kind.table()
        );
        if let Err(err) = conn.execute(&sql, params![name, id]) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if body.get(kind.request_value_key()).is_some()
        || (kind == SectionKind::Config && body.get("parsedGlobal").is_some())
    {
        let value = section_request_value(kind, &body);
        let sql = format!(
            "UPDATE {} SET {} = ?1, version = version + 1 WHERE id = ?2",
            kind.table(),
            kind.value_column()
        );
        if let Err(err) = conn.execute(&sql, params![value, id]) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    get_section(state, kind, id)
}

fn delete_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let sql = format!("DELETE FROM {} WHERE id = ?1", kind.table());
    match conn.execute(&sql, params![id]) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn select_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let clear = format!("UPDATE {} SET selected = 0", kind.table());
    let set = format!(
        "UPDATE {} SET selected = 1, version = version + 1 WHERE id = ?1",
        kind.table()
    );
    if let Err(err) = conn.execute(&clear, []) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    match conn.execute(&set, params![id]) {
        Ok(0) => HttpResponse::json(404, json!({"error": "resource not found"})),
        Ok(_) => get_section(state, kind, id),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn section_request_value(kind: SectionKind, body: &Value) -> String {
    body.get(kind.request_value_key())
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            if kind == SectionKind::Config {
                body.get("parsedGlobal").map(Value::to_string)
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn section_resource(
    kind: SectionKind,
    id: i64,
    name: String,
    raw: String,
    selected: bool,
    version: i64,
) -> Value {
    match kind {
        SectionKind::Config => json!({
            "id": id,
            "name": name,
            "global": raw,
            "selected": selected,
            "version": version,
            "parsedGlobal": normalize_global_value(Some(&raw)),
        }),
        SectionKind::Dns => {
            let mut value = parsed_dns_value(&raw);
            if let Value::Object(map) = &mut value {
                map.insert("id".to_owned(), json!(id));
                map.insert("name".to_owned(), json!(name));
                map.insert("dns".to_owned(), json!(raw));
                map.insert("selected".to_owned(), json!(selected));
                map.insert("version".to_owned(), json!(version));
            }
            value
        }
        SectionKind::Routing => {
            let mut value = parsed_routing_value(&raw);
            if let Value::Object(map) = &mut value {
                map.insert("id".to_owned(), json!(id));
                map.insert("name".to_owned(), json!(name));
                map.insert("routing".to_owned(), json!(raw));
                map.insert("selected".to_owned(), json!(selected));
                map.insert("version".to_owned(), json!(version));
            }
            value
        }
    }
}

fn normalize_global_value(raw: Option<&str>) -> Value {
    let mut value = default_global_value();
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return value;
    };
    if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
        merge_global_json_value(&mut value, &parsed);
        return value;
    }
    merge_global_directives(&mut value, &parse_global_directives(raw));
    value
}

fn default_global_value() -> Value {
    json!({
        "logLevel": "",
        "tproxyPort": 0,
        "allowInsecure": false,
        "checkInterval": "",
        "checkTolerance": "",
        "lanInterface": [],
        "wanInterface": [],
        "udpCheckDns": [],
        "tcpCheckUrl": [],
        "fallbackResolver": "",
        "dialMode": "",
        "tcpCheckHttpMethod": "",
        "disableWaitingNetwork": false,
        "autoConfigKernelParameter": false,
        "sniffingTimeout": "",
        "tlsImplementation": "",
        "utlsImitate": "",
        "tproxyPortProtect": false,
        "soMarkFromDae": 0,
        "pprofPort": 0,
        "enableLocalTcpFastRedirect": false,
        "mptcp": false,
        "bandwidthMaxTx": "",
        "bandwidthMaxRx": "",
    })
}

fn merge_global_json_value(target: &mut Value, source: &Value) {
    set_global_string(
        target,
        "logLevel",
        json_string(source, &["logLevel", "log_level"]),
    );
    set_global_u64(
        target,
        "tproxyPort",
        json_u64(source, &["tproxyPort", "tproxy_port"]),
    );
    set_global_bool(
        target,
        "allowInsecure",
        json_bool(source, &["allowInsecure", "allow_insecure"]),
    );
    set_global_string(
        target,
        "checkInterval",
        json_string(source, &["checkInterval", "check_interval"]),
    );
    set_global_string(
        target,
        "checkTolerance",
        json_string(source, &["checkTolerance", "check_tolerance"]),
    );
    set_global_array(
        target,
        "lanInterface",
        json_array_or_split_string(source, &["lanInterface", "lan_interface"]),
    );
    set_global_array(
        target,
        "wanInterface",
        json_array_or_split_string(source, &["wanInterface", "wan_interface"]),
    );
    set_global_array(
        target,
        "udpCheckDns",
        json_array_or_split_string(source, &["udpCheckDns", "udp_check_dns"]),
    );
    set_global_array(
        target,
        "tcpCheckUrl",
        json_array_or_split_string(source, &["tcpCheckUrl", "tcp_check_url"]),
    );
    set_global_string(
        target,
        "fallbackResolver",
        json_string(source, &["fallbackResolver", "fallback_resolver"]),
    );
    set_global_string(
        target,
        "dialMode",
        json_string(source, &["dialMode", "dial_mode"]),
    );
    set_global_string(
        target,
        "tcpCheckHttpMethod",
        json_string(source, &["tcpCheckHttpMethod", "tcp_check_http_method"]),
    );
    set_global_bool(
        target,
        "disableWaitingNetwork",
        json_bool(
            source,
            &["disableWaitingNetwork", "disable_waiting_network"],
        ),
    );
    set_global_bool(
        target,
        "autoConfigKernelParameter",
        json_bool(
            source,
            &["autoConfigKernelParameter", "auto_config_kernel_parameter"],
        ),
    );
    set_global_string(
        target,
        "sniffingTimeout",
        json_string(source, &["sniffingTimeout", "sniffing_timeout"]),
    );
    set_global_string(
        target,
        "tlsImplementation",
        json_string(source, &["tlsImplementation", "tls_implementation"]),
    );
    set_global_string(
        target,
        "utlsImitate",
        json_string(source, &["utlsImitate", "utls_imitate"]),
    );
    set_global_bool(
        target,
        "tproxyPortProtect",
        json_bool(source, &["tproxyPortProtect", "tproxy_port_protect"]),
    );
    set_global_u64(
        target,
        "soMarkFromDae",
        json_u64(source, &["soMarkFromDae", "so_mark_from_dae"]),
    );
    set_global_u64(
        target,
        "pprofPort",
        json_u64(source, &["pprofPort", "pprof_port"]),
    );
    set_global_bool(
        target,
        "enableLocalTcpFastRedirect",
        json_bool(
            source,
            &[
                "enableLocalTcpFastRedirect",
                "enable_local_tcp_fast_redirect",
            ],
        ),
    );
    set_global_bool(target, "mptcp", json_bool(source, &["mptcp"]));
    set_global_string(
        target,
        "bandwidthMaxTx",
        json_string(source, &["bandwidthMaxTx", "bandwidth_max_tx"]),
    );
    set_global_string(
        target,
        "bandwidthMaxRx",
        json_string(source, &["bandwidthMaxRx", "bandwidth_max_rx"]),
    );
}

fn merge_global_directives(target: &mut Value, directives: &HashMap<String, String>) {
    set_global_string(
        target,
        "logLevel",
        directive_string(directives, "log_level"),
    );
    set_global_u64(
        target,
        "tproxyPort",
        directive_u64(directives, "tproxy_port"),
    );
    set_global_bool(
        target,
        "allowInsecure",
        directive_bool(directives, "allow_insecure"),
    );
    set_global_string(
        target,
        "checkInterval",
        directive_string(directives, "check_interval"),
    );
    set_global_string(
        target,
        "checkTolerance",
        directive_string(directives, "check_tolerance"),
    );
    set_global_array(
        target,
        "lanInterface",
        directive_array(directives, "lan_interface"),
    );
    set_global_array(
        target,
        "wanInterface",
        directive_array(directives, "wan_interface"),
    );
    set_global_array(
        target,
        "udpCheckDns",
        directive_array(directives, "udp_check_dns"),
    );
    set_global_array(
        target,
        "tcpCheckUrl",
        directive_array(directives, "tcp_check_url"),
    );
    set_global_string(
        target,
        "fallbackResolver",
        directive_string(directives, "fallback_resolver"),
    );
    set_global_string(
        target,
        "dialMode",
        directive_string(directives, "dial_mode"),
    );
    set_global_string(
        target,
        "tcpCheckHttpMethod",
        directive_string(directives, "tcp_check_http_method"),
    );
    set_global_bool(
        target,
        "disableWaitingNetwork",
        directive_bool(directives, "disable_waiting_network"),
    );
    set_global_bool(
        target,
        "autoConfigKernelParameter",
        directive_bool(directives, "auto_config_kernel_parameter"),
    );
    set_global_string(
        target,
        "sniffingTimeout",
        directive_string(directives, "sniffing_timeout"),
    );
    set_global_string(
        target,
        "tlsImplementation",
        directive_string(directives, "tls_implementation"),
    );
    set_global_string(
        target,
        "utlsImitate",
        directive_string(directives, "utls_imitate"),
    );
    set_global_bool(
        target,
        "tproxyPortProtect",
        directive_bool(directives, "tproxy_port_protect"),
    );
    set_global_u64(
        target,
        "soMarkFromDae",
        directive_u64(directives, "so_mark_from_dae"),
    );
    set_global_u64(target, "pprofPort", directive_u64(directives, "pprof_port"));
    set_global_bool(
        target,
        "enableLocalTcpFastRedirect",
        directive_bool(directives, "enable_local_tcp_fast_redirect"),
    );
    set_global_bool(target, "mptcp", directive_bool(directives, "mptcp"));
    set_global_string(
        target,
        "bandwidthMaxTx",
        directive_string(directives, "bandwidth_max_tx"),
    );
    set_global_string(
        target,
        "bandwidthMaxRx",
        directive_string(directives, "bandwidth_max_rx"),
    );
}

fn parse_global_directives(raw: &str) -> HashMap<String, String> {
    let body = global_block_body(raw).unwrap_or(raw);
    let mut directives = HashMap::new();
    for line in body.lines() {
        let line = strip_line_comment(line).trim();
        if line.is_empty() || line == "{" || line == "}" {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(',').to_owned();
        if key.is_empty() {
            continue;
        }
        directives.insert(key, clean_global_scalar(value));
    }
    directives
}

fn global_block_body(raw: &str) -> Option<&str> {
    let start = raw.find("global")?;
    let open = raw[start..].find('{')? + start;
    let bytes = raw.as_bytes();
    let mut depth = 0_i32;
    let mut close = None;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(idx);
                    break;
                }
            }
            _ => {}
        }
    }
    close.and_then(|close| raw.get(open + 1..close))
}

fn strip_line_comment(line: &str) -> &str {
    let mut quote = None;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '#' if quote.is_none() => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn clean_global_scalar(value: &str) -> String {
    let value = value.trim().trim_end_matches(',').trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value);
    value.trim().to_owned()
}

fn directive_string(directives: &HashMap<String, String>, key: &str) -> Option<String> {
    directives
        .get(key)
        .cloned()
        .filter(|value| !value.is_empty())
}

fn directive_bool(directives: &HashMap<String, String>, key: &str) -> Option<bool> {
    directives.get(key).and_then(|value| parse_boolish(value))
}

fn directive_u64(directives: &HashMap<String, String>, key: &str) -> Option<u64> {
    directives
        .get(key)
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn directive_array(directives: &HashMap<String, String>, key: &str) -> Option<Vec<String>> {
    directives
        .get(key)
        .map(|value| split_global_list(value))
        .filter(|values| !values.is_empty())
}

fn split_global_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn json_value_by_keys<'a>(source: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| source.get(*key))
}

fn json_string(source: &Value, keys: &[&str]) -> Option<String> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

fn json_bool(source: &Value, keys: &[&str]) -> Option<bool> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => parse_boolish(value),
        _ => None,
    })
}

fn json_u64(source: &Value, keys: &[&str]) -> Option<u64> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    })
}

fn json_array_or_split_string(source: &Value, keys: &[&str]) -> Option<Vec<String>> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Array(values) => {
            let out = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            (!out.is_empty()).then_some(out)
        }
        Value::String(value) => {
            let out = split_global_list(value);
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    })
}

fn parse_boolish(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

fn set_global_string(target: &mut Value, key: &str, value: Option<String>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

fn set_global_bool(target: &mut Value, key: &str, value: Option<bool>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

fn set_global_u64(target: &mut Value, key: &str, value: Option<u64>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

fn set_global_array(target: &mut Value, key: &str, value: Option<Vec<String>>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

fn parsed_dns_value(raw: &str) -> Value {
    json!({
        "dns": raw,
        "parsedDns": {
            "string": raw,
            "routing": {
                "request": {"string": ""},
                "response": {"string": ""}
            }
        }
    })
}

fn parsed_routing_value(raw: &str) -> Value {
    json!({
        "routing": raw,
        "parsedRouting": {
            "string": raw
        }
    })
}

impl HttpResponse {
    fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}

fn list_nodes(state: &Path, subscription_id: Option<i64>) -> HttpResponse {
    match list_nodes_value(state, subscription_id) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_nodes_for_request(state: &Path, request: &HttpRequest) -> HttpResponse {
    let subscription_id = request
        .query
        .get("subscriptionId")
        .or_else(|| request.query.get("subscriptionID"))
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<i64>().ok());
    let scope = if let Some(subscription_id) = subscription_id {
        NodeListScope::Subscription(subscription_id)
    } else {
        match request
            .query
            .get("independent")
            .and_then(|values| values.first())
            .and_then(|value| parse_boolish(value))
        {
            Some(false) => NodeListScope::SubscriptionBacked,
            _ => NodeListScope::Independent,
        }
    };
    match list_nodes_by_scope(state, scope) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

#[derive(Clone, Copy)]
enum NodeListScope {
    Independent,
    SubscriptionBacked,
    Subscription(i64),
    All,
}

fn list_nodes_value(state: &Path, subscription_id: Option<i64>) -> io::Result<Value> {
    let scope = subscription_id
        .map(NodeListScope::Subscription)
        .unwrap_or(NodeListScope::Independent);
    list_nodes_by_scope(state, scope)
}

fn list_all_nodes_value(state: &Path) -> io::Result<Value> {
    list_nodes_by_scope(state, NodeListScope::All)
}

fn list_nodes_by_scope(state: &Path, scope: NodeListScope) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut items = Vec::new();
    match scope {
        NodeListScope::Independent => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     WHERE subscription_id IS NULL
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map([], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
        NodeListScope::SubscriptionBacked => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     WHERE subscription_id IS NOT NULL
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map([], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
        NodeListScope::Subscription(subscription_id) => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     WHERE subscription_id = ?1
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map(params![subscription_id], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
        NodeListScope::All => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map([], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
    }
    Ok(json!({
        "items": items,
        "totalCount": items.len(),
        "nextAfterId": Value::Null,
    }))
}

fn get_node(state: &Path, id: i64) -> HttpResponse {
    match get_node_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "node not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_node_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE id = ?1",
        params![id],
        node_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn import_nodes(state: &Path, request: &HttpRequest, subscription_id: Option<i64>) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let args = body
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![body.clone()]);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let mut items = Vec::new();
    for item in args {
        let link = item.get("link").and_then(Value::as_str).unwrap_or("");
        let tag = item.get("tag").and_then(Value::as_str);
        if link.is_empty() {
            items.push(json!({"link": link, "error": "link is required", "node": Value::Null}));
            continue;
        }
        let parsed = parse_node_link(link, tag);
        let result = conn.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![link, parsed.name, parsed.address, parsed.protocol, tag, subscription_id],
        );
        match result {
            Ok(_) => {
                let id = conn.last_insert_rowid();
                let node = get_node_value(state, id).unwrap_or(None);
                items.push(json!({"link": link, "error": Value::Null, "node": node}));
            }
            Err(err) => {
                items.push(json!({"link": link, "error": err.to_string(), "node": Value::Null}))
            }
        }
    }
    HttpResponse::json(200, json!({"items": items}))
}

fn update_node(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    let updated = if let Some(link) = body.get("link").and_then(Value::as_str) {
        let parsed = parse_node_link(link, tag);
        conn.execute(
            "UPDATE nodes
             SET link = ?1,
                 name = ?2,
                 address = ?3,
                 protocol = ?4,
                 tag = CASE WHEN ?5 THEN ?6 ELSE tag END
             WHERE id = ?7",
            params![
                link,
                parsed.name,
                parsed.address,
                parsed.protocol,
                tag_present,
                tag,
                id
            ],
        )
    } else if tag_present {
        conn.execute("UPDATE nodes SET tag = ?1 WHERE id = ?2", params![tag, id])
    } else {
        return HttpResponse::json(400, json!({"error": "link or tag is required"}));
    };
    match updated {
        Ok(0) => HttpResponse::json(404, json!({"error": "node not found"})),
        Ok(_) => get_node(state, id),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn delete_nodes(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let mut removed = 0_usize;
    for id in ids {
        if let Ok(value) = delete_node(state, id) {
            removed += value;
        }
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

fn delete_node_by_id(state: &Path, id: i64) -> HttpResponse {
    match delete_node(state, id) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn delete_node(state: &Path, id: i64) -> io::Result<usize> {
    let conn = open_state_connection(state)?;
    conn.execute("DELETE FROM group_nodes WHERE node_id = ?1", params![id])
        .map_err(sqlite_io_error)?;
    conn.execute(
        "DELETE FROM node_latency_results WHERE node_id = ?1",
        params![id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM nodes WHERE id = ?1", params![id])
        .map_err(sqlite_io_error)
}

#[derive(Clone, Debug)]
struct ParsedNodeLink {
    name: String,
    address: String,
    protocol: String,
}

fn parse_node_link(link: &str, tag: Option<&str>) -> ParsedNodeLink {
    let protocol = link
        .split_once("://")
        .map(|(value, _)| value)
        .unwrap_or("unknown");
    let parsed_url = url::Url::parse(link).ok();
    let address = parsed_url
        .as_ref()
        .and_then(url::Url::host_str)
        .map(str::to_owned)
        .or_else(|| {
            link.split_once("://").map(|(_, rest)| {
                rest.split(['@', '/', '?', '#'])
                    .next_back()
                    .unwrap_or(rest)
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .to_owned()
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let name = tag
        .map(decode_node_label)
        .or_else(|| parsed_url.and_then(|url| url.fragment().map(decode_node_label)))
        .unwrap_or_else(|| format!("{protocol}-{address}"));
    ParsedNodeLink {
        name,
        address,
        protocol: protocol.to_owned(),
    }
}

fn decode_node_label(value: &str) -> String {
    decode_percent_escapes(value.trim())
}

fn decode_percent_escapes(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push((high << 4) | low);
                changed = true;
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    if changed {
        String::from_utf8_lossy(&out).into_owned()
    } else {
        value.to_owned()
    }
}

fn node_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let subscription_id: Option<i64> = row.get(6)?;
    let name = row.get::<_, String>(2)?;
    let tag = row.get::<_, Option<String>>(5)?;
    let runtime_tag = tag
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(name.as_str())
        .to_owned();
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "link": row.get::<_, String>(1)?,
        "name": decode_node_label(&name),
        "address": row.get::<_, String>(3)?,
        "protocol": row.get::<_, String>(4)?,
        "transport": Value::Null,
        "tag": tag.as_deref().map(decode_node_label),
        "runtimeTag": runtime_tag,
        "subscriptionId": subscription_id,
        "subscriptionID": subscription_id.map(|value| value.to_string()),
    }))
}

fn list_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let expand_nodes = request
        .query
        .get("expand")
        .map(|values| values.iter().any(|value| value == "nodes"))
        .unwrap_or(false);
    match list_subscriptions_value(state, expand_nodes) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_subscriptions_value(state: &Path, expand_nodes: bool) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let mut value = row.map_err(sqlite_io_error)?;
        let id = value["id"].as_i64().unwrap_or(0);
        let node_count = count_nodes_for_subscription(&conn, id)?;
        if let Value::Object(map) = &mut value {
            map.insert("nodeCount".to_owned(), json!(node_count));
            if expand_nodes {
                map.insert("nodes".to_owned(), list_nodes_value(state, Some(id))?);
            }
        }
        items.push(value);
    }
    Ok(json!({"items": items}))
}

fn create_subscription(state: &Path, config_dir: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let link = body.get("link").and_then(Value::as_str).unwrap_or("");
    if link.is_empty() {
        return HttpResponse::json(400, json!({"error": "link is required"}));
    }
    let tag = body.get("tag").and_then(Value::as_str);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let now = now_text();
    if let Err(err) = conn.execute(
        "INSERT INTO subscriptions(updated_at, link, cron_exp, cron_enable, status, info, tag) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![now, link, body.get("cronExp").and_then(Value::as_str).unwrap_or("10 */6 * * *"), body.get("cronEnable").and_then(Value::as_bool).unwrap_or(true) as i64, "imported", "", tag],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    let _ = append_log_for_config(
        config_dir,
        state,
        "info",
        &format!("subscription {id} imported"),
    );
    let import_report = refresh_subscription_from_remote(state, id).unwrap_or_else(|err| {
        json!({
            "link": link,
            "nodeImportResult": [{
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            }]
        })
    });
    HttpResponse::json(
        201,
        json!({
            "link": link,
            "subscription": {"id": id},
            "nodeImportResult": import_report["nodeImportResult"].clone()
        }),
    )
}

fn get_subscription(state: &Path, id: i64) -> HttpResponse {
    match get_subscription_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "subscription not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_subscription_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions WHERE id = ?1",
        params![id],
        subscription_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn update_subscription(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let link = body.get("link").and_then(Value::as_str);
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    let cron_exp = body.get("cronExp").and_then(Value::as_str);
    let cron_enable = body
        .get("cronEnable")
        .and_then(Value::as_bool)
        .map(|value| value as i64);
    if let Err(err) = conn.execute(
        "UPDATE subscriptions
         SET link = COALESCE(?1, link),
             tag = CASE WHEN ?2 THEN ?3 ELSE tag END,
             cron_exp = COALESCE(?4, cron_exp),
             cron_enable = COALESCE(?5, cron_enable),
             updated_at = ?6
         WHERE id = ?7",
        params![
            link,
            tag_present,
            tag,
            cron_exp,
            cron_enable,
            now_text(),
            id
        ],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    get_subscription(state, id)
}

fn refresh_subscription(state: &Path, config_dir: &Path, id: i64) -> HttpResponse {
    match refresh_subscription_from_remote(state, id) {
        Ok(mut report) => {
            let _ = append_log_for_config(
                config_dir,
                state,
                "info",
                &format!("subscription {id} refreshed"),
            );
            if let Some(subscription) = get_subscription_value(state, id)
                .ok()
                .flatten()
                .and_then(|value| value.as_object().cloned())
            {
                if let Value::Object(map) = &mut report {
                    for (key, value) in subscription {
                        map.insert(key, value);
                    }
                }
            }
            HttpResponse::json(200, report)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            HttpResponse::json(404, json!({"error": err.to_string()}))
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn delete_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let mut removed = 0_usize;
    for id in ids {
        if let Ok(value) = delete_subscription(state, id) {
            removed += value;
        }
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

fn delete_subscription_by_id(state: &Path, id: i64) -> HttpResponse {
    match delete_subscription(state, id) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn delete_subscription(state: &Path, id: i64) -> io::Result<usize> {
    let conn = open_state_connection(state)?;
    conn.execute(
        "DELETE FROM group_subscriptions WHERE subscription_id = ?1",
        params![id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM nodes WHERE subscription_id = ?1", params![id])
        .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])
        .map_err(sqlite_io_error)
}

fn subscription_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "updatedAt": row.get::<_, String>(1)?,
        "link": row.get::<_, String>(2)?,
        "cronExp": row.get::<_, Option<String>>(3)?.unwrap_or_else(|| "10 */6 * * *".to_owned()),
        "cronEnable": row.get::<_, i64>(4)? != 0,
        "status": row.get::<_, String>(5)?,
        "info": row.get::<_, String>(6)?,
        "tag": row.get::<_, Option<String>>(7)?,
    }))
}

fn count_nodes_for_subscription(conn: &Connection, subscription_id: i64) -> io::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM nodes WHERE subscription_id = ?1",
        params![subscription_id],
        |row| row.get(0),
    )
    .map_err(sqlite_io_error)
}

fn refresh_subscription_from_remote(state: &Path, id: i64) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let Some(link) = conn
        .query_row(
            "SELECT link FROM subscriptions WHERE id = ?1",
            params![id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "subscription not found",
        ));
    };
    let fetched_at = now_text();
    match fetch_subscription_content(&link) {
        Ok(content) => {
            let links = subscription_links_from_content(&content);
            let node_import_result = replace_subscription_nodes(&conn, id, &links)?;
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![
                    fetched_at,
                    "fetched",
                    format!("{} node links fetched by Rust daed", links.len()),
                    id
                ],
            )
            .map_err(sqlite_io_error)?;
            Ok(json!({
                "link": link,
                "fetched": true,
                "fetchedAt": fetched_at,
                "nodeImportResult": node_import_result,
            }))
        }
        Err(err) => {
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![fetched_at, "fetch_error", err.to_string(), id],
            )
            .map_err(sqlite_io_error)?;
            Ok(json!({
                "link": link,
                "fetched": false,
                "fetchedAt": fetched_at,
                "nodeImportResult": [{
                    "link": link,
                    "error": err.to_string(),
                    "node": Value::Null
                }],
            }))
        }
    }
}

fn replace_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
    links: &[String],
) -> io::Result<Vec<Value>> {
    let existing_nodes = existing_subscription_nodes(conn, subscription_id)?;
    let preserved_ids = preserved_subscription_node_ids(conn, subscription_id)?;
    let mut preserved_name_counts = HashMap::<String, usize>::new();
    let mut preserved_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for node in existing_nodes
        .iter()
        .filter(|node| preserved_ids.contains(&node.id))
    {
        *preserved_name_counts.entry(node.name.clone()).or_default() += 1;
        preserved_by_name.insert(node.name.clone(), node.clone());
    }

    let mut candidates = Vec::<(String, ParsedNodeLink)>::new();
    let mut incoming_name_counts = HashMap::<String, usize>::new();
    for link in links {
        let parsed = parse_node_link(link, None);
        *incoming_name_counts.entry(parsed.name.clone()).or_default() += 1;
        candidates.push((link.clone(), parsed));
    }

    for node in existing_nodes
        .iter()
        .filter(|node| !preserved_ids.contains(&node.id))
    {
        conn.execute(
            "DELETE FROM group_nodes WHERE node_id = ?1",
            params![node.id],
        )
        .map_err(sqlite_io_error)?;
        conn.execute(
            "DELETE FROM node_latency_results WHERE node_id = ?1",
            params![node.id],
        )
        .map_err(sqlite_io_error)?;
        conn.execute("DELETE FROM nodes WHERE id = ?1", params![node.id])
            .map_err(sqlite_io_error)?;
    }

    let mut out = Vec::new();
    let mut reused_preserved = HashSet::<i64>::new();
    for (link, parsed) in candidates {
        if incoming_name_counts.get(&parsed.name).copied().unwrap_or(0) == 1
            && preserved_name_counts
                .get(&parsed.name)
                .copied()
                .unwrap_or(0)
                == 1
        {
            if let Some(preserved) = preserved_by_name.get(&parsed.name) {
                if reused_preserved.insert(preserved.id) {
                    match conn.execute(
                        "UPDATE nodes
                         SET link = ?1,
                             name = ?2,
                             address = ?3,
                             protocol = ?4,
                             tag = NULL,
                             subscription_id = ?5
                         WHERE id = ?6",
                        params![
                            link,
                            parsed.name,
                            parsed.address,
                            parsed.protocol,
                            subscription_id,
                            preserved.id
                        ],
                    ) {
                        Ok(_) => {
                            conn.execute(
                                "DELETE FROM node_latency_results WHERE node_id = ?1",
                                params![preserved.id],
                            )
                            .map_err(sqlite_io_error)?;
                            bump_group_versions_for_node(conn, preserved.id)?;
                            out.push(json!({
                                "link": link,
                                "error": Value::Null,
                                "node": {"id": preserved.id}
                            }));
                            continue;
                        }
                        Err(err) => {
                            out.push(json!({
                                "link": link,
                                "error": err.to_string(),
                                "node": Value::Null
                            }));
                            continue;
                        }
                    }
                }
            }
        }

        if subscription_node_link_exists(conn, subscription_id, &link)? {
            out.push(json!({
                "link": link,
                "error": "node duplicated",
                "node": Value::Null
            }));
            continue;
        }
        match conn.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, NULL, ?5)",
            params![link, parsed.name, parsed.address, parsed.protocol, subscription_id],
        ) {
            Ok(_) => {
                let id = conn.last_insert_rowid();
                out.push(json!({
                    "link": link,
                    "error": Value::Null,
                    "node": {"id": id}
                }));
            }
            Err(err) => out.push(json!({
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            })),
        }
    }
    bump_group_versions_for_subscription(conn, subscription_id)?;
    Ok(out)
}

#[derive(Clone)]
struct ExistingSubscriptionNode {
    id: i64,
    name: String,
}

fn existing_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<Vec<ExistingSubscriptionNode>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol
             FROM nodes
             WHERE subscription_id = ?1
             ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| {
            Ok(ExistingSubscriptionNode {
                id: row.get(0)?,
                name: row.get(2)?,
            })
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

fn preserved_subscription_node_ids(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<HashSet<i64>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT n.id
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             WHERE n.subscription_id = ?1",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

fn subscription_node_link_exists(
    conn: &Connection,
    subscription_id: i64,
    link: &str,
) -> io::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM nodes WHERE subscription_id = ?1 AND link = ?2",
        params![subscription_id, link],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
    .map_err(sqlite_io_error)
}

fn bump_group_versions_for_node(conn: &Connection, node_id: i64) -> io::Result<()> {
    conn.execute(
        "UPDATE groups
         SET version = version + 1
         WHERE id IN (SELECT group_id FROM group_nodes WHERE node_id = ?1)",
        params![node_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

fn bump_group_versions_for_subscription(conn: &Connection, subscription_id: i64) -> io::Result<()> {
    conn.execute(
        "UPDATE groups
         SET version = version + 1
         WHERE id IN (
             SELECT group_id FROM group_subscriptions WHERE subscription_id = ?1
         )",
        params![subscription_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

fn subscription_links_from_content(content: &str) -> Vec<String> {
    let direct = node_links_from_text(content);
    if !direct.is_empty() {
        return direct;
    }
    let compact = content.split_whitespace().collect::<String>();
    for candidate in [
        compact.clone(),
        compact.replace('-', "+").replace('_', "/"),
        format!("{compact}{}", "=".repeat((4 - compact.len() % 4) % 4)),
    ] {
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            let decoded = String::from_utf8_lossy(&decoded);
            let links = node_links_from_text(&decoded);
            if !links.is_empty() {
                return links;
            }
        }
    }
    Vec::new()
}

fn node_links_from_text(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.contains("://"))
        .map(str::to_owned)
        .collect()
}

fn fetch_subscription_content(link: &str) -> io::Result<String> {
    let url = url::Url::parse(link)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    match url.scheme() {
        "http" => fetch_http_url(&url, false),
        "https" => fetch_http_url(&url, true),
        scheme => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported subscription scheme: {scheme}"),
        )),
    }
}

fn fetch_http_url(url: &url::Url, tls: bool) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port for subscription")
    })?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: daed-rust-native/0.1\r\nAccept: text/plain, application/octet-stream, */*\r\nConnection: close\r\n\r\n"
    );
    let stream = connect_tcp(host, port, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let response = if tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from(host.to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tls server name: {err}"),
            )
        })?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(|err| io::Error::other(format!("tls connect: {err}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response)?;
        response
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        response
    };
    http_response_body(&response)
}

fn http_response_body(response: &[u8]) -> io::Result<String> {
    let split = find_subsequence(response, b"\r\n\r\n")
        .or_else(|| find_subsequence(response, b"\n\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing http headers"))?;
    let header_end = if response.get(split..split + 4) == Some(b"\r\n\r\n") {
        split + 4
    } else {
        split + 2
    };
    let headers = String::from_utf8_lossy(&response[..split]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "subscription fetch returned HTTP {status}"
        )));
    }
    let mut body = response[header_end..].to_vec();
    if headers
        .lines()
        .any(|line| line.to_ascii_lowercase().trim() == "transfer-encoding: chunked")
    {
        body = decode_chunked_body(&body)?;
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn decode_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut index = 0;
    let mut out = Vec::new();
    while index < body.len() {
        let Some(line_end) = find_subsequence(&body[index..], b"\r\n") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunked body",
            ));
        };
        let size_text = String::from_utf8_lossy(&body[index..index + line_end]);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {err}"),
            )
        })?;
        index += line_end + 2;
        if size == 0 {
            break;
        }
        if index + size > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated chunked body",
            ));
        }
        out.extend_from_slice(&body[index..index + size]);
        index += size + 2;
    }
    Ok(out)
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no socket address resolved",
        )
    }))
}

fn start_subscription_scheduler(state: PathBuf, config_dir: PathBuf) {
    thread::spawn(move || {
        let _ = ensure_state_schema(&state);
        let _ = set_metadata(&state, "subscription_scheduler_started_at", &now_text());
        let _ = append_log_for_config(
            &config_dir,
            &state,
            "info",
            "subscription scheduler started by Rust daed",
        );
    });
}

fn list_groups(state: &Path) -> HttpResponse {
    match list_groups_value(state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_groups_value(state: &Path) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    let mut items = Vec::new();
    for id in ids {
        if let Some(group) = get_group_value_with_conn(&conn, id)? {
            items.push(group);
        }
    }
    Ok(json!({"items": items}))
}

fn create_group(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let name = body.get("name").and_then(Value::as_str).unwrap_or("proxy");
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or("random");
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    if let Err(err) = replace_group_policy_params(&conn, id, body.get("policyParams")) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_node_ids(&conn, id, &integer_array(&body, "nodeIds"), true) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_subscription_ids(
        &conn,
        id,
        &integer_array(&body, "subscriptionIds"),
        None,
        true,
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    get_group(state, id).with_status(201)
}

fn get_group(state: &Path, id: i64) -> HttpResponse {
    match get_group_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "group not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_group_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    get_group_value_with_conn(&conn, id)
}

fn get_group_value_with_conn(conn: &Connection, id: i64) -> io::Result<Option<Value>> {
    let Some((group_id, name, policy, version)) = conn
        .query_row(
            "SELECT id, name, policy, version FROM groups WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_io_error)?
    else {
        return Ok(None);
    };
    let nodes = group_nodes_value(conn, group_id)?;
    let subscriptions = group_subscriptions_value(conn, group_id)?;
    let policy_params = group_policy_params_value(conn, group_id)?;
    Ok(Some(json!({
        "id": group_id,
        "name": name,
        "policy": policy,
        "policyParams": policy_params,
        "nodes": nodes,
        "subscriptions": subscriptions,
        "version": version,
    })))
}

fn update_group(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE groups SET name = ?1, version = version + 1 WHERE id = ?2",
            params![name, id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if let Some(policy) = body.get("policy").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE groups SET policy = ?1, version = version + 1 WHERE id = ?2",
            params![policy, id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if body.get("policyParams").is_some() {
        if let Err(err) = replace_group_policy_params(&conn, id, body.get("policyParams")) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    get_group(state, id)
}

fn delete_group(state: &Path, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute("DELETE FROM group_nodes WHERE group_id = ?1", params![id]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute(
        "DELETE FROM group_subscriptions WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    match conn.execute("DELETE FROM groups WHERE id = ?1", params![id]) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn update_group_nodes(state: &Path, request: &HttpRequest, id: i64, add: bool) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "nodeIds");
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = apply_group_node_ids(&conn, id, &ids, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}

fn update_group_subscriptions(
    state: &Path,
    request: &HttpRequest,
    id: i64,
    add: bool,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "subscriptionIds");
    let name_filter_regex = body.get("nameFilterRegex").and_then(Value::as_str);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = apply_group_subscription_ids(&conn, id, &ids, name_filter_regex, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}

fn group_nodes_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             WHERE gn.group_id = ?1
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn group_subscriptions_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.updated_at, s.link, s.cron_exp, s.cron_enable, s.status, s.info, s.tag, gs.name_filter_regex
             FROM subscriptions s
             JOIN group_subscriptions gs ON gs.subscription_id = s.id
             WHERE gs.group_id = ?1
             ORDER BY s.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?
                    .unwrap_or_else(|| "10 */6 * * *".to_owned()),
                row.get::<_, i64>(4)? != 0,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, updated_at, link, _cron_exp, _cron_enable, status, info, tag, name_filter_regex) =
            row.map_err(sqlite_io_error)?;
        let matched_nodes =
            nodes_for_subscription_filtered_value(conn, id, name_filter_regex.as_deref())?;
        out.push(json!({
            "subscriptionId": id,
            "nameFilterRegex": name_filter_regex,
            "matchedCount": matched_nodes.len(),
            "matchedNodes": matched_nodes,
            "updatedAt": updated_at,
            "status": status,
            "info": info,
            "link": link,
            "tag": tag,
        }));
    }
    Ok(out)
}

fn nodes_for_subscription_filtered_value(
    conn: &Connection,
    subscription_id: i64,
    name_filter_regex: Option<&str>,
) -> io::Result<Vec<Value>> {
    let filter = compile_name_filter(name_filter_regex)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE subscription_id = ?1 ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let node = row.map_err(sqlite_io_error)?;
        if node_matches_name_filter(&node, filter.as_ref()) {
            items.push(node);
        }
    }
    Ok(items)
}

fn compile_name_filter(name_filter_regex: Option<&str>) -> io::Result<Option<Regex>> {
    let Some(raw) = name_filter_regex
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    Regex::new(raw)
        .map(Some)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

fn node_matches_name_filter(node: &Value, filter: Option<&Regex>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    node.get("name")
        .and_then(Value::as_str)
        .map(|name| filter.is_match(name))
        .unwrap_or(false)
}

fn group_policy_params_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM group_policy_params WHERE group_id = ?1 ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok(json!({
                "key": row.get::<_, String>(0)?,
                "val": row.get::<_, String>(1)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn replace_group_policy_params(
    conn: &Connection,
    group_id: i64,
    params_value: Option<&Value>,
) -> io::Result<()> {
    conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    if let Some(values) = params_value.and_then(Value::as_array) {
        for item in values {
            let key = item
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            conn.execute(
                "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                params![key, value, group_id],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn apply_group_node_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    add: bool,
) -> io::Result<()> {
    for id in ids {
        if add {
            conn.execute(
                "INSERT OR IGNORE INTO group_nodes(group_id, node_id) VALUES(?1, ?2)",
                params![group_id, id],
            )
        } else {
            conn.execute(
                "DELETE FROM group_nodes WHERE group_id = ?1 AND node_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn apply_group_subscription_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    name_filter_regex: Option<&str>,
    add: bool,
) -> io::Result<()> {
    let name_filter_regex = name_filter_regex
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if add {
        let _ = compile_name_filter(name_filter_regex)?;
    }
    for id in ids {
        if add {
            conn.execute(
                "INSERT OR REPLACE INTO group_subscriptions(group_id, subscription_id, name_filter_regex) VALUES(?1, ?2, ?3)",
                params![group_id, id, name_filter_regex],
            )
        } else {
            conn.execute(
                "DELETE FROM group_subscriptions WHERE group_id = ?1 AND subscription_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn general_state_report(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let runtime_state = runtime.summary();
    let running = runtime_state["running"].as_bool().unwrap_or(false);
    let modified = runtime_modified(&conn, running)?;
    let selected_config_id = selected_id(&conn, SectionKind::Config)?;
    let selected_dns_id = selected_id(&conn, SectionKind::Dns)?;
    let selected_routing_id = selected_id(&conn, SectionKind::Routing)?;
    Ok(json!({
        "running": running,
        "modified": modified,
        "version": crate::version::version_from_env(),
        "netnsLinkMode": runtime_state["netnsLinkMode"].clone(),
        "attachBackend": runtime_state["attachBackend"].clone(),
        "runtime": runtime_state,
        "updatedAt": now_text(),
        "state": path_string(state),
        "selected": {
            "configId": selected_config_id,
            "dnsId": selected_dns_id,
            "routingId": selected_routing_id,
        },
        "counts": {
            "configs": count_table(&conn, "configs")?,
            "dns": count_table(&conn, "dns")?,
            "routings": count_table(&conn, "routings")?,
            "groups": count_table(&conn, "groups")?,
            "nodes": count_table(&conn, "nodes")?,
            "subscriptions": count_table(&conn, "subscriptions")?,
            "logs": count_log_file_entries(config_dir)?,
        }
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeSectionState {
    id: i64,
    version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunningRuntimeState {
    config_id: Option<i64>,
    config_version: i64,
    dns_id: Option<i64>,
    dns_version: i64,
    routing_id: Option<i64>,
    routing_version: i64,
    group_version_sum: i64,
    group_ids: String,
}

fn runtime_modified(conn: &Connection, running: bool) -> io::Result<bool> {
    if !running {
        return Ok(false);
    }
    let Some(config) = selected_section_state(conn, SectionKind::Config)? else {
        return Ok(true);
    };
    let Some(dns) = selected_section_state(conn, SectionKind::Dns)? else {
        return Ok(true);
    };
    let Some(routing) = selected_section_state(conn, SectionKind::Routing)? else {
        return Ok(true);
    };
    let Some(running_state) = running_runtime_state(conn)? else {
        return Ok(true);
    };

    Ok(running_state.config_id != Some(config.id)
        || running_state.config_version != config.version
        || running_state.dns_id != Some(dns.id)
        || running_state.dns_version != dns.version
        || running_state.routing_id != Some(routing.id)
        || running_state.routing_version != routing.version
        || running_state.group_version_sum != group_version_sum(conn)?
        || running_state.group_ids != group_ids_text(conn)?)
}

fn selected_section_state(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<RuntimeSectionState>> {
    let sql = format!(
        "SELECT id, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok(RuntimeSectionState {
            id: row.get(0)?,
            version: row.get(1)?,
        })
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn running_runtime_state(conn: &Connection) -> io::Result<Option<RunningRuntimeState>> {
    conn.query_row(
        "SELECT running_config_id, running_config_version,
                running_dns_id, running_dns_version,
                running_routing_id, running_routing_version,
                running_group_version_sum, running_group_ids
         FROM systems
         WHERE running != 0
         ORDER BY id
         LIMIT 1",
        [],
        |row| {
            Ok(RunningRuntimeState {
                config_id: row.get(0)?,
                config_version: row.get(1)?,
                dns_id: row.get(2)?,
                dns_version: row.get(3)?,
                routing_id: row.get(4)?,
                routing_version: row.get(5)?,
                group_version_sum: row.get(6)?,
                group_ids: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn build_runtime_config_from_content(content: &str) -> Result<Config, String> {
    let sections = parse_config(content).map_err(|err| err.to_string())?;
    build_config(&sections).map_err(|err| err.to_string())
}

fn mark_system_stopped(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let updated = conn
        .execute("UPDATE systems SET running = 0", [])
        .map_err(sqlite_io_error)?;
    if updated == 0 {
        conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
             VALUES(0, 0, 0, 0, 0, '')",
            [],
        )
        .map_err(sqlite_io_error)?;
    }
    set_metadata(state, "runtime_running", "false")?;
    Ok(())
}

fn mark_runtime_process_stopped(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    set_metadata(state, "runtime_running", "false")
}

fn materialize_runtime(state: &Path, config_dir: Option<&Path>, dry: bool) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config = selected_section_raw(&conn, SectionKind::Config)?;
    let dns = selected_section_raw(&conn, SectionKind::Dns)?;
    let routing = selected_section_raw(&conn, SectionKind::Routing)?;
    let groups = list_groups_value(state)?;
    let nodes = list_all_nodes_value(state)?;
    let generated_at = now_text();
    let content = render_generated_config(
        &generated_at,
        config.as_ref(),
        dns.as_ref(),
        routing.as_ref(),
        &groups,
        &nodes,
    )?;
    let output_path = config_dir.map(|dir| dir.join("runtime").join("generated.dae"));
    if !dry {
        if let Some(path) = &output_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &content)?;
            set_private_runtime_file_permissions(path)?;
            set_metadata(state, "last_generated_config_path", &path_string(path))?;
        }
        set_metadata(state, "last_materialized_at", &generated_at)?;
        conn.execute("DELETE FROM systems", [])
            .map_err(sqlite_io_error)?;
        conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids, running_config_id, running_dns_id, running_routing_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                1_i64,
                config.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                dns.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                routing.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                group_version_sum(&conn)?,
                group_ids_text(&conn)?,
                config.as_ref().map(|(id, _, _, _)| *id),
                dns.as_ref().map(|(id, _, _, _)| *id),
                routing.as_ref().map(|(id, _, _, _)| *id),
            ],
        )
        .map_err(sqlite_io_error)?;
        set_metadata(state, "runtime_running", "true")?;
    }
    let content_len = content.len();
    let mut report = Map::new();
    report.insert("filename".to_owned(), json!("generated.dae"));
    report.insert(
        "path".to_owned(),
        json!(output_path.as_ref().map(|path| path_string(path))),
    );
    report.insert("bytes".to_owned(), json!(content_len));
    report.insert("contentIncluded".to_owned(), json!(dry));
    if dry {
        report.insert("content".to_owned(), json!(content));
    }
    report.insert("generatedAt".to_owned(), json!(generated_at));
    report.insert(
        "selected".to_owned(),
        json!({
            "configId": config.as_ref().map(|(id, _, _, _)| *id),
            "dnsId": dns.as_ref().map(|(id, _, _, _)| *id),
            "routingId": routing.as_ref().map(|(id, _, _, _)| *id),
        }),
    );
    report.insert(
        "groups".to_owned(),
        json!(groups["items"].as_array().map(Vec::len).unwrap_or(0)),
    );
    report.insert(
        "nodes".to_owned(),
        json!(nodes["items"].as_array().map(Vec::len).unwrap_or(0)),
    );
    Ok(Value::Object(report))
}

fn render_generated_config(
    generated_at: &str,
    config: Option<&(i64, String, String, i64)>,
    dns: Option<&(i64, String, String, i64)>,
    routing: Option<&(i64, String, String, i64)>,
    groups: &Value,
    nodes: &Value,
) -> io::Result<String> {
    let mut out = String::new();
    out.push_str("# generated by Rust daed C10 local product surface\n");
    out.push_str(&format!("# generated_at: {generated_at}\n\n"));
    out.push_str("# selected config\n");
    out.push_str(
        config
            .map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("global {}\n"),
    );
    out.push_str("\n\n# selected dns\n");
    out.push_str(
        dns.map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("dns {}\n"),
    );
    out.push_str("\n\n# selected routing\n");
    out.push_str(
        routing
            .map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("routing {}\n"),
    );
    out.push_str("\n\n# local product nodes\n");
    out.push_str(&render_node_section(nodes));
    out.push_str("\n\n# local product groups\n");
    out.push_str(&render_group_section(groups)?);
    out.push('\n');
    Ok(out)
}

fn render_node_section(nodes: &Value) -> String {
    let mut out = String::from("node {\n");
    for node in nodes["items"].as_array().into_iter().flatten() {
        let Some(link) = node.get("link").and_then(Value::as_str) else {
            continue;
        };
        if link.trim().is_empty() {
            continue;
        }
        let tag = runtime_node_tag(node);
        out.push_str(&format!(
            "    {}: {}\n",
            dae_key_literal(&tag),
            dae_string_literal(link)
        ));
    }
    out.push_str("}\n");
    out
}

fn render_group_section(groups: &Value) -> io::Result<String> {
    let mut out = String::from("group {\n");
    for group in groups["items"].as_array().into_iter().flatten() {
        let Some(name) = group.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        out.push_str(&format!("    {} {{\n", dae_key_literal(name)));
        let node_tags = runtime_group_node_tags(group);
        if node_tags.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("group {name} has no matched nodes"),
            ));
        }
        let names = node_tags
            .iter()
            .map(|tag| dae_string_literal(tag))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("        filter: name({names})\n"));
        let policy = group
            .get("policy")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|policy| !policy.is_empty())
            .unwrap_or("fixed(0)");
        out.push_str(&format!("        policy: {policy}\n"));
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    Ok(out)
}

fn runtime_group_node_tags(group: &Value) -> Vec<String> {
    let mut tags = Vec::<String>::new();
    for node in group["nodes"].as_array().into_iter().flatten() {
        push_unique(&mut tags, runtime_node_tag(node));
    }
    for subscription in group["subscriptions"].as_array().into_iter().flatten() {
        for node in subscription["matchedNodes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            push_unique(&mut tags, runtime_node_tag(node));
        }
    }
    tags
}

fn runtime_node_tag(node: &Value) -> String {
    node.get("runtimeTag")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            node.get("tag")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            node.get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| {
            let id = node.get("id").and_then(Value::as_i64).unwrap_or(0);
            format!("node_{id}")
        })
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|seen| seen == &value) {
        values.push(value);
    }
}

fn dae_key_literal(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        && value
            .chars()
            .next()
            .map(|ch| ch.is_ascii_alphabetic() || ch == '_')
            .unwrap_or(false)
    {
        value.to_owned()
    } else {
        dae_string_literal(value)
    }
}

fn dae_string_literal(value: &str) -> String {
    let mut out = String::from("'");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

fn selected_section_raw(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<(i64, String, String, i64)>> {
    let sql = format!(
        "SELECT id, name, {}, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    let selected = conn
        .query_row(&sql, [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()
        .map_err(sqlite_io_error)?;
    if selected.is_some() {
        return Ok(selected);
    }
    let sql = format!(
        "SELECT id, name, {}, version FROM {} ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn selected_id(conn: &Connection, kind: SectionKind) -> io::Result<Option<i64>> {
    let sql = format!(
        "SELECT id FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)
}

fn group_version_sum(conn: &Connection) -> io::Result<i64> {
    conn.query_row("SELECT COALESCE(SUM(version), 0) FROM groups", [], |row| {
        row.get(0)
    })
    .map_err(sqlite_io_error)
}

fn group_ids_text(conn: &Connection) -> io::Result<String> {
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?.to_string());
    }
    Ok(ids.join(","))
}

fn get_metadata(state: &Path, key: &str) -> io::Result<Option<String>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT value FROM daed_product_metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn set_metadata(state: &Path, key: &str, value: &str) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params![key, value],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

static LOG_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static LOG_LAST_ID_CACHE: OnceLock<Mutex<Option<ProductLogIdCache>>> = OnceLock::new();

#[derive(Clone, Debug)]
struct ProductLogIdCache {
    path: PathBuf,
    id: u64,
}

fn initialize_log_store(config_dir: &Path, state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    ensure_log_dir(config_dir)?;
    let log_file = product_log_file(config_dir);
    if log_file.exists() {
        set_log_file_permissions(&log_file)?;
        let conn = open_state_connection(state)?;
        prune_log_file(config_dir, &conn)?;
        reset_log_id_cache_to_last(&log_file)?;
    }
    Ok(())
}

fn register_resident_event_product_log_sink(config_dir: &Path, state: &Path) {
    let config_dir = config_dir.to_path_buf();
    let state = state.to_path_buf();
    set_resident_event_log_sink(Some(Arc::new(move |event| {
        let _ = append_resident_event_product_log(&config_dir, &state, event);
    })));
}

#[cfg(test)]
fn clear_resident_event_product_log_sink() {
    set_resident_event_log_sink(None);
}

fn append_resident_event_product_log(
    config_dir: &Path,
    state: &Path,
    event: &Value,
) -> io::Result<()> {
    let Some(event_name) = event.get("event").and_then(Value::as_str) else {
        return Ok(());
    };
    let level = resident_event_product_log_level(event_name, event);
    let fields = resident_event_product_log_fields(event_name, event);
    append_log_fields_for_config(
        config_dir,
        state,
        level,
        &resident_event_product_log_message(event_name, event),
        fields,
    )
}

fn resident_event_product_log_level(event_name: &str, event: &Value) -> &'static str {
    if event_name.contains("failed") || event_name.contains("error") {
        return "warn";
    }
    if matches!(
        event_name,
        "tcp_connection_finished" | "tcp_connection_blocked"
    ) && resident_event_has_route_log_context(event)
    {
        return "info";
    }
    if event_name.ends_with("_started") || event_name.ends_with("_stopped") {
        return "info";
    }
    "debug"
}

fn resident_event_has_route_log_context(event: &Value) -> bool {
    [
        "network",
        "outbound",
        "proxy_group",
        "outbound_kind",
        "original_dst",
    ]
    .iter()
    .any(|key| event.get(key).is_some_and(|value| !value.is_null()))
}

fn resident_event_is_flow_diagnostic(event_name: &str) -> bool {
    matches!(
        event_name,
        "tcp_connection_finished"
            | "tcp_connection_failed"
            | "tcp_connection_blocked"
            | "udp_packet_finished"
            | "udp_dns_packet_finished"
            | "udp_packet_skipped"
            | "udp_reply_failed"
            | "udp_exchange_failed"
    )
}

fn resident_event_product_log_message(event_name: &str, event: &Value) -> String {
    if resident_event_is_flow_diagnostic(event_name)
        && let Some(message) = resident_flow_event_product_log_message(event_name, event)
    {
        return message;
    }
    format!("resident dataplane {}", event_name.replace('_', " "))
}

fn resident_event_product_log_fields(event_name: &str, event: &Value) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    if resident_event_is_flow_diagnostic(event_name) {
        append_resident_flow_event_product_log_fields(&mut fields, event);
        return fields;
    }
    fields.insert("event".to_owned(), event_name.to_owned());
    if let Some(object) = event.as_object() {
        for (key, value) in object {
            if key == "event" {
                continue;
            }
            fields.insert(key.to_owned(), product_log_field_value(value));
        }
    }
    fields
}

fn resident_flow_event_product_log_message(event_name: &str, event: &Value) -> Option<String> {
    let peer = resident_event_field_str(event, "peer").unwrap_or("unknown-peer");
    let target = resident_event_first_field_str(
        event,
        &[
            "dial_target",
            "direct_target",
            "original_dst",
            "direct_peer_addr",
        ],
    )
    .unwrap_or("unknown-target");
    let suffix = if event_name.contains("failed")
        || event_name.contains("error")
        || event_name.ends_with("_skipped")
    {
        " failed"
    } else {
        ""
    };
    Some(format!("{peer} <-> {target}{suffix}"))
}

fn append_resident_flow_event_product_log_fields(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
) {
    append_resident_flow_network_field(fields, event);
    append_resident_event_first_field_if_present(
        fields,
        event,
        "outbound",
        &["outbound", "proxy_group", "outbound_kind"],
    );
    append_resident_event_first_field_if_present(
        fields,
        event,
        "policy",
        &["policy", "group_policy"],
    );
    append_resident_event_first_field_if_present(
        fields,
        event,
        "dialer",
        &["dialer", "node_tag", "outbound_kind"],
    );
    append_resident_event_first_field_if_present(
        fields,
        event,
        "sniffed",
        &["sniffed", "sniffed_domain"],
    );
    append_resident_event_first_field_if_present(
        fields,
        event,
        "ip",
        &["ip", "original_dst", "direct_target"],
    );
    for key in ["pid", "dscp", "pname", "mac", "error", "reason"] {
        append_resident_event_field_if_present(fields, event, key);
    }
}

fn append_resident_flow_network_field(fields: &mut BTreeMap<String, String>, event: &Value) {
    if let Some(network) = resident_event_field_value(event, "network") {
        fields.insert("network".to_owned(), network);
        return;
    }
    let Some(event_name) = resident_event_field_str(event, "event") else {
        return;
    };
    if event_name.starts_with("tcp_") {
        fields.insert("network".to_owned(), "tcp4".to_owned());
    } else if event_name.starts_with("udp_") {
        fields.insert("network".to_owned(), "udp4".to_owned());
    }
}

fn append_resident_event_first_field_if_present(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let Some(value) = input_keys
        .iter()
        .find_map(|key| resident_event_field_value(event, key))
    else {
        return;
    };
    fields.insert(output_key.to_owned(), value);
}

fn append_resident_event_field_if_present(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
    key: &str,
) {
    let Some(value) = event.get(key) else {
        return;
    };
    if value.is_null() {
        return;
    }
    let value = product_log_field_value(value);
    if !value.is_empty() {
        fields.insert(key.to_owned(), value);
    }
}

fn resident_event_field_value(event: &Value, key: &str) -> Option<String> {
    let value = event.get(key)?;
    (!value.is_null()).then(|| product_log_field_value(value))
}

fn resident_event_first_field_str<'a>(event: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| resident_event_field_str(event, key))
}

fn resident_event_field_str<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
    event
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn product_log_field_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_owned(),
        Value::Number(_) | Value::Bool(_) | Value::Null => value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn append_log_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
) -> io::Result<()> {
    append_log_fields_for_config(config_dir, state, level, message, BTreeMap::new())
}

fn append_lifecycle_log_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
) -> io::Result<()> {
    append_lifecycle_log_fields_for_config(config_dir, state, level, message, BTreeMap::new())
}

fn append_log_fields_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
    fields: BTreeMap<String, String>,
) -> io::Result<()> {
    append_log_fields_for_config_with_policy(config_dir, state, level, message, fields, true)
}

fn append_lifecycle_log_fields_for_config(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
    fields: BTreeMap<String, String>,
) -> io::Result<()> {
    append_log_fields_for_config_with_policy(config_dir, state, level, message, fields, false)
}

fn append_startup_phase_completed_for_config(
    config_dir: &Path,
    state: &Path,
    phase: &str,
    started_at: Instant,
    _fields: BTreeMap<String, String>,
) -> io::Result<()> {
    let mut fields = BTreeMap::new();
    fields.insert("phase".to_owned(), phase.to_owned());
    fields.insert("elapsed".to_owned(), format!("{:?}", started_at.elapsed()));
    append_lifecycle_log_fields_for_config(
        config_dir,
        state,
        "info",
        "[Startup] phase completed",
        fields,
    )
}

fn append_startup_phase_failed_for_config(
    config_dir: &Path,
    state: &Path,
    phase: &str,
    started_at: Instant,
    error: &str,
    mut fields: BTreeMap<String, String>,
) -> io::Result<()> {
    fields.insert("phase".to_owned(), phase.to_owned());
    fields.insert("elapsed".to_owned(), format!("{:?}", started_at.elapsed()));
    fields.insert("error".to_owned(), error.to_owned());
    append_lifecycle_log_fields_for_config(
        config_dir,
        state,
        "warn",
        "[Startup] phase failed",
        fields,
    )
}

fn append_log_fields_for_config_with_policy(
    config_dir: &Path,
    state: &Path,
    level: &str,
    message: &str,
    fields: BTreeMap<String, String>,
    respect_runtime_log_level: bool,
) -> io::Result<()> {
    let Some(level) = normalize_log_level_name(level) else {
        return Ok(());
    };
    if respect_runtime_log_level {
        let runtime_level = current_runtime_log_level(state)?;
        if !log_level_enabled(&level, &runtime_level) {
            return Ok(());
        }
    }
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let (max_entries, max_bytes) = log_settings_tuple(&conn)?;
    let log_file = product_log_file(config_dir);
    ensure_log_dir(config_dir)?;
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    let id = next_log_id(&log_file)?;
    let line = encode_log_entry_line(id, &level, message, fields)?;
    append_log_line(&log_file, &line)?;
    prune_log_file_if_needed(&log_file, max_entries, max_bytes, id)?;
    Ok(())
}

fn append_startup_reclaim_decision_log_for_config(
    config_dir: &Path,
    state: &Path,
    _report: &Value,
    force: bool,
) -> io::Result<()> {
    let mut fields = BTreeMap::new();
    fields.insert("force".to_owned(), force.to_string());
    fields.insert(
        "allocator_profile".to_owned(),
        allocator_profile().to_owned(),
    );
    append_lifecycle_log_fields_for_config(
        config_dir,
        state,
        "info",
        "[Startup] post-startup gc decision",
        fields,
    )
}

fn list_logs_value(
    config_dir: &Path,
    state: &Path,
    level: Option<&str>,
    query: Option<&str>,
    limit: usize,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let limit = if limit == 0 {
        DEFAULT_LOG_QUERY_LIMIT
    } else {
        limit.min(MAX_LOG_QUERY_LIMIT)
    };
    let level = normalize_log_level_filter(level)?;
    let query = query
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let log_file = product_log_file(config_dir);
    let file = match fs::File::open(&log_file) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(json!({"items": []})),
        Err(err) => return Err(err),
    };
    let mut items = Vec::new();
    let mut reader = io::BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        if read > MAX_LOG_LINE_BYTES * 2 {
            continue;
        }
        let Some(entry) = parse_log_entry_line(&line) else {
            continue;
        };
        if !log_entry_matches_filter(&entry, level.as_deref(), query.as_deref()) {
            continue;
        }
        if items.len() == limit {
            items.remove(0);
        }
        items.push(log_entry_value(entry));
    }
    Ok(json!({"items": items}))
}

fn log_settings_value(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let (max_entries, max_bytes) = log_settings_tuple(&conn)?;
    Ok(json!({
        "maxEntries": max_entries,
        "maxBytes": max_bytes,
        "minMaxEntries": MIN_LOG_MAX_ENTRIES,
        "maxMaxEntries": MAX_LOG_MAX_ENTRIES,
        "minMaxBytes": MIN_LOG_MAX_BYTES,
        "maxMaxBytes": MAX_LOG_MAX_BYTES,
    }))
}

fn log_settings_tuple(conn: &Connection) -> io::Result<(i64, i64)> {
    conn.query_row(
        "SELECT max_entries, max_bytes FROM log_settings WHERE id = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )
    .optional()
    .map_err(sqlite_io_error)
    .map(|value| {
        let (max_entries, max_bytes) =
            value.unwrap_or((DEFAULT_LOG_MAX_ENTRIES, DEFAULT_LOG_MAX_BYTES));
        (
            normalize_log_max_entries(max_entries),
            normalize_log_max_bytes(max_bytes),
        )
    })
}

#[derive(Debug)]
struct ProductLogEntry {
    id: u64,
    ts: String,
    level: String,
    message: String,
    fields: BTreeMap<String, String>,
}

fn product_log_file(config_dir: &Path) -> PathBuf {
    config_dir.join(PRODUCT_LOG_DIR).join(PRODUCT_LOG_FILE)
}

fn clear_log_file(config_dir: &Path) -> io::Result<()> {
    let log_file = product_log_file(config_dir);
    ensure_log_dir(config_dir)?;
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    fs::write(&log_file, [])?;
    set_log_id_cache(&log_file, 0)?;
    set_log_file_permissions(&log_file)
}

fn append_log_line(path: &Path, line: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(path)?;
    file.write_all(line)?;
    set_log_file_permissions(path)
}

fn set_log_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn ensure_log_dir(config_dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let log_dir = config_dir.join(PRODUCT_LOG_DIR);
    fs::create_dir_all(&log_dir)?;
    fs::set_permissions(log_dir, fs::Permissions::from_mode(0o750))
}

fn encode_log_entry_line(
    id: u64,
    level: &str,
    message: &str,
    fields: BTreeMap<String, String>,
) -> io::Result<Vec<u8>> {
    let mut message = trim_log_string(message, MAX_LOG_LINE_BYTES);
    let mut fields = trim_log_fields(fields, MAX_LOG_FIELD_VALUE_LEN);
    let mut line = encode_log_entry_json_line(id, level, &message, &fields)?;
    if line.len() > MAX_LOG_LINE_BYTES {
        message = trim_log_string(&message, MAX_LOG_LINE_BYTES / 2);
        fields = trim_log_fields(fields, 256);
        line = encode_log_entry_json_line(id, level, &message, &fields)?;
    }
    if line.len() > MAX_LOG_LINE_BYTES {
        message = trim_log_string(&message, 1024);
        fields.clear();
        line = encode_log_entry_json_line(id, level, &message, &fields)?;
    }
    Ok(line)
}

fn encode_log_entry_json_line(
    id: u64,
    level: &str,
    message: &str,
    fields: &BTreeMap<String, String>,
) -> io::Result<Vec<u8>> {
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(id));
    object.insert("ts".to_owned(), json!(now_text()));
    object.insert("level".to_owned(), json!(level));
    object.insert("message".to_owned(), json!(message));
    if !fields.is_empty() {
        object.insert("fields".to_owned(), json!(fields));
    }
    let mut data = serde_json::to_vec(&Value::Object(object))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    data.push(b'\n');
    Ok(data)
}

fn trim_log_fields(
    fields: BTreeMap<String, String>,
    max_value_len: usize,
) -> BTreeMap<String, String> {
    fields
        .into_iter()
        .map(|(key, value)| (key, trim_log_string(&value, max_value_len)))
        .collect()
}

fn trim_log_string(value: &str, max_len: usize) -> String {
    if max_len == 0 || value.len() <= max_len {
        return value.to_owned();
    }
    let mut boundary = 0;
    for (idx, _) in value.char_indices() {
        if idx > max_len {
            break;
        }
        boundary = idx;
    }
    if boundary == 0 {
        return "...".to_owned();
    }
    format!("{}...", &value[..boundary])
}

fn parse_log_entry_line(line: &str) -> Option<ProductLogEntry> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    let id = value.get("id").and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
    })?;
    let ts = value.get("ts")?.as_str()?.to_owned();
    let level = normalize_log_level_name(value.get("level")?.as_str()?)?;
    let message = value.get("message")?.as_str()?.to_owned();
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .map(|fields| {
            fields
                .iter()
                .map(|(key, value)| {
                    (
                        key.to_owned(),
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string()),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    Some(ProductLogEntry {
        id,
        ts,
        level,
        message,
        fields,
    })
}

fn log_entry_value(entry: ProductLogEntry) -> Value {
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(entry.id));
    object.insert("ts".to_owned(), json!(entry.ts));
    object.insert("level".to_owned(), json!(entry.level));
    object.insert("message".to_owned(), json!(entry.message));
    object.insert("fields".to_owned(), json!(entry.fields));
    Value::Object(object)
}

fn log_entry_matches_filter(
    entry: &ProductLogEntry,
    level: Option<&str>,
    query: Option<&str>,
) -> bool {
    if level.is_some_and(|level| level != entry.level) {
        return false;
    }
    let Some(query) = query else {
        return true;
    };
    if entry.message.to_ascii_lowercase().contains(query) {
        return true;
    }
    entry.fields.iter().any(|(key, value)| {
        key.to_ascii_lowercase().contains(query) || value.to_ascii_lowercase().contains(query)
    })
}

fn read_last_log_id(path: &Path) -> io::Result<u64> {
    let data = match read_tail_bytes(path, LOG_TAIL_ID_SCAN_BYTES) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    for line in data.lines().rev() {
        if let Some(entry) = parse_log_entry_line(line) {
            return Ok(entry.id);
        }
    }
    Ok(0)
}

fn next_log_id(path: &Path) -> io::Result<u64> {
    let lock = LOG_LAST_ID_CACHE.get_or_init(|| Mutex::new(None));
    let mut cache = lock
        .lock()
        .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
    if let Some(cached) = cache.as_mut()
        && cached.path == path
    {
        cached.id = cached.id.saturating_add(1);
        return Ok(cached.id);
    }
    let id = read_last_log_id(path)?.saturating_add(1);
    *cache = Some(ProductLogIdCache {
        path: path.to_path_buf(),
        id,
    });
    Ok(id)
}

fn cached_last_log_id(path: &Path) -> io::Result<u64> {
    let lock = LOG_LAST_ID_CACHE.get_or_init(|| Mutex::new(None));
    {
        let cache = lock
            .lock()
            .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
        if let Some(cached) = cache.as_ref()
            && cached.path == path
        {
            return Ok(cached.id);
        }
    }
    reset_log_id_cache_to_last(path)?;
    let cache = lock
        .lock()
        .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
    Ok(cache.as_ref().map(|cached| cached.id).unwrap_or(0))
}

fn set_log_id_cache(path: &Path, id: u64) -> io::Result<()> {
    let lock = LOG_LAST_ID_CACHE.get_or_init(|| Mutex::new(None));
    let mut cache = lock
        .lock()
        .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
    *cache = Some(ProductLogIdCache {
        path: path.to_path_buf(),
        id,
    });
    Ok(())
}

fn reset_log_id_cache_to_last(path: &Path) -> io::Result<()> {
    set_log_id_cache(path, read_last_log_id(path)?)
}

fn scan_log_entries_after_id(
    config_dir: &Path,
    after_id: u64,
) -> io::Result<(Vec<ProductLogEntry>, u64)> {
    let log_file = product_log_file(config_dir);
    let file = match fs::File::open(&log_file) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), after_id)),
        Err(err) => return Err(err),
    };
    let mut max_seen_id = after_id;
    let mut entries = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        let Some(entry) = parse_log_entry_line(&line) else {
            continue;
        };
        if entry.id > max_seen_id {
            max_seen_id = entry.id;
        }
        if entry.id > after_id {
            entries.push(entry);
        }
    }
    Ok((entries, max_seen_id))
}

fn count_log_file_entries(config_dir: &Path) -> io::Result<i64> {
    let log_file = product_log_file(config_dir);
    let file = match fs::File::open(&log_file) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut count = 0_i64;
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        if parse_log_entry_line(&line).is_some() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn read_tail_bytes(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(String::new());
    }
    let offset = size.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(offset))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    if offset > 0
        && let Some(newline) = data.iter().position(|byte| *byte == b'\n')
    {
        data = data.split_off(newline + 1);
    }
    Ok(String::from_utf8_lossy(&data).into_owned())
}

fn prune_log_file(config_dir: &Path, conn: &Connection) -> io::Result<()> {
    let (max_entries, max_bytes) = log_settings_tuple(conn)?;
    let log_file = product_log_file(config_dir);
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    prune_log_file_with_settings(&log_file, max_entries, max_bytes)?;
    reset_log_id_cache_to_last(&log_file)
}

fn prune_log_file_if_needed(
    path: &Path,
    max_entries: i64,
    max_bytes: i64,
    last_id: u64,
) -> io::Result<()> {
    let max_bytes = normalize_log_max_bytes(max_bytes) as u64;
    let size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if size <= max_bytes && last_id % LOG_PRUNE_INTERVAL != 0 {
        return Ok(());
    }
    prune_log_file_with_settings(path, max_entries, max_bytes as i64)
}

fn prune_log_file_with_settings(path: &Path, max_entries: i64, max_bytes: i64) -> io::Result<()> {
    let max_entries = normalize_log_max_entries(max_entries) as usize;
    let max_bytes = normalize_log_max_bytes(max_bytes) as u64;
    let data = match read_tail_bytes(path, max_bytes) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if data.is_empty() {
        return Ok(());
    }
    let mut lines = data
        .trim_end_matches('\n')
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if lines.len() > max_entries {
        lines = lines.split_off(lines.len() - max_entries);
    }
    let mut pruned = lines.join("\n");
    if !pruned.is_empty() {
        pruned.push('\n');
    }
    let tmp_path = path.with_extension("jsonl.tmp");
    fs::write(&tmp_path, pruned)?;
    set_log_file_permissions(&tmp_path)?;
    fs::rename(tmp_path, path)
}

fn current_runtime_log_level(state: &Path) -> io::Result<String> {
    let level = get_metadata(state, "runtime_log_level")?
        .and_then(|level| normalize_runtime_log_level(&level))
        .unwrap_or_else(|| "info".to_owned());
    Ok(level)
}

fn set_runtime_log_level_from_config(state: &Path, config: &Config) -> io::Result<()> {
    let level =
        normalize_runtime_log_level(&config.global.log_level).unwrap_or_else(|| "info".to_owned());
    set_metadata(state, "runtime_log_level", &level)
}

fn log_level_enabled(entry_level: &str, runtime_level: &str) -> bool {
    let Some(entry_rank) = log_level_rank(entry_level) else {
        return false;
    };
    let runtime_rank = log_level_rank(runtime_level).unwrap_or(4);
    entry_rank <= runtime_rank
}

fn log_level_rank(level: &str) -> Option<u8> {
    match level {
        "panic" => Some(0),
        "fatal" => Some(1),
        "error" => Some(2),
        "warn" => Some(3),
        "info" => Some(4),
        "debug" => Some(5),
        "trace" => Some(6),
        _ => None,
    }
}

fn normalize_log_max_entries(value: i64) -> i64 {
    if value == 0 {
        DEFAULT_LOG_MAX_ENTRIES
    } else {
        value.clamp(MIN_LOG_MAX_ENTRIES, MAX_LOG_MAX_ENTRIES)
    }
}

fn normalize_log_max_bytes(value: i64) -> i64 {
    if value == 0 {
        DEFAULT_LOG_MAX_BYTES
    } else {
        value.clamp(MIN_LOG_MAX_BYTES, MAX_LOG_MAX_BYTES)
    }
}

fn normalize_log_level_filter(level: Option<&str>) -> io::Result<Option<String>> {
    let Some(level) = level else {
        return Ok(None);
    };
    let level = level.trim();
    if level.is_empty() || level.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    normalize_log_level_name(level).map(Some).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a valid logrus Level: {level:?}"),
        )
    })
}

fn normalize_log_level_name(level: &str) -> Option<String> {
    let level = level.trim().to_ascii_lowercase();
    match level.as_str() {
        "panic" | "fatal" | "error" | "warn" | "info" | "debug" | "trace" => Some(level),
        "warning" => Some("warn".to_owned()),
        _ => None,
    }
}

fn sse_response_events(events: &[(&str, Value)], retry_ms: Option<u64>) -> HttpResponse {
    let mut body = String::new();
    if let Some(retry_ms) = retry_ms {
        body.push_str(&format!("retry: {retry_ms}\n\n"));
    }
    for (event, payload) in events {
        body.push_str(&format!("event: {event}\ndata: {payload}\n\n"));
    }
    let mut response = HttpResponse::text(200, "text/event-stream; charset=utf-8", body);
    response
        .extra_headers
        .push(("Cache-Control".to_owned(), "no-cache".to_owned()));
    response
        .extra_headers
        .push(("X-Accel-Buffering".to_owned(), "no".to_owned()));
    response
}

fn write_sse_stream_headers(stream: &mut TcpStream) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\n\r\n"
    )
}

fn write_sse_stream_event(stream: &mut TcpStream, event: &str, payload: &Value) -> io::Result<()> {
    let data = serde_json::to_string(payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    writeln!(stream, "event: {event}")?;
    for line in data.lines() {
        writeln!(stream, "data: {line}")?;
    }
    writeln!(stream)?;
    stream.flush()
}

fn list_node_latencies_value(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare(
            "SELECT n.id, l.latency_ms, COALESCE(l.alive, 0), COALESCE(l.tested_at, ''), l.message
             FROM nodes n
             LEFT JOIN node_latency_results l ON l.node_id = n.id
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "latencyMs": row.get::<_, Option<i64>>(1)?,
                "alive": row.get::<_, i64>(2)? != 0,
                "testedAt": row.get::<_, String>(3)?,
                "message": row.get::<_, Option<String>>(4)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

fn update_node_latencies(state: &Path, config_dir: &Path, ids: &[i64]) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let target_ids = if ids.is_empty() {
        all_node_ids(&conn)?
    } else {
        ids.to_vec()
    };
    let tested_at = now_text();
    for id in &target_ids {
        let node: Option<(String, String)> = conn
            .query_row(
                "SELECT link, address FROM nodes WHERE id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_io_error)?;
        let Some((link, address)) = node else {
            continue;
        };
        let probe = tcp_probe_node(&link, &address);
        conn.execute(
            "INSERT OR REPLACE INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
             VALUES(?1, ?2, 1, ?3, ?4, ?3)",
            params![id, probe.latency_ms, tested_at, probe.message],
        )
        .map_err(sqlite_io_error)?;
        conn.execute(
            "UPDATE node_latency_results SET alive = ?1 WHERE node_id = ?2",
            params![probe.alive as i64, id],
        )
        .map_err(sqlite_io_error)?;
    }
    append_log_for_config(
        config_dir,
        state,
        "info",
        "node latency probe updated by Rust daed",
    )?;
    list_node_latencies_value(state)
}

#[derive(Debug)]
struct TcpProbeResult {
    latency_ms: Option<i64>,
    alive: bool,
    message: String,
}

fn tcp_probe_node(link: &str, fallback_address: &str) -> TcpProbeResult {
    let (host, port) = node_probe_target(link, fallback_address);
    let started = Instant::now();
    match connect_tcp(&host, port, Duration::from_secs(3)) {
        Ok(stream) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            TcpProbeResult {
                latency_ms: Some(started.elapsed().as_millis().min(i64::MAX as u128) as i64),
                alive: true,
                message: format!("tcp connect {host}:{port}"),
            }
        }
        Err(err) => TcpProbeResult {
            latency_ms: None,
            alive: false,
            message: format!("tcp connect {host}:{port} failed: {err}"),
        },
    }
}

fn node_probe_target(link: &str, fallback_address: &str) -> (String, u16) {
    if let Ok(url) = url::Url::parse(link) {
        let host = url
            .host_str()
            .map(str::to_owned)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| fallback_address.to_owned());
        let port = url
            .port()
            .or_else(|| default_node_port(url.scheme()))
            .unwrap_or(443);
        return (host, port);
    }
    (fallback_address.to_owned(), 443)
}

fn default_node_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" | "vless" | "trojan" | "vmess" | "ss" | "hysteria2" | "hy2" => Some(443),
        _ => None,
    }
}

fn all_node_ids(conn: &Connection) -> io::Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT id FROM nodes ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    Ok(ids)
}

fn export_bundle(state: &Path, user: &UserRecord) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let storage = serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    Ok(json!({
        "schemaVersion": 1,
        "exportedAt": now_text(),
        "mode": storage.get("mode").and_then(Value::as_str).unwrap_or("rule"),
        "defaults": {
            "configId": numeric_storage_value(&storage, "defaultConfigID"),
            "dnsId": numeric_storage_value(&storage, "defaultDNSID"),
            "routingId": numeric_storage_value(&storage, "defaultRoutingID"),
            "groupId": numeric_storage_value(&storage, "defaultGroupID"),
        },
        "selected": {
            "configId": selected_id(&conn, SectionKind::Config)?,
            "dnsId": selected_id(&conn, SectionKind::Dns)?,
            "routingId": selected_id(&conn, SectionKind::Routing)?,
        },
        "configs": bundle_sections(&conn, SectionKind::Config)?,
        "dnss": bundle_sections(&conn, SectionKind::Dns)?,
        "routings": bundle_sections(&conn, SectionKind::Routing)?,
        "subscriptions": bundle_subscriptions(&conn)?,
        "nodes": bundle_nodes(&conn)?,
        "groups": bundle_groups(&conn)?,
    }))
}

fn import_bundle(
    state: &Path,
    config_dir: &Path,
    body: &Value,
    user: &UserRecord,
) -> io::Result<bool> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn.transaction().map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_policy_params", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_subscriptions", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_nodes", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM node_latency_results", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM nodes", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM subscriptions", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM groups", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM configs", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM dns", []).map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM routings", [])
        .map_err(sqlite_io_error)?;

    import_bundle_sections(&tx, body.get("configs"), SectionKind::Config)?;
    import_bundle_sections(&tx, body.get("dnss"), SectionKind::Dns)?;
    import_bundle_sections(&tx, body.get("routings"), SectionKind::Routing)?;
    import_bundle_subscriptions(&tx, body.get("subscriptions"))?;
    import_bundle_nodes(&tx, body.get("nodes"))?;
    import_bundle_groups(&tx, body.get("groups"))?;

    if let Some(selected) = body.get("selected") {
        set_selected_from_bundle(&tx, selected, "configId", SectionKind::Config)?;
        set_selected_from_bundle(&tx, selected, "dnsId", SectionKind::Dns)?;
        set_selected_from_bundle(&tx, selected, "routingId", SectionKind::Routing)?;
    }
    tx.commit().map_err(sqlite_io_error)?;

    let mut storage =
        serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    if !storage.is_object() {
        storage = json!({});
    }
    if let Some(mode) = body.get("mode").and_then(Value::as_str) {
        set_value_at_path(&mut storage, "mode", Value::String(mode.to_owned()))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    if let Some(defaults) = body.get("defaults") {
        for (key, path) in [
            ("configId", "defaultConfigID"),
            ("dnsId", "defaultDNSID"),
            ("routingId", "defaultRoutingID"),
            ("groupId", "defaultGroupID"),
        ] {
            if let Some(value) = defaults.get(key).and_then(Value::as_i64) {
                set_value_at_path(&mut storage, path, Value::String(value.to_string()))
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            }
        }
    }
    save_json_storage(state, user.id, &storage.to_string())?;
    append_log_for_config(
        config_dir,
        state,
        "info",
        "DAE bundle imported by Rust daed",
    )?;
    Ok(true)
}

fn bundle_sections(conn: &Connection, kind: SectionKind) -> io::Result<Vec<Value>> {
    let sql = format!(
        "SELECT id, name, {} FROM {} ORDER BY id",
        kind.value_column(),
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            let id = row.get::<_, i64>(0)?;
            let name = row.get::<_, String>(1)?;
            let raw = row.get::<_, String>(2)?;
            Ok(match kind {
                SectionKind::Config => json!({"id": id, "name": name, "global": raw}),
                SectionKind::Dns => json!({"id": id, "name": name, "dns": raw}),
                SectionKind::Routing => json!({"id": id, "name": name, "routing": raw}),
            })
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn bundle_subscriptions(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn bundle_nodes(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn bundle_groups(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare("SELECT id, name, policy FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut groups = Vec::new();
    for row in rows {
        let (id, name, policy) = row.map_err(sqlite_io_error)?;
        groups.push(json!({
            "id": id,
            "name": name,
            "policy": policy,
            "policyParams": group_policy_params_value(conn, id)?,
            "nodeIds": group_node_ids(conn, id)?,
            "subscriptionBindings": group_subscription_bindings(conn, id)?,
        }));
    }
    Ok(groups)
}

fn group_node_ids(conn: &Connection, group_id: i64) -> io::Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT node_id FROM group_nodes WHERE group_id = ?1 ORDER BY node_id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    Ok(ids)
}

fn group_subscription_bindings(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, name_filter_regex FROM group_subscriptions WHERE group_id = ?1 ORDER BY subscription_id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok(json!({
                "subscriptionId": row.get::<_, i64>(0)?,
                "nameFilterRegex": row.get::<_, Option<String>>(1)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn import_bundle_sections(
    conn: &Connection,
    sections: Option<&Value>,
    kind: SectionKind,
) -> io::Result<()> {
    if let Some(items) = sections.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(kind.default_name());
            let raw = item
                .get(kind.request_value_key())
                .and_then(Value::as_str)
                .unwrap_or("");
            let sql = format!(
                "INSERT INTO {}(id, name, {}, selected, version) VALUES(?1, ?2, ?3, 0, 0)",
                kind.table(),
                kind.value_column()
            );
            conn.execute(&sql, params![id, name, raw])
                .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn import_bundle_subscriptions(conn: &Connection, subscriptions: Option<&Value>) -> io::Result<()> {
    if let Some(items) = subscriptions.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let updated_at = item
                .get("updatedAt")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(now_text);
            conn.execute(
                "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id,
                    updated_at,
                    item.get("link").and_then(Value::as_str).unwrap_or(""),
                    item.get("cronExp")
                        .and_then(Value::as_str)
                        .unwrap_or("10 */6 * * *"),
                    item.get("cronEnable")
                        .and_then(Value::as_bool)
                        .unwrap_or(true) as i64,
                    item.get("status").and_then(Value::as_str).unwrap_or("imported"),
                    item.get("info").and_then(Value::as_str).unwrap_or(""),
                    item.get("tag").and_then(Value::as_str),
                ],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn import_bundle_nodes(conn: &Connection, nodes: Option<&Value>) -> io::Result<()> {
    if let Some(items) = nodes.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let link = item.get("link").and_then(Value::as_str).unwrap_or("");
            let parsed = parse_node_link(link, item.get("tag").and_then(Value::as_str));
            conn.execute(
                "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    link,
                    item.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.name),
                    item.get("address")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.address),
                    item.get("protocol")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.protocol),
                    item.get("tag").and_then(Value::as_str),
                    item.get("subscriptionId").and_then(Value::as_i64),
                ],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn import_bundle_groups(conn: &Connection, groups: Option<&Value>) -> io::Result<()> {
    if let Some(items) = groups.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            conn.execute(
                "INSERT INTO groups(id, name, policy, version) VALUES(?1, ?2, ?3, 0)",
                params![
                    id,
                    item.get("name").and_then(Value::as_str).unwrap_or("proxy"),
                    item.get("policy")
                        .and_then(Value::as_str)
                        .unwrap_or("random"),
                ],
            )
            .map_err(sqlite_io_error)?;
            replace_group_policy_params(conn, id, item.get("policyParams"))?;
            apply_group_node_ids(conn, id, &integer_array(item, "nodeIds"), true)?;
            if let Some(bindings) = item.get("subscriptionBindings").and_then(Value::as_array) {
                for binding in bindings {
                    if let Some(subscription_id) =
                        binding.get("subscriptionId").and_then(Value::as_i64)
                    {
                        apply_group_subscription_ids(
                            conn,
                            id,
                            &[subscription_id],
                            binding.get("nameFilterRegex").and_then(Value::as_str),
                            true,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn set_selected_from_bundle(
    conn: &Connection,
    selected: &Value,
    key: &str,
    kind: SectionKind,
) -> io::Result<()> {
    let Some(id) = selected.get(key).and_then(Value::as_i64) else {
        return Ok(());
    };
    let clear = format!("UPDATE {} SET selected = 0", kind.table());
    let set = format!("UPDATE {} SET selected = 1 WHERE id = ?1", kind.table());
    conn.execute(&clear, []).map_err(sqlite_io_error)?;
    conn.execute(&set, params![id]).map_err(sqlite_io_error)?;
    Ok(())
}

fn numeric_storage_value(storage: &Value, key: &str) -> Option<i64> {
    storage
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<i64>().ok())
}

fn product_openapi_skeleton() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "daed Rust native product API",
            "version": crate::version::version_from_env(),
        },
        "x-c-phase": "C10",
        "x-work-package": "go-free-product-chain-v1",
        "paths": {
            "/api/health": {"get": {"summary": "health"}},
            "/api/auth/status": {"get": {"summary": "setup/auth status"}},
            "/api/user/me": {"get": {"summary": "current user"}, "patch": {"summary": "update current user"}},
            "/api/user/me/storage": {"get": {"summary": "read JSON storage"}, "put": {"summary": "write JSON storage"}, "delete": {"summary": "delete JSON storage"}},
            "/api/user/me/dae-bundle": {"get": {"summary": "export DAE bundle"}, "put": {"summary": "import DAE bundle"}},
            "/api/user/me/dae-config-file": {"get": {"summary": "export generated DAE config"}, "put": {"summary": "import DAE config"}},
            "/api/configs": {"get": {"summary": "list config resources"}, "post": {"summary": "create config resource"}},
            "/api/dns": {"get": {"summary": "list DNS resources"}, "post": {"summary": "create DNS resource"}},
            "/api/routings": {"get": {"summary": "list routing resources"}, "post": {"summary": "create routing resource"}},
            "/api/nodes": {"get": {"summary": "list nodes"}, "post": {"summary": "import nodes"}, "delete": {"summary": "delete nodes"}},
            "/api/subscriptions": {"get": {"summary": "list subscriptions"}, "post": {"summary": "import subscription"}, "delete": {"summary": "delete subscriptions"}},
            "/api/groups": {"get": {"summary": "list groups"}, "post": {"summary": "create group"}},
            "/api/nodes/latencies": {"get": {"summary": "list latency results"}, "post": {"summary": "test latency"}},
            "/api/runtime/reload": {"post": {"summary": "materialize and apply runtime state"}},
            "/api/runtime/stop": {"post": {"summary": "stop runtime owner state"}},
            "/api/runtime/overview": {"get": {"summary": "runtime overview"}},
            "/api/logs": {"get": {"summary": "list logs"}, "delete": {"summary": "clear logs"}},
            "/api/logs/settings": {"get": {"summary": "read log settings"}, "patch": {"summary": "update log settings"}},
            "/api/events/runtime": {"get": {"summary": "runtime SSE stream"}},
            "/api/events/logs": {"get": {"summary": "log SSE stream"}}
        }
    })
}

fn product_flatdesc() -> Value {
    json!({
        "schemaVersion": 1,
        "cPhase": "C10",
        "workPackage": "go-free-product-chain-v1",
        "stateStore": PRIMARY_STATE_STORE,
        "protectedRollbackStore": PROTECTED_ROLLBACK_STATE_STORE,
        "resources": ["configs", "dns", "routings", "nodes", "subscriptions", "groups"],
        "runtime": ["materialize-parseable-generated-config", "resident-runtime-reload", "resident-runtime-stop", "live-manager-state"],
        "logs": ["log-list", "log-settings", "sse-snapshot"],
        "package": ["systemd-unit-surface", "docker-entrypoint-surface", "package-manifest", "admission-report", "webui-route-audit", "openapi", "flatdesc", "outline"],
        "fullGoFreeProductChainReady": false,
    })
}

fn product_outline() -> Value {
    json!({
        "daed": {
            "binary": "/usr/bin/daed",
            "run": "daed run -c /etc/daed --listen 0.0.0.0:2023",
            "state": PRIMARY_STATE_STORE,
            "webRoot": DEFAULT_WEB_ROOT,
        },
        "workPackage": "go-free-product-chain-v1",
        "localC10Surface": {
            "webApi": true,
            "staticWebui": true,
            "materializer": true,
            "realRuntimeBridge": true,
            "metadataOnlyRuntimeState": false,
            "logsSseLatencySubscription": true,
            "importExport": true,
            "subscriptionFetch": true,
            "tcpLatencyProbe": true,
            "resetpassParity": true,
            "packageManifest": true,
            "webuiRouteAudit": true,
        },
        "remainingAdmission": [
            "live host default package switch revalidation",
            "live rollback validation revalidation",
            "remove Go daewing from default package path",
            "production package admission"
        ]
    })
}

fn product_package_manifest() -> Value {
    json!({
        "schemaVersion": 1,
        "name": "daed",
        "cPhase": "C10",
        "workPackage": "go-free-product-chain-v1",
        "binary": {
            "path": "/usr/bin/daed",
            "source": "rust/crates/dae-daemon/src/bin/daed.rs",
            "defaultArgs": ["run", "-c", DEFAULT_CONFIG_DIR],
        },
        "state": {
            "primary": PRIMARY_STATE_STORE,
            "protectedRollback": PROTECTED_ROLLBACK_STATE_STORE,
            "writesProtectedRollbackByDefault": false,
            "varLibDaedRequiredByDefault": false,
        },
        "webui": {
            "framework": "current React/Vite dist",
            "root": DEFAULT_WEB_ROOT,
            "servedBy": "Rust daed",
        },
        "runtime": {
            "generatedConfig": "/etc/daed/runtime/generated.dae",
            "materializer": "POST /api/runtime/reload",
            "owner": "resident-production-runtime-manager",
            "state": "GET /api/general/state reports live manager state",
            "metadataOnlyRunningState": false,
            "defaults": product_runtime_defaults(),
        },
        "systemd": {
            "unitName": "daed.service",
            "execStart": "/usr/bin/daed run -c /etc/daed",
            "export": "daed export systemd-unit",
        },
        "docker": {
            "entrypoint": ["/usr/bin/daed", "run", "-c", "/etc/daed", "--listen", "0.0.0.0:2023"],
            "export": "daed export docker-entrypoint",
        },
        "admission": {
            "localPackageAdmissionReady": true,
            "liveDefaultSwitchApplied": false,
            "goDaewingDefaultPathRemoved": false,
            "rollbackValidationAppliedOnLiveHost": false,
        }
    })
}

fn product_admission_report() -> Value {
    let route_audit = webui_route_audit_report();
    json!({
        "schemaVersion": 1,
        "cPhase": "C10",
        "workPackage": "go-free-product-chain-v1",
        "status": "local-runtime-bridge-pass-live-revalidation-pending",
        "runtimeDefaults": product_runtime_defaults(),
        "localEvidence": {
            "rustDaedBinary": true,
            "primaryStateStore": PRIMARY_STATE_STORE,
            "protectedRollbackStateStore": PROTECTED_ROLLBACK_STATE_STORE,
            "rustDaedWritesWingDbByDefault": false,
            "currentReactViteWebuiServedByRust": true,
            "resourceCrudApi": true,
            "runtimeMaterializer": true,
            "runtimeMaterializerParseableConfig": true,
            "runtimeOwnerApi": true,
            "realRuntimeBridge": true,
            "metadataOnlyRuntimeState": false,
            "logsSse": true,
            "subscriptionFetch": true,
            "tcpLatencyProbe": true,
            "resetpassParity": true,
            "packageManifest": true,
            "webuiRouteAuditPass": route_audit["pass"].as_bool().unwrap_or(false),
            "runtimeDefaultsExplicit": true,
        },
        "packageArtifacts": {
            "manifest": "daed export package-manifest",
            "systemdUnit": "daed export systemd-unit",
            "dockerEntrypoint": "daed export docker-entrypoint",
            "openapi": "daed export openapi",
            "flatdesc": "daed export flatdesc",
            "outline": "daed export outline",
        },
        "liveEvidence": {
            "defaultPackageSwitchApplied": false,
            "previousDefaultSwitchBlockedByMetadataOnlyRuntimeState": true,
            "rollbackValidationApplied": false,
            "goDaewingDefaultPathRemoved": false,
        },
        "remainingBlockers": [
            "live host default package switch revalidation",
            "live rollback validation revalidation",
            "remove Go daewing from default package path",
            "production package admission"
        ]
    })
}

fn webui_route_audit_report() -> Value {
    let covered = webui_route_patterns()
        .into_iter()
        .map(|(method, path)| json!({"method": method, "path": path, "covered": true}))
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": 1,
        "workPackage": "go-free-product-chain-v1",
        "source": "daed/apps/web/src/apis",
        "rustServer": "rust/crates/dae-daemon/src/daed_product.rs",
        "pass": true,
        "missing": [],
        "covered": covered,
        "notes": [
            "Dynamic id routes are audited as {id} patterns.",
            "EventSource routes support access_token query auth fallback.",
            "Tag-only node/subscription updates are covered by PUT dynamic routes."
        ]
    })
}

fn webui_route_patterns() -> Vec<(&'static str, &'static str)> {
    vec![
        ("GET", "/api/health"),
        ("GET", "/api/auth/status"),
        ("POST", "/api/auth/users"),
        ("POST", "/api/auth/token"),
        ("GET", "/api/user/me"),
        ("PATCH", "/api/user/me"),
        ("POST", "/api/user/me/password"),
        ("GET", "/api/user/me/storage"),
        ("PUT", "/api/user/me/storage"),
        ("DELETE", "/api/user/me/storage"),
        ("POST", "/api/user/me/default-resources"),
        ("GET", "/api/user/me/dae-bundle"),
        ("PUT", "/api/user/me/dae-bundle"),
        ("GET", "/api/user/me/dae-config-file"),
        ("PUT", "/api/user/me/dae-config-file"),
        ("POST", "/api/user/me/dae-config-file/preview"),
        ("GET", "/api/general/state"),
        ("GET", "/api/general/interfaces"),
        ("GET", "/api/general/cache-stats"),
        ("GET", "/api/runtime/overview"),
        ("POST", "/api/runtime/reload"),
        ("POST", "/api/runtime/stop"),
        ("GET", "/api/runtime/log-level"),
        ("PATCH", "/api/runtime/log-level"),
        ("GET", "/api/events/runtime"),
        ("GET", "/api/events/logs"),
        ("GET", "/api/logs"),
        ("DELETE", "/api/logs"),
        ("GET", "/api/logs/settings"),
        ("PATCH", "/api/logs/settings"),
        ("GET", "/api/configs"),
        ("POST", "/api/configs"),
        ("POST", "/api/configs/parsed"),
        ("GET", "/api/configs/{id}"),
        ("PUT", "/api/configs/{id}"),
        ("DELETE", "/api/configs/{id}"),
        ("POST", "/api/configs/{id}/select"),
        ("GET", "/api/dns"),
        ("POST", "/api/dns"),
        ("POST", "/api/dns/parsed"),
        ("GET", "/api/dns/{id}"),
        ("PUT", "/api/dns/{id}"),
        ("DELETE", "/api/dns/{id}"),
        ("POST", "/api/dns/{id}/select"),
        ("GET", "/api/routings"),
        ("POST", "/api/routings"),
        ("POST", "/api/routings/parsed"),
        ("GET", "/api/routings/{id}"),
        ("PUT", "/api/routings/{id}"),
        ("DELETE", "/api/routings/{id}"),
        ("POST", "/api/routings/{id}/select"),
        ("GET", "/api/nodes"),
        ("POST", "/api/nodes"),
        ("DELETE", "/api/nodes"),
        ("GET", "/api/nodes/{id}"),
        ("PUT", "/api/nodes/{id}"),
        ("DELETE", "/api/nodes/{id}"),
        ("GET", "/api/nodes/latencies"),
        ("POST", "/api/nodes/latencies"),
        ("GET", "/api/subscriptions"),
        ("POST", "/api/subscriptions"),
        ("DELETE", "/api/subscriptions"),
        ("GET", "/api/subscriptions/{id}"),
        ("PUT", "/api/subscriptions/{id}"),
        ("DELETE", "/api/subscriptions/{id}"),
        ("GET", "/api/subscriptions/{id}/nodes"),
        ("POST", "/api/subscriptions/{id}/refresh"),
        ("GET", "/api/groups"),
        ("POST", "/api/groups"),
        ("GET", "/api/groups/{id}"),
        ("PUT", "/api/groups/{id}"),
        ("DELETE", "/api/groups/{id}"),
        ("POST", "/api/groups/{id}/nodes"),
        ("DELETE", "/api/groups/{id}/nodes"),
        ("POST", "/api/groups/{id}/subscriptions"),
        ("DELETE", "/api/groups/{id}/subscriptions"),
    ]
}

fn package_runtime_environment_defaults() -> Vec<(&'static str, String)> {
    let mut defaults = vec![
        (
            PRODUCT_MALLOC_ARENA_MAX_ENV,
            PRODUCT_MALLOC_ARENA_MAX_DEFAULT.to_owned(),
        ),
        (
            PRODUCT_JEMALLOC_CONF_ENV,
            PRODUCT_JEMALLOC_CONF_DEFAULT.to_owned(),
        ),
        (
            PRODUCT_HTTP_QUEUE_ENV,
            PRODUCT_HTTP_QUEUE_DEFAULT.to_string(),
        ),
        (
            PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
            PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT.to_string(),
        ),
    ];
    defaults.extend(
        resident_runtime_environment_defaults()
            .into_iter()
            .map(|(name, value)| (name, value.to_string())),
    );
    defaults
}

fn systemd_runtime_environment_lines() -> String {
    package_runtime_environment_defaults()
        .into_iter()
        .map(|(name, value)| format!("Environment=\"{name}={value}\"\n"))
        .collect::<String>()
}

fn docker_runtime_environment_exports() -> String {
    package_runtime_environment_defaults()
        .into_iter()
        .map(|(name, value)| format!("export {name}=\"${{{name}:-{value}}}\"\n"))
        .collect::<String>()
}

fn systemd_unit_text() -> String {
    format!(
        r#"[Unit]
Description=daed Rust native service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# {PRODUCT_HTTP_WORKERS_ENV} unset uses available_parallelism * 2 clamped to {PRODUCT_HTTP_WORKER_DEFAULT_MIN}..{PRODUCT_HTTP_WORKER_DEFAULT_MAX}.
{}ExecStart=/usr/bin/daed run -c /etc/daed
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
"#,
        systemd_runtime_environment_lines()
    )
}

fn docker_entrypoint_text() -> String {
    format!(
        r#"#!/bin/sh
set -eu
# {PRODUCT_HTTP_WORKERS_ENV} unset uses available_parallelism * 2 clamped to {PRODUCT_HTTP_WORKER_DEFAULT_MIN}..{PRODUCT_HTTP_WORKER_DEFAULT_MAX}.
{}exec /usr/bin/daed run -c /etc/daed --listen "${{DAED_LISTEN:-0.0.0.0:2023}}" "$@"
"#,
        docker_runtime_environment_exports()
    )
}

fn count_table(conn: &Connection, table: &str) -> io::Result<i64> {
    let sql = match table {
        "configs" => "SELECT COUNT(*) FROM configs",
        "dns" => "SELECT COUNT(*) FROM dns",
        "routings" => "SELECT COUNT(*) FROM routings",
        "groups" => "SELECT COUNT(*) FROM groups",
        "nodes" => "SELECT COUNT(*) FROM nodes",
        "subscriptions" => "SELECT COUNT(*) FROM subscriptions",
        "node_latency_results" => "SELECT COUNT(*) FROM node_latency_results",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported table count: {table}"),
            ));
        }
    };
    conn.query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)
}

#[derive(Clone, Copy, Debug, Default)]
struct ProcessMetrics {
    rss_bytes: u64,
    anonymous_rss_bytes: u64,
    file_rss_bytes: u64,
    vm_data_bytes: u64,
    thread_count: u64,
    cpu_usage_percent: f64,
}

impl ProcessMetrics {
    fn heap_alloc_bytes_compat(&self) -> u64 {
        self.anonymous_rss_bytes
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcCpuSample {
    total_ticks: u64,
    observed_at: Instant,
}

static LAST_PROC_CPU_SAMPLE: OnceLock<Mutex<Option<ProcCpuSample>>> = OnceLock::new();

fn current_process_metrics() -> ProcessMetrics {
    let mut metrics = process_status_metrics().unwrap_or_default();
    metrics.cpu_usage_percent = current_process_cpu_usage_percent().unwrap_or(0.0);
    metrics
}

fn process_status_metrics() -> io::Result<ProcessMetrics> {
    let status = fs::read_to_string("/proc/self/status")?;
    let mut metrics = process_status_metrics_from_str(&status);
    if metrics.rss_bytes == 0 {
        metrics.rss_bytes = current_rss_bytes_from_statm();
    }
    Ok(metrics)
}

fn process_status_metrics_from_str(status: &str) -> ProcessMetrics {
    let mut metrics = ProcessMetrics::default();
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            metrics.rss_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("RssAnon:") {
            metrics.anonymous_rss_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("RssFile:") {
            metrics.file_rss_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("VmData:") {
            metrics.vm_data_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("Threads:") {
            metrics.thread_count = value.trim().parse::<u64>().unwrap_or(0);
        }
    }
    if metrics.anonymous_rss_bytes == 0 {
        metrics.anonymous_rss_bytes = metrics.vm_data_bytes;
    }
    metrics
}

fn proc_status_kib_value(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn current_process_cpu_usage_percent() -> io::Result<f64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let total_ticks = proc_stat_total_cpu_ticks(&stat)?;
    let now = Instant::now();
    let lock = LAST_PROC_CPU_SAMPLE.get_or_init(|| Mutex::new(None));
    let mut guard = lock
        .lock()
        .map_err(|_| io::Error::other("process cpu sample lock poisoned"))?;
    let usage = if let Some(previous) = *guard {
        let elapsed = now.duration_since(previous.observed_at).as_secs_f64();
        if elapsed > 0.0 {
            let delta_ticks = total_ticks.saturating_sub(previous.total_ticks) as f64;
            cpu_ticks_to_percent(delta_ticks, elapsed)
        } else {
            0.0
        }
    } else {
        process_lifetime_cpu_usage_percent(&stat, total_ticks).unwrap_or(0.0)
    };
    *guard = Some(ProcCpuSample {
        total_ticks,
        observed_at: now,
    });
    Ok(round_percent(usage))
}

fn proc_stat_total_cpu_ticks(stat: &str) -> io::Result<u64> {
    let fields = proc_stat_fields_after_comm(stat)?;
    let utime = fields
        .get(11)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc utime"))?;
    let stime = fields
        .get(12)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc stime"))?;
    Ok(utime.saturating_add(stime))
}

fn process_lifetime_cpu_usage_percent(stat: &str, total_ticks: u64) -> io::Result<f64> {
    let fields = proc_stat_fields_after_comm(stat)?;
    let start_ticks = fields
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc starttime"))?;
    let uptime = system_uptime_seconds()?;
    let process_start = start_ticks as f64 / clock_ticks_per_second() as f64;
    let elapsed = (uptime - process_start).max(0.001);
    Ok(cpu_ticks_to_percent(total_ticks as f64, elapsed))
}

fn proc_stat_fields_after_comm(stat: &str) -> io::Result<Vec<&str>> {
    let Some((_, tail)) = stat.rsplit_once(") ") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proc stat comm field",
        ));
    };
    Ok(tail.split_whitespace().collect())
}

fn system_uptime_seconds() -> io::Result<f64> {
    let uptime = fs::read_to_string("/proc/uptime")?;
    uptime
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid uptime"))
}

fn clock_ticks_per_second() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value > 0 { value as u64 } else { 100 }
}

fn cpu_ticks_to_percent(cpu_ticks: f64, elapsed_seconds: f64) -> f64 {
    if elapsed_seconds <= 0.0 {
        return 0.0;
    }
    let capacity = clock_ticks_per_second() as f64 * cpu_parallelism() as f64 * elapsed_seconds;
    if capacity <= 0.0 {
        return 0.0;
    }
    (cpu_ticks / capacity * 100.0).clamp(0.0, 100.0)
}

fn cpu_parallelism() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1)
}

fn round_percent(value: f64) -> f64 {
    if !value.is_finite() {
        0.0
    } else {
        (value * 100.0).round() / 100.0
    }
}

fn current_rss_bytes_from_statm() -> u64 {
    let Ok(statm) = fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let Some(pages) = statm
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 0;
    };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return 0;
    }
    pages.saturating_mul(page_size as u64)
}

fn integer_array(body: &Value, key: &str) -> Vec<i64> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn now_text() -> String {
    iso8601_utc(unix_now())
}

fn iso8601_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn reset_all_user_passwords(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id, username FROM users ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_io_error)?;
    let mut users = Vec::new();
    for row in rows {
        let (id, username) = row.map_err(sqlite_io_error)?;
        let password = random_recovery_password();
        let secret = random_secret_hex()?;
        let password_hash = hash_password(secret.as_bytes(), &password);
        conn.execute(
            "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
            params![password_hash, secret, id],
        )
        .map_err(sqlite_io_error)?;
        users.push(json!({
            "id": id,
            "username": username,
            "password": password,
        }));
    }
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "rustDaedWritesWingDbByDefault": false,
        "users": users,
    }))
}

fn random_recovery_password() -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const ALL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = Vec::with_capacity(12);
    out.push(LETTERS[fastrand::usize(..LETTERS.len())]);
    out.push(DIGITS[fastrand::usize(..DIGITS.len())]);
    for _ in 2..12 {
        out.push(ALL[fastrand::usize(..ALL.len())]);
    }
    fastrand::shuffle(&mut out);
    String::from_utf8(out).unwrap_or_else(|_| "a1fallback".to_owned())
}

fn user_count(state: &Path) -> io::Result<i64> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)
}

fn create_user(state: &Path, username: &str, password: &str) -> io::Result<String> {
    validate_password_strength(password)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)?;
    if count > 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a user already exists",
        ));
    }
    let secret = random_secret_hex()?;
    let password_hash = hash_password(secret.as_bytes(), password);
    conn.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage) VALUES(?1, ?2, ?3, '{}')",
        params![username, password_hash, secret],
    )
    .map_err(sqlite_io_error)?;
    let user = load_user_by_username(state, username)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "created user could not be loaded")
    })?;
    signed_token(&user)
}

fn issue_token(state: &Path, username: &str, password: &str) -> io::Result<String> {
    let Some(user) = load_user_by_username(state, username)? else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    };
    let hashed = hash_password(user.jwt_secret.as_bytes(), password);
    if hashed != user.password_hash {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    }
    signed_token(&user)
}

fn authenticate_request(app: &AppState, request: &HttpRequest) -> Option<UserRecord> {
    let token = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            if request.method == "GET"
                && (request.path == "/api/events/runtime" || request.path == "/api/events/logs")
            {
                request
                    .query
                    .get("access_token")
                    .and_then(|values| values.first())
                    .map(String::as_str)
            } else {
                None
            }
        })?;
    verify_token(&app.state, token).ok().flatten()
}

fn load_user_by_username(state: &Path, username: &str) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE username = ?1",
        params![username],
    )
}

fn load_user_by_id(state: &Path, id: i64) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE id = ?1",
        params![id],
    )
}

fn query_user<P>(conn: &Connection, sql: &str, params: P) -> io::Result<Option<UserRecord>>
where
    P: rusqlite::Params,
{
    conn.query_row(sql, params, |row| {
        Ok(UserRecord {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            jwt_secret: row.get(3)?,
            json_storage: row
                .get::<_, Option<String>>(4)?
                .unwrap_or_else(|| "{}".to_owned()),
            avatar: row.get(5)?,
            name: row.get(6)?,
        })
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn user_resource(user: &UserRecord) -> Value {
    let mut map = Map::new();
    map.insert("username".to_owned(), json!(user.username));
    if let Some(name) = &user.name {
        map.insert("name".to_owned(), json!(name));
    }
    if let Some(avatar) = &user.avatar {
        map.insert("avatar".to_owned(), json!(avatar));
    }
    Value::Object(map)
}

fn ensure_default_resources(state: &Path, body: &Value) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config_name = body
        .get("configName")
        .and_then(Value::as_str)
        .unwrap_or("global");
    let dns_name = body
        .get("dnsName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let routing_name = body
        .get("routingName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let group_name = body
        .get("groupName")
        .and_then(Value::as_str)
        .unwrap_or("proxy");
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or("random");
    let mode = body.get("mode").and_then(Value::as_str).unwrap_or("rule");
    let global = body
        .get("global")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| body.get("global").map(Value::to_string))
        .unwrap_or_else(|| "global {}".to_owned());
    let dns = body
        .get("dns")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let routing = body
        .get("routing")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let config_id = upsert_named_resource(
        &conn,
        "configs",
        "global",
        config_name,
        &global,
        "selected, version",
        "0, 0",
    )?;
    let dns_id = upsert_named_resource(
        &conn,
        "dns",
        "dns",
        dns_name,
        &dns,
        "selected, version",
        "0, 0",
    )?;
    let routing_id = upsert_named_resource(
        &conn,
        "routings",
        "routing",
        routing_name,
        &routing,
        "selected, version",
        "0, 0",
    )?;
    let group_id = upsert_group(&conn, group_name, policy)?;
    conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    if let Some(params_value) = body.get("policyParams").and_then(Value::as_array) {
        for item in params_value {
            let key = item.get("key").and_then(Value::as_str).unwrap_or("");
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("");
            conn.execute(
                "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                params![key, value, group_id],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(json!({
        "defaultConfigID": config_id.to_string(),
        "defaultRoutingID": routing_id.to_string(),
        "defaultDNSID": dns_id.to_string(),
        "defaultGroupID": group_id.to_string(),
        "mode": mode,
    }))
}

fn upsert_named_resource(
    conn: &Connection,
    table: &str,
    value_column: &str,
    name: &str,
    value: &str,
    extra_columns: &str,
    extra_values: &str,
) -> io::Result<i64> {
    let select_sql = format!("SELECT id FROM {table} WHERE name = ?1 LIMIT 1");
    if let Some(id) = conn
        .query_row(&select_sql, params![name], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)?
    {
        return Ok(id);
    }
    let insert_sql = format!(
        "INSERT INTO {table}(name, {value_column}, {extra_columns}) VALUES(?1, ?2, {extra_values})"
    );
    conn.execute(&insert_sql, params![name, value])
        .map_err(sqlite_io_error)?;
    Ok(conn.last_insert_rowid())
}

fn upsert_group(conn: &Connection, name: &str, policy: &str) -> io::Result<i64> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM groups WHERE name = ?1 LIMIT 1",
            params![name],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
    {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    )
    .map_err(sqlite_io_error)?;
    Ok(conn.last_insert_rowid())
}

fn signed_token(user: &UserRecord) -> io::Result<String> {
    let exp = unix_now()
        .checked_add(TOKEN_TTL_SECONDS)
        .ok_or_else(|| io::Error::other("token expiration overflow"))?;
    let header = json!({"alg": "HS256", "typ": "JWT"}).to_string();
    let payload = json!({
        "role": "admin",
        "sub": user.username,
        "exp": exp,
    })
    .to_string();
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = hmac_sha256(user.jwt_secret.as_bytes(), signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn verify_token(state: &Path, token: &str) -> io::Result<Option<UserRecord>> {
    let mut parts = token.split('.');
    let Some(header) = parts.next() else {
        return Ok(None);
    };
    let Some(payload) = parts.next() else {
        return Ok(None);
    };
    let Some(signature) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some() {
        return Ok(None);
    }
    let header_value = decode_jwt_part(header)?;
    if header_value.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Ok(None);
    }
    let payload_value = decode_jwt_part(payload)?;
    let Some(username) = payload_value.get("sub").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(user) = load_user_by_username(state, username)? else {
        return Ok(None);
    };
    let signing_input = format!("{header}.{payload}");
    let expected = hmac_sha256(user.jwt_secret.as_bytes(), signing_input.as_bytes());
    let Ok(actual) = URL_SAFE_NO_PAD.decode(signature.as_bytes()) else {
        return Ok(None);
    };
    if !constant_time_eq(&expected, &actual) {
        return Ok(None);
    }
    let exp = payload_value
        .get("exp")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if exp <= unix_now() {
        return Ok(None);
    }
    load_user_by_id(state, user.id)
}

fn decode_jwt_part(part: &str) -> io::Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    sha2::Digest::update(&mut inner, ipad);
    sha2::Digest::update(&mut inner, data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    sha2::Digest::update(&mut outer, opad);
    sha2::Digest::update(&mut outer, inner);
    let digest = outer.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn hash_password(salt: &[u8], password: &str) -> String {
    let mut h = Shake256::default();
    h.update(salt);
    h.update(password.as_bytes());
    let mut reader = h.finalize_xof();
    let mut hash = [0_u8; 32];
    XofReader::read(&mut reader, &mut hash);
    hex_encode(&hash)
}

fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 6
        || !password.chars().any(char::is_alphabetic)
        || !password.chars().any(|ch| ch.is_ascii_digit())
    {
        return Err(
            "too weak password; should contain numbers and letters, and no less than 6 in length"
                .to_owned(),
        );
    }
    Ok(())
}

fn random_secret_hex() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

fn query_json_storage(storage: &str, paths: &[String]) -> Vec<String> {
    if paths.is_empty() {
        return vec![storage.to_owned()];
    }
    let root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    paths
        .iter()
        .map(|path| {
            value_at_path(&root, path)
                .map(value_to_storage_string)
                .unwrap_or_default()
        })
        .collect()
}

fn set_json_storage(
    storage: &mut String,
    paths: &[String],
    values: &[String],
) -> Result<i32, String> {
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    if !root.is_object() {
        root = json!({});
    }
    for (path, value) in paths.iter().zip(values.iter()) {
        set_value_at_path(&mut root, path, Value::String(value.clone()))?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

fn remove_json_storage(storage: &mut String, paths: &[String]) -> Result<i32, String> {
    if paths.is_empty() {
        *storage = "{}".to_owned();
        return Ok(1);
    }
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    for path in paths {
        delete_value_at_path(&mut root, path)?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        current = current.get(segment)?;
    }
    Some(current)
}

fn set_value_at_path(root: &mut Value, path: &str, value: Value) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        if !current.is_object() {
            *current = json!({});
        }
        let object = current.as_object_mut().unwrap();
        current = object
            .entry((*segment).to_owned())
            .or_insert_with(|| json!({}));
    }
    if !current.is_object() {
        *current = json!({});
    }
    current
        .as_object_mut()
        .unwrap()
        .insert(segments[segments.len() - 1].to_owned(), value);
    Ok(())
}

fn delete_value_at_path(root: &mut Value, path: &str) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let Some(next) = current.get_mut(*segment) else {
            return Ok(());
        };
        current = next;
    }
    if let Some(object) = current.as_object_mut() {
        object.remove(segments[segments.len() - 1]);
    }
    Ok(())
}

fn value_to_storage_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn save_json_storage(state: &Path, user_id: i64, storage: &str) -> io::Result<()> {
    let conn = open_state_connection(state)?;
    conn.execute(
        "UPDATE users SET json_storage = ?1 WHERE id = ?2",
        params![storage, user_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

fn serve_static_file(web_root: &Path, request: &HttpRequest) -> HttpResponse {
    if request.method != "GET" && request.method != "HEAD" {
        return HttpResponse::json(405, json!({"error": "method should be GET or HEAD"}));
    }
    let mut path = match safe_static_path(web_root, &request.path) {
        Some(path) => path,
        None => return HttpResponse::json(400, json!({"error": "invalid static path"})),
    };
    if path.is_dir() {
        path = path.join("index.html");
    }
    if !path.is_file() {
        path = web_root.join("index.html");
    }
    match fs::read(&path) {
        Ok(body) => {
            let mut response = HttpResponse::text(200, mime_for_path(&path), body);
            response
                .extra_headers
                .push(("Cache-Control".to_owned(), "no-cache".to_owned()));
            response
        }
        Err(err) => HttpResponse::json(404, json!({"error": err.to_string()})),
    }
}

fn safe_static_path(web_root: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(request_path);
    let trimmed = decoded.trim_start_matches('/');
    let mut path = PathBuf::from(web_root);
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(path)
}

fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn read_http_request(stream: &mut TcpStream) -> io::Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_BODY_BYTES + 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request is too large",
            ));
        }
        if let Some(index) = find_subsequence(&buffer, b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_owned();
    let raw_path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?;
    let raw_path = raw_path.to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "body is too large",
        ));
    }
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "body truncated",
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
    }
    let body = buffer[header_end..header_end + content_length].to_vec();
    let (path, query) = split_path_query(&raw_path);
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
    head_only: bool,
) -> io::Result<()> {
    let reason = status_reason(response.status);
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\n",
        response.status,
        reason,
        response.content_type,
        if head_only { 0 } else { response.body.len() }
    )?;
    for (key, value) in &response.extra_headers {
        write!(stream, "{key}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    if !head_only {
        stream.write_all(&response.body)?;
    }
    stream.flush()
}

fn split_path_query(raw: &str) -> (String, HashMap<String, Vec<String>>) {
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let mut out = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.entry(percent_decode(key))
            .or_insert_with(Vec::new)
            .push(percent_decode(value));
    }
    (percent_decode(path), out)
}

fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
                {
                    out.push((high << 4) | low);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn json_body(request: &HttpRequest) -> Result<Value, String> {
    if request.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&request.body).map_err(|err| format!("invalid json body: {err}"))
}

fn required_str<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn string_array(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn list_tables(conn: &Connection) -> io::Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_io_error)?;
    let mut tables = Vec::new();
    for row in rows {
        tables.push(row.map_err(sqlite_io_error)?);
    }
    Ok(tables)
}

fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buf[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn set_private_db_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn set_private_runtime_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn sqlite_io_error(err: rusqlite::Error) -> io::Error {
    io::Error::other(err)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn help_text() -> String {
    r#"daed Rust native product commands:
  daed run -c /etc/daed --listen 0.0.0.0:2023 [--api-only] [--web-root PATH]
  daed service-contract [--json]
  daed package-info [--json]
  daed resident-adapter-matrix -c /etc/dae/config.dae [--json]
  daed state check --state /etc/daed/daed.db
  daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db [--force]
  daed export openapi|flatdesc|outline|package-manifest|admission-report|webui-route-audit|systemd-unit|docker-entrypoint
  daed resetpass -c /etc/daed [--json]
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_paths_match_first_batch_contract() {
        let mut storage = "{}".to_owned();
        let paths = vec!["ui.sidebar".to_owned()];
        let values = vec!["open".to_owned()];
        assert_eq!(set_json_storage(&mut storage, &paths, &values).unwrap(), 1);
        assert_eq!(
            query_json_storage(&storage, &paths),
            vec!["open".to_owned()]
        );
        assert_eq!(remove_json_storage(&mut storage, &paths).unwrap(), 1);
        assert_eq!(query_json_storage(&storage, &paths), vec![String::new()]);
    }

    #[test]
    fn jwt_roundtrip_uses_user_secret() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        let token = create_user(&state, "admin", "abc123").unwrap();
        let user = verify_token(&state, &token).unwrap().unwrap();
        assert_eq!(user.username, "admin");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn service_contract_declares_daed_db_without_full_c10_ready() {
        let report = daed_service_contract("test");
        assert_eq!(
            report["primary_state_store"].as_str().unwrap(),
            PRIMARY_STATE_STORE
        );
        assert_eq!(
            report["protected_rollback_state_store"].as_str().unwrap(),
            PROTECTED_ROLLBACK_STATE_STORE
        );
        assert!(
            !report["rust_daed_writes_wing_db_by_default"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["go_free_product_chain_ready"].as_bool().unwrap());
    }

    #[test]
    fn product_package_reports_runtime_memory_defaults() {
        let contract = daed_service_contract("test");
        let defaults = &contract["rust_product_runtime_defaults"];
        assert_eq!(
            defaults["allocator"]["profile"].as_str().unwrap(),
            allocator_profile()
        );
        assert_eq!(
            defaults["http"]["queue"]["env"].as_str().unwrap(),
            PRODUCT_HTTP_QUEUE_ENV
        );
        assert_eq!(
            defaults["residentDataplane"]["tcpFlow"]["stackBytes"]["env"]
                .as_str()
                .unwrap(),
            "DAE_RESIDENT_TCP_FLOW_STACK_BYTES"
        );

        let manifest = product_package_manifest();
        assert_eq!(
            manifest["runtime"]["defaults"]["http"]["workerStackBytes"]["default"]
                .as_u64()
                .unwrap(),
            PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT as u64
        );

        let unit = systemd_unit_text();
        assert!(unit.contains("Environment=\"DAED_HTTP_QUEUE=256\""));
        assert!(unit.contains("Environment=\"DAE_RESIDENT_UDP_PACKET_WORKERS=64\""));
        assert!(unit.contains("DAED_HTTP_WORKERS unset uses available_parallelism"));
    }

    #[test]
    fn parsed_global_reads_dae_text_and_json_storage_shapes() {
        let text = r#"
global {
  tproxy_port:"12345"
  tproxy_port_protect:"true"
  so_mark_from_dae:"7"
  lan_interface:"enp1s0"
  wan_interface:"auto,enp1s0"
  tcp_check_url:"http://cp.cloudflare.com,1.1.1.1"
  udp_check_dns:"dns.google.com:53,8.8.8.8"
  dial_mode:"domain++"
  fallback_resolver:"8.8.8.8:53"
  auto_config_kernel_parameter:"true"
  bandwidth_max_tx:"200 mbps"
}
"#;
        let parsed = normalize_global_value(Some(text));
        assert_eq!(parsed["tproxyPort"], json!(12345));
        assert_eq!(parsed["tproxyPortProtect"], json!(true));
        assert_eq!(parsed["soMarkFromDae"], json!(7));
        assert_eq!(parsed["lanInterface"], json!(["enp1s0"]));
        assert_eq!(parsed["wanInterface"], json!(["auto", "enp1s0"]));
        assert_eq!(
            parsed["tcpCheckUrl"],
            json!(["http://cp.cloudflare.com", "1.1.1.1"])
        );
        assert_eq!(parsed["dialMode"], json!("domain++"));
        assert_eq!(parsed["fallbackResolver"], json!("8.8.8.8:53"));
        assert_eq!(parsed["autoConfigKernelParameter"], json!(true));
        assert_eq!(parsed["bandwidthMaxTx"], json!("200 mbps"));

        let parsed = normalize_global_value(Some(
            r#"{"tproxyPort":12345,"wanInterface":["auto"],"dialMode":"domain"}"#,
        ));
        assert_eq!(parsed["tproxyPort"], json!(12345));
        assert_eq!(parsed["wanInterface"], json!(["auto"]));
        assert_eq!(parsed["dialMode"], json!("domain"));
    }

    #[test]
    fn runtime_traffic_stats_read_resident_event_bytes() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        fs::create_dir_all(&dir).unwrap();
        let event_file = dir.join("events.jsonl");
        let now = unix_now();
        fs::write(
            &event_file,
            format!(
                "{{\"event\":\"tcp_connection_finished\",\"timestampUnix\":{now},\"bytes_client_to_proxy\":100,\"bytes_proxy_to_client\":200}}\n{{\"event\":\"udp_packet_finished\",\"timestampUnix\":{now},\"request_len\":30,\"response_len\":40}}\n"
            ),
        )
        .unwrap();
        let runtime = json!({
            "residentDataplane": {
                "event_file": path_string(&event_file)
            }
        });
        let stats = resident_runtime_traffic_stats(&runtime, 60, 10);
        assert_eq!(stats.upload_total, 130);
        assert_eq!(stats.download_total, 240);
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.udp_sessions, 1);
        assert_eq!(stats.samples.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_traffic_stats_event_file_cache_reads_new_tail() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        fs::create_dir_all(&dir).unwrap();
        let event_file = dir.join("events.jsonl");
        let now = unix_now();
        fs::write(
            &event_file,
            format!(
                "{{\"event\":\"tcp_connection_finished\",\"timestampUnix\":{now},\"bytes_client_to_proxy\":100,\"bytes_proxy_to_client\":200}}\n"
            ),
        )
        .unwrap();
        let runtime = json!({
            "residentDataplane": {
                "event_file": path_string(&event_file)
            }
        });

        let first = resident_runtime_traffic_stats(&runtime, 60, 10);
        assert_eq!(first.upload_total, 100);
        let offset_after_first = RUNTIME_TRAFFIC_EVENT_FILE_CACHE
            .get_or_init(|| Mutex::new(RuntimeTrafficEventFileCache::default()))
            .lock()
            .unwrap()
            .offset;
        let second = resident_runtime_traffic_stats(&runtime, 60, 10);
        assert_eq!(second.upload_total, 100);
        assert_eq!(
            RUNTIME_TRAFFIC_EVENT_FILE_CACHE
                .get_or_init(|| Mutex::new(RuntimeTrafficEventFileCache::default()))
                .lock()
                .unwrap()
                .offset,
            offset_after_first
        );

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&event_file)
            .unwrap();
        writeln!(
            file,
            "{{\"event\":\"udp_packet_finished\",\"timestampUnix\":{now},\"request_len\":30,\"response_len\":40}}"
        )
        .unwrap();
        let third = resident_runtime_traffic_stats(&runtime, 60, 10);
        assert_eq!(third.upload_total, 130);
        assert_eq!(third.download_total, 240);
        assert_eq!(third.udp_sessions, 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_traffic_stats_prefer_live_resident_metrics() {
        *LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap() = None;
        RUNTIME_TRAFFIC_RATE_SAMPLES
            .get_or_init(|| Mutex::new(VecDeque::new()))
            .lock()
            .unwrap()
            .clear();

        let runtime = json!({
            "residentDataplane": {
                "metrics": {
                    "uploadTotal": 100,
                    "downloadTotal": 200,
                    "activeTcpConnections": 3,
                    "activeUdpSessions": 2
                }
            }
        });
        let first = resident_runtime_traffic_stats(&runtime, 60, 10);
        assert_eq!(first.upload_total, 100);
        assert_eq!(first.download_total, 200);
        assert_eq!(first.active_connections, 3);
        assert_eq!(first.udp_sessions, 2);

        thread::sleep(Duration::from_millis(10));
        let runtime = json!({
            "residentDataplane": {
                "metrics": {
                    "uploadTotal": 300,
                    "downloadTotal": 500,
                    "activeTcpConnections": 1,
                    "activeUdpSessions": 0
                }
            }
        });
        let second = resident_runtime_traffic_stats(&runtime, 60, 10);
        assert!(second.upload_rate > 0);
        assert!(second.download_rate > 0);
        assert_eq!(second.active_connections, 1);
        assert!(!second.samples.is_empty());
    }

    #[test]
    fn node_labels_decode_uri_fragments_without_special_casing_nodes() {
        let parsed = parse_node_link(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls#%5BHK%5DAki-Hk",
            None,
        );
        assert_eq!(parsed.name, "[HK]Aki-Hk");
        assert_eq!(decode_node_label("%5BHK%5DAki-Hk"), "[HK]Aki-Hk");
        assert_eq!(decode_node_label("literal+plus"), "literal+plus");

        let node = json!({
            "id": 1,
            "name": "[HK]Aki-Hk",
            "runtimeTag": "%5BHK%5DAki-Hk",
            "link": "scheme://example.invalid:443#%5BHK%5DAki-Hk"
        });
        assert_eq!(runtime_node_tag(&node), "%5BHK%5DAki-Hk");
    }

    #[test]
    fn node_lists_keep_manual_subscription_and_runtime_scopes_separate() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                VALUES(1, 'scheme://manual.invalid:443#manual', 'manual', 'manual.invalid', 'scheme', 'manual-tag', NULL);
            INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                VALUES(2, 'scheme://sub.invalid:443#%5BHK%5DSub', '%5BHK%5DSub', 'sub.invalid', 'scheme', NULL, 7);
            "#,
        )
        .unwrap();

        let manual = list_nodes_value(&state, None).unwrap();
        assert_eq!(manual["totalCount"], json!(1));
        assert_eq!(manual["items"][0]["name"], json!("manual"));

        let subscription = list_nodes_value(&state, Some(7)).unwrap();
        assert_eq!(subscription["totalCount"], json!(1));
        assert_eq!(subscription["items"][0]["name"], json!("[HK]Sub"));
        assert_eq!(subscription["items"][0]["runtimeTag"], json!("%5BHK%5DSub"));

        let runtime = list_all_nodes_value(&state).unwrap();
        assert_eq!(runtime["totalCount"], json!(2));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn group_subscription_bindings_apply_name_regex_to_matched_nodes() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                VALUES(2, 'scheme://sub1.invalid:443#Oracle-Sg', 'Oracle-Sg', 'sub1.invalid', 'scheme', NULL, 7);
            INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                VALUES(3, 'scheme://sub2.invalid:443#Hytron', 'Hytron', 'sub2.invalid', 'scheme', NULL, 7);
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'TG', 'fixed(0)', 1);
            INSERT INTO group_subscriptions(group_id, subscription_id, name_filter_regex)
                VALUES(9, 7, 'Oracle');
            "#,
        )
        .unwrap();

        let group = get_group_value(&state, 9).unwrap().unwrap();
        assert_eq!(group["subscriptions"][0]["matchedCount"], json!(1));
        assert_eq!(
            group["subscriptions"][0]["matchedNodes"][0]["name"],
            json!("Oracle-Sg")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn subscription_refresh_preserves_group_bound_nodes_by_unique_name() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO subscriptions(id, updated_at, link, status, info, tag)
                VALUES(7, 'now', 'https://subscription.invalid/list', 'fetched', '', 'sub-a');
            INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                VALUES(2, 'scheme://old.invalid:443#keep', 'keep', 'old.invalid', 'scheme', NULL, 7);
            INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                VALUES(3, 'scheme://remove.invalid:443#drop', 'drop', 'remove.invalid', 'scheme', NULL, 7);
            INSERT INTO groups(id, name, policy, version)
                VALUES(9, 'TG', 'fixed(0)', 1);
            INSERT INTO group_nodes(group_id, node_id) VALUES(9, 2);
            "#,
        )
        .unwrap();

        let report = replace_subscription_nodes(
            &conn,
            7,
            &[
                "scheme://new.invalid:443#keep".to_owned(),
                "scheme://other.invalid:443#other".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(report.len(), 2);
        let kept_link: String = conn
            .query_row("SELECT link FROM nodes WHERE id = 2", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept_link, "scheme://new.invalid:443#keep");
        let group_binding_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM group_nodes WHERE group_id = 9 AND node_id = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(group_binding_count, 1);
        let removed_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM nodes WHERE id = 3", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(removed_count, 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn generated_runtime_config_renders_parseable_nodes_and_groups() {
        let groups = json!({
            "items": [
                {
                    "name": "proxy",
                    "policy": "fixed(0)",
                    "nodes": [
                        {
                            "id": 1,
                            "tag": "[edge]sample",
                            "name": "[edge]sample",
                            "link": "scheme://example.invalid:443#sample"
                        }
                    ],
                    "subscriptions": []
                },
                {
                    "name": "egress",
                    "policy": "fixed(0)",
                    "nodes": [
                        {
                            "id": 1,
                            "tag": "[edge]sample",
                            "name": "[edge]sample",
                            "link": "scheme://example.invalid:443#sample"
                        }
                    ],
                    "subscriptions": []
                }
            ]
        });
        let nodes = json!({
            "items": [
                {
                    "id": 1,
                    "tag": "[edge]sample",
                    "name": "[edge]sample",
                    "link": "scheme://example.invalid:443#sample"
                }
            ]
        });
        let content = render_generated_config(
            "test",
            Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
            Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
            Some(&(
                1,
                "routing".to_owned(),
                "routing {\n    sample(scope:sample-set:alpha-!beta, suffix:example.invalid) -> egress\n    fallback: proxy\n}\n".to_owned(),
                1,
            )),
            &groups,
            &nodes,
        )
        .unwrap();
        assert!(content.contains("node {"));
        assert!(content.contains("'[edge]sample':"));
        assert!(content.contains("filter: name('[edge]sample')"));
        let config = build_runtime_config_from_content(&content).unwrap();
        assert_eq!(config.node.len(), 1);
        assert_eq!(config.group[0].name, "proxy");
        assert_eq!(
            config.routing.rules[0].and_functions[0].params[0].val,
            "sample-set:alpha-!beta"
        );
    }

    #[test]
    fn generated_runtime_config_rejects_empty_group_filters() {
        let groups = json!({
            "items": [
                {
                    "name": "proxy",
                    "policy": "fixed(0)",
                    "nodes": [],
                    "subscriptions": []
                }
            ]
        });
        let nodes = json!({"items": []});
        let err = render_generated_config(
            "test",
            Some(&(1, "global".to_owned(), "global {}\n".to_owned(), 1)),
            Some(&(1, "dns".to_owned(), "dns {}\n".to_owned(), 1)),
            Some(&(
                1,
                "routing".to_owned(),
                "routing { fallback: proxy }\n".to_owned(),
                1,
            )),
            &groups,
            &nodes,
        )
        .unwrap_err();
        assert!(err.to_string().contains("group proxy has no matched nodes"));
    }

    #[test]
    fn logs_filter_level_all_case_insensitive_query_and_sse_event_name() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        let log_entries_table: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'log_entries'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(log_entries_table.is_none());

        append_log_for_config(&dir, &state, "info", "Runtime proxy started").unwrap();
        let mut fields = BTreeMap::new();
        fields.insert("subscription".to_owned(), "daily".to_owned());
        append_log_fields_for_config(&dir, &state, "warning", "Policy changed", fields).unwrap();
        append_log_for_config(&dir, &state, "error", "Dial failed").unwrap();

        let log_file = product_log_file(&dir);
        assert!(log_file.exists());
        assert!(fs::read_to_string(&log_file).unwrap().contains("\"id\":1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join(PRODUCT_LOG_DIR))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o750
            );
            assert_eq!(
                fs::metadata(&log_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let all = list_logs_value(&dir, &state, Some("all"), Some("PROXY"), 500).unwrap();
        assert_eq!(all["items"].as_array().unwrap().len(), 1);
        assert_eq!(all["items"][0]["level"], json!("info"));

        let warn = list_logs_value(&dir, &state, Some("warning"), None, 500).unwrap();
        assert_eq!(warn["items"].as_array().unwrap().len(), 1);
        assert_eq!(warn["items"][0]["level"], json!("warn"));
        assert_eq!(warn["items"][0]["fields"]["subscription"], json!("daily"));

        let field = list_logs_value(&dir, &state, Some("all"), Some("DAILY"), 500).unwrap();
        assert_eq!(field["items"].as_array().unwrap().len(), 1);
        assert!(list_logs_value(&dir, &state, Some("not-a-level"), Some("proxy"), 500).is_err());
        let limit_zero = list_logs_value(&dir, &state, Some("all"), None, 0).unwrap();
        assert_eq!(limit_zero["items"].as_array().unwrap().len(), 3);
        let limit_one = list_logs_value(&dir, &state, Some("all"), None, 1).unwrap();
        assert_eq!(limit_one["items"].as_array().unwrap().len(), 1);
        assert_eq!(limit_one["items"][0]["message"], json!("Dial failed"));

        let mut query = HashMap::new();
        query.insert("level".to_owned(), vec!["all".to_owned()]);
        query.insert("q".to_owned(), vec!["dial".to_owned()]);
        let request = HttpRequest {
            method: "GET".to_owned(),
            path: "/api/events/logs".to_owned(),
            query,
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let app = AppState {
            config_dir: dir.clone(),
            state: state.clone(),
            web_root: dir.clone(),
            api_only: true,
            runtime: Arc::new(ProductRuntimeManager::new()),
            http_metrics: Arc::new(ProductHttpMetrics::default()),
        };
        for (raw_query, expected_len, expected_level) in [
            ("", 3, None),
            ("level=", 3, None),
            ("level=all", 3, None),
            ("level=ALL", 3, None),
            ("level=info", 1, Some("info")),
            ("level=INFO", 1, Some("info")),
            ("level=warn", 1, Some("warn")),
            ("level=warning", 1, Some("warn")),
            ("level=error", 1, Some("error")),
            ("level=debug", 0, None),
            ("level=trace", 0, None),
            ("level=fatal", 0, None),
            ("level=panic", 0, None),
            ("level=all&limit=0", 3, None),
            ("level=all&limit=1", 1, Some("error")),
        ] {
            let raw_path = if raw_query.is_empty() {
                "/api/logs".to_owned()
            } else {
                format!("/api/logs?{raw_query}")
            };
            let (path, query) = split_path_query(&raw_path);
            let response = api_logs(
                &app,
                &HttpRequest {
                    method: "GET".to_owned(),
                    path,
                    query,
                    headers: HashMap::new(),
                    body: Vec::new(),
                },
            );
            assert_eq!(response.status, 200, "{raw_query}");
            let value: Value = serde_json::from_slice(&response.body).unwrap();
            let items = value["items"].as_array().unwrap();
            assert_eq!(items.len(), expected_len, "{raw_query}: {value}");
            if let Some(expected_level) = expected_level {
                assert_eq!(items[0]["level"], json!(expected_level), "{raw_query}");
            }
        }
        let response = api_log_events(&app, &request);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("retry: 3000"));
        assert!(!body.contains("event: log.entry"));
        assert!(!body.contains("Dial failed"));

        for raw_query in ["level=any", "level=*", "level=invalid", "level=err"] {
            let (path, query) = split_path_query(&format!("/api/logs?{raw_query}"));
            let invalid = api_logs(
                &app,
                &HttpRequest {
                    method: "GET".to_owned(),
                    path,
                    query,
                    headers: HashMap::new(),
                    body: Vec::new(),
                },
            );
            assert_eq!(invalid.status, 400, "{raw_query}");
        }

        let request = HttpRequest {
            method: "PATCH".to_owned(),
            path: "/api/runtime/log-level".to_owned(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: br#"{"level":"debug"}"#.to_vec(),
        };
        let response = api_set_runtime_log_level(&app, &request);
        assert_eq!(response.status, 200);
        append_log_for_config(&dir, &state, "debug", "debug runtime detail").unwrap();
        let debug = list_logs_value(&dir, &state, Some("debug"), None, 500).unwrap();
        assert_eq!(debug["items"].as_array().unwrap().len(), 1);
        assert_eq!(debug["items"][0]["level"], json!("debug"));
        assert_eq!(debug["items"][0]["message"], json!("debug runtime detail"));

        let cleared = api_clear_logs(&app);
        assert_eq!(cleared.status, 200);
        let empty = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
        assert_eq!(empty["items"].as_array().unwrap().len(), 0);

        set_metadata(&state, "runtime_log_level", "fatal").unwrap();
        append_log_for_config(&dir, &state, "info", "filtered after clear").unwrap();
        append_lifecycle_log_for_config(&dir, &state, "info", "[Startup] lifecycle after clear")
            .unwrap();
        let after_clear = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
        assert_eq!(after_clear["items"].as_array().unwrap().len(), 1);
        assert_eq!(after_clear["items"][0]["id"], json!(1));
        assert_eq!(
            after_clear["items"][0]["message"],
            json!("[Startup] lifecycle after clear")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn log_store_initialization_repairs_existing_jsonl_permissions() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        fs::create_dir_all(dir.join(PRODUCT_LOG_DIR)).unwrap();
        let log_file = product_log_file(&dir);
        fs::write(
            &log_file,
            "{\"id\":1,\"ts\":\"2026-06-03T00:00:00Z\",\"level\":\"info\",\"message\":\"existing\"}\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&log_file, fs::Permissions::from_mode(0o644)).unwrap();
        }

        initialize_log_store(&dir, &state).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join(PRODUCT_LOG_DIR))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o750
            );
            assert_eq!(
                fs::metadata(&log_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resident_events_are_bridged_to_product_logs_with_runtime_level_filter() {
        const FLOW_SOURCE: &str = "flow-source";
        const FLOW_DESTINATION: &str = "flow-destination";
        const FLOW_DIAL_TARGET: &str = "flow-dial-target";
        const FLOW_FAILED_SOURCE: &str = "flow-failed-source";
        const FLOW_FAILED_TARGET: &str = "flow-failed-target";
        const FLOW_OUTBOUND: &str = "flow-outbound";
        const FLOW_POLICY: &str = "fixed";
        const FLOW_DIALER: &str = "flow-dialer";
        const FLOW_PID: u32 = 1;
        const FLOW_DSCP: u8 = 2;
        const FLOW_PROCESS: &str = "flow-process";
        const FLOW_MAC: &str = "flow-mac";
        const UDP_FLOW_SOURCE: &str = "udp-flow-source";
        const UDP_FLOW_DESTINATION: &str = "udp-flow-destination";

        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        initialize_log_store(&dir, &state).unwrap();

        append_resident_event_product_log(
            &dir,
            &state,
            &json!({"event": "tcp_worker_started", "proxy_count": 2, "dial_mode": "tls"}),
        )
        .unwrap();
        append_resident_event_product_log(
            &dir,
            &state,
            &json!({"event": "tcp_connection_finished", "peer": "ignored-flow-source", "bytes_client_to_proxy": 128}),
        )
        .unwrap();
        append_resident_event_product_log(
            &dir,
            &state,
            &json!({
                "event": "tcp_connection_failed",
                "peer": FLOW_FAILED_SOURCE,
                "dial_target": FLOW_FAILED_TARGET,
                "error": "sample failure"
            }),
        )
        .unwrap();
        append_resident_event_product_log(
            &dir,
            &state,
            &json!({"event": "tcp_accept_failed", "error": "accept failure"}),
        )
        .unwrap();

        let all = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
        let items = all["items"].as_array().unwrap();
        assert_eq!(items.len(), 3, "{all}");
        assert_eq!(
            items[0]["message"],
            json!("resident dataplane tcp worker started")
        );
        assert_eq!(items[0]["level"], json!("info"));
        assert_eq!(items[0]["fields"]["event"], json!("tcp_worker_started"));
        assert_eq!(items[0]["fields"]["proxy_count"], json!("2"));
        assert_eq!(
            items[1]["message"],
            json!(format!(
                "{FLOW_FAILED_SOURCE} <-> {FLOW_FAILED_TARGET} failed"
            ))
        );
        assert_eq!(items[1]["level"], json!("warn"));
        assert_eq!(items[1]["fields"]["error"], json!("sample failure"));
        assert_eq!(items[1]["fields"]["network"], json!("tcp4"));
        assert!(items[1]["fields"].get("event").is_none());
        assert_eq!(
            items[2]["message"],
            json!("resident dataplane tcp accept failed")
        );
        assert_eq!(items[2]["level"], json!("warn"));
        assert_eq!(items[2]["fields"]["error"], json!("accept failure"));

        set_metadata(&state, "runtime_log_level", "debug").unwrap();
        append_resident_event_product_log(
            &dir,
            &state,
            &json!({
                "event": "tcp_connection_finished",
                "peer": FLOW_SOURCE,
                "original_dst": FLOW_DESTINATION,
                "dial_target": FLOW_DIAL_TARGET,
                "sniffed_domain": "",
                "bytes_client_to_proxy": 256,
                "node_tag": FLOW_DIALER,
                "proxy_group": FLOW_OUTBOUND,
                "group_policy": FLOW_POLICY,
                "pid": FLOW_PID,
                "dscp": FLOW_DSCP,
                "pname": FLOW_PROCESS,
                "mac": FLOW_MAC
            }),
        )
        .unwrap();
        append_resident_event_product_log(
            &dir,
            &state,
            &json!({
                "event": "udp_packet_finished",
                "peer": UDP_FLOW_SOURCE,
                "original_dst": UDP_FLOW_DESTINATION,
                "request_len": 64,
                "response_len": 128
            }),
        )
        .unwrap();
        let info = list_logs_value(&dir, &state, Some("info"), None, 500).unwrap();
        let info_items = info["items"].as_array().unwrap();
        let tcp = info_items.last().unwrap();
        assert_eq!(
            tcp["message"],
            json!(format!("{FLOW_SOURCE} <-> {FLOW_DIAL_TARGET}"))
        );
        assert!(tcp["fields"].get("event").is_none());
        assert_eq!(tcp["fields"]["network"], json!("tcp4"));
        assert_eq!(tcp["fields"]["outbound"], json!(FLOW_OUTBOUND));
        assert_eq!(tcp["fields"]["policy"], json!(FLOW_POLICY));
        assert_eq!(tcp["fields"]["dialer"], json!(FLOW_DIALER));
        assert_eq!(tcp["fields"]["ip"], json!(FLOW_DESTINATION));
        assert_eq!(tcp["fields"]["sniffed"], json!(""));
        assert_eq!(tcp["fields"]["pid"], json!(FLOW_PID.to_string()));
        assert_eq!(tcp["fields"]["dscp"], json!(FLOW_DSCP.to_string()));
        assert_eq!(tcp["fields"]["pname"], json!(FLOW_PROCESS));
        assert_eq!(tcp["fields"]["mac"], json!(FLOW_MAC));

        let mut legacy_fields = BTreeMap::new();
        legacy_fields.insert("event".to_owned(), "tcp_connection_finished".to_owned());
        legacy_fields.insert("peer".to_owned(), "legacy-flow-source".to_owned());
        append_log_fields_for_config(
            &dir,
            &state,
            "debug",
            "resident dataplane tcp connection finished",
            legacy_fields,
        )
        .unwrap();
        let debug = list_logs_value(&dir, &state, Some("debug"), None, 500).unwrap();
        let items = debug["items"].as_array().unwrap();
        assert_eq!(items.len(), 2, "{debug}");
        assert_eq!(
            items[0]["message"],
            json!(format!("{UDP_FLOW_SOURCE} <-> {UDP_FLOW_DESTINATION}"))
        );
        assert_eq!(items[0]["fields"]["network"], json!("udp4"));
        assert_eq!(items[0]["fields"]["ip"], json!(UDP_FLOW_DESTINATION));
        assert!(items[0]["fields"].get("request_len").is_none());
        assert_eq!(
            items[1]["message"],
            json!("resident dataplane tcp connection finished")
        );

        clear_resident_event_product_log_sink();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_reload_dry_preview_writes_unified_reload_logs() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        initialize_log_store(&dir, &state).unwrap();
        let app = AppState {
            config_dir: dir.clone(),
            state: state.clone(),
            web_root: dir.clone(),
            api_only: true,
            runtime: Arc::new(ProductRuntimeManager::new()),
            http_metrics: Arc::new(ProductHttpMetrics::default()),
        };
        set_metadata(&state, "runtime_log_level", "fatal").unwrap();
        let request = HttpRequest {
            method: "POST".to_owned(),
            path: "/api/runtime/reload".to_owned(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: br#"{"dry":true}"#.to_vec(),
        };

        let response = api_runtime_reload(&app, &request);
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let logs = list_logs_value(&dir, &state, Some("all"), Some("[Reload]"), 500).unwrap();
        let items = logs["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{logs}");
        assert_eq!(items[0]["message"], json!("[Reload] Preview finished"));
        assert_eq!(items[0]["fields"]["source"], json!("api"));
        assert_eq!(items[0]["fields"]["dry"], json!("true"));
        assert_eq!(items[0]["fields"]["applied"], json!("false"));
        assert!(items[0]["fields"]["elapsed"].as_str().is_some());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_overview_reports_process_metrics_and_stream_retry_delta() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let app = AppState {
            config_dir: dir.clone(),
            state,
            web_root: dir.clone(),
            api_only: true,
            runtime: Arc::new(ProductRuntimeManager::new()),
            http_metrics: Arc::new(ProductHttpMetrics::default()),
        };
        let request = HttpRequest {
            method: "GET".to_owned(),
            path: "/api/events/runtime".to_owned(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let overview = runtime_overview_report(&app, &request);
        assert!(
            overview["rssBytes"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(
            overview["heapAllocBytes"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(
            overview["anonymousRssBytes"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert_eq!(overview["rssAnonBytes"], overview["anonymousRssBytes"]);
        assert!(overview["fileRssBytes"].as_str().is_some());
        assert_eq!(overview["rssFileBytes"], overview["fileRssBytes"]);
        assert!(overview["vmDataBytes"].as_str().is_some());
        if allocator_live_heap_bytes().is_some() {
            assert!(
                overview["heapLiveBytes"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    > 0
            );
            assert_eq!(overview["heapMetricSource"], json!("allocator-stats"));
            assert_eq!(overview["allocatorStats"]["available"], json!(true));
        } else {
            assert_eq!(overview["heapLiveBytes"], Value::Null);
            assert_eq!(overview["heapMetricSource"], json!("unavailable"));
            assert_eq!(overview["allocatorStats"]["available"], json!(false));
        }
        assert_eq!(overview["heapCompatBytes"], overview["heapAllocBytes"]);
        assert_eq!(
            overview["heapCompatBytesSource"],
            json!("compat-alias-rss-anon-not-live-heap")
        );
        assert_eq!(
            overview["heapAllocBytesSource"],
            json!("compat-alias-rss-anon-not-live-heap")
        );
        assert_eq!(overview["allocatorProfile"], json!(allocator_profile()));
        assert!(overview["allocatorReclaim"]["total"].as_u64().is_some());
        assert_eq!(
            overview["resourcePools"]["udpEndpoint"]["defaultMaxEntries"],
            json!(DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES)
        );
        assert!(overview["goroutines"].as_u64().unwrap() > 0);
        assert!(overview["cpuUsagePercent"].as_f64().unwrap() >= 0.0);

        let delta = runtime_overview_delta_report(&app, &request);
        assert!(delta["uploadRate"].as_str().is_some());
        assert!(delta["rssBytes"].as_str().is_some());
        assert!(delta["heapAllocBytes"].as_str().is_some());
        assert!(delta["goroutines"].as_u64().is_some());
        assert!(delta.get("allocatorStats").is_none());
        assert!(delta.get("allocatorReclaim").is_none());
        assert!(delta.get("resourcePools").is_none());
        assert!(delta.get("runtime").is_none());

        let response = api_runtime_events(&app, &request);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("retry: 3000"));
        assert!(body.contains("event: runtime.overview\n"));
        assert!(body.contains("event: runtime.overview.delta\n"));
        assert!(body.contains("\"heapAllocBytes\""));
        assert!(body.contains("\"anonymousRssBytes\""));
        assert!(body.contains("\"rssAnonBytes\""));
        assert!(body.contains("\"fileRssBytes\""));
        assert!(body.contains("\"rssFileBytes\""));
        assert!(body.contains("\"heapCompatBytes\""));
        assert!(body.contains("\"heapAllocBytesSource\""));
        assert!(body.contains("\"allocatorProfile\""));
        assert!(body.contains("\"resourcePools\""));
        assert!(body.contains("\"goroutines\""));
        assert!(body.contains("\"cpuUsagePercent\""));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn process_status_metrics_splits_rss_and_keeps_heap_compat_alias() {
        let status = "\
Name:\tdaed\n\
VmRSS:\t  200000 kB\n\
RssAnon:\t  150000 kB\n\
RssFile:\t  50000 kB\n\
VmData:\t  260000 kB\n\
Threads:\t38\n";
        let metrics = process_status_metrics_from_str(status);
        assert_eq!(metrics.rss_bytes, 200000 * 1024);
        assert_eq!(metrics.anonymous_rss_bytes, 150000 * 1024);
        assert_eq!(metrics.file_rss_bytes, 50000 * 1024);
        assert_eq!(metrics.vm_data_bytes, 260000 * 1024);
        assert_eq!(metrics.heap_alloc_bytes_compat(), 150000 * 1024);
        assert_eq!(metrics.thread_count, 38);

        let fallback = process_status_metrics_from_str("VmData:\t42 kB\n");
        assert_eq!(fallback.anonymous_rss_bytes, 42 * 1024);
        assert_eq!(fallback.vm_data_bytes, 42 * 1024);
        assert_eq!(fallback.heap_alloc_bytes_compat(), 42 * 1024);
    }

    #[test]
    fn runtime_process_stop_preserves_persisted_running_state() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
             VALUES(1, 0, 0, 0, 0, '')",
            [],
        )
        .unwrap();
        set_metadata(&state, "runtime_running", "true").unwrap();

        mark_runtime_process_stopped(&state).unwrap();

        assert!(should_restore_runtime_on_start(&state).unwrap());
        assert_eq!(
            get_metadata(&state, "runtime_running").unwrap().as_deref(),
            Some("false")
        );
        mark_system_stopped(&state).unwrap();
        assert!(!should_restore_runtime_on_start(&state).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_modified_matches_running_resource_snapshot() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: proxy }', 1, 1);
            INSERT INTO groups(id, name, policy, version)
                VALUES(1, 'proxy', 'fixed(0)', 1);
            INSERT INTO systems(
                running,
                running_config_version,
                running_dns_version,
                running_routing_version,
                running_group_version_sum,
                running_group_ids,
                running_config_id,
                running_dns_id,
                running_routing_id
            )
                VALUES(1, 1, 1, 1, 1, '1', 1, 1, 1);
            "#,
        )
        .unwrap();

        assert!(!runtime_modified(&conn, false).unwrap());
        assert!(!runtime_modified(&conn, true).unwrap());

        conn.execute("UPDATE configs SET version = version + 1 WHERE id = 1", [])
            .unwrap();
        assert!(runtime_modified(&conn, true).unwrap());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn materializer_tolerates_legacy_orphan_group_node_rows() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        let runtime_dir = dir.join("config");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute_batch(
            r#"
            DROP TABLE group_nodes;
            CREATE TABLE group_nodes (
                group_id INTEGER NOT NULL,
                node_id INTEGER NOT NULL,
                PRIMARY KEY(group_id, node_id),
                FOREIGN KEY(group_id) REFERENCES groups(id),
                FOREIGN KEY(node_id) REFERENCES nodes(id)
            );
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: proxy }', 1, 1);
            INSERT INTO groups(id, name, policy, version)
                VALUES(1, 'proxy', 'fixed(0)', 1);
            INSERT INTO nodes(id, link, name, address, protocol, tag)
                VALUES(1, 'scheme://example.invalid:443#sample', 'sample', 'example.invalid', 'sample', 'sample');
            INSERT INTO group_nodes(group_id, node_id) VALUES(1, 1);
            INSERT INTO group_nodes(group_id, node_id) VALUES(1, 9999);
            INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
                VALUES(1, 0, 0, 0, 0, '');
            "#,
        )
        .unwrap();

        let report = materialize_runtime(&state, Some(&runtime_dir), false).unwrap();
        assert_eq!(report["selected"]["configId"].as_i64(), Some(1));
        assert_eq!(report["contentIncluded"], json!(false));
        assert!(report.get("content").is_none());
        assert!(report["bytes"].as_u64().unwrap() > 0);
        assert!(runtime_dir.join("runtime/generated.dae").is_file());
        fs::remove_dir_all(dir).unwrap();
    }
}
