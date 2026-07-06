use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

#[cfg(not(feature = "allocator-jemalloc"))]
const ALLOCATOR_SYSTEM_TRIM_ENV: &str = "ALLOCATOR_SYSTEM_TRIM";
#[cfg(not(feature = "allocator-jemalloc"))]
const ALLOCATOR_SYSTEM_TRIM_LEGACY_ENV: &str = "DAED_ALLOCATOR_SYSTEM_TRIM";

#[cfg(all(feature = "allocator-system", feature = "allocator-jemalloc"))]
compile_error!("allocator-system cannot be combined with allocator-jemalloc");

#[cfg(all(test, feature = "allocator-jemalloc"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone, Copy, Debug)]
pub enum AllocatorReclaimReason {
    StartupControlBuilt,
    ReloadCompleted,
    ReloadFailedAfterCleanup,
    StopRuntime,
    IdleMemoryPressure,
    ManualLatencyProbe,
    GroupHealthProbe,
    GeodataUpdate,
}

impl AllocatorReclaimReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::StartupControlBuilt => "startup_control_built",
            Self::ReloadCompleted => "reload_completed",
            Self::ReloadFailedAfterCleanup => "reload_failed_after_cleanup",
            Self::StopRuntime => "stop_runtime",
            Self::IdleMemoryPressure => "idle_memory_pressure",
            Self::ManualLatencyProbe => "manual_latency_probe",
            Self::GroupHealthProbe => "group_health_probe",
            Self::GeodataUpdate => "geodata_update",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AllocatorStatsSnapshot {
    pub allocated: u64,
    pub active: u64,
    pub metadata: u64,
    pub resident: u64,
    pub mapped: u64,
    pub retained: u64,
}

impl AllocatorStatsSnapshot {
    pub fn active_minus_allocated(self) -> u64 {
        self.active.saturating_sub(self.allocated)
    }

    pub fn resident_minus_active(self) -> u64 {
        self.resident.saturating_sub(self.active)
    }

    pub fn rss_anon_minus_allocated(self, anonymous_rss_bytes: u64) -> u64 {
        anonymous_rss_bytes.saturating_sub(self.allocated)
    }

    pub fn idle_reclaim_pressure_bytes(self) -> u64 {
        self.resident_minus_active().max(self.retained)
    }

    fn from_bytes(stats: BTreeMap<&'static str, u64>) -> Option<Self> {
        Some(Self {
            allocated: *stats.get("allocated")?,
            active: *stats.get("active")?,
            metadata: *stats.get("metadata")?,
            resident: *stats.get("resident")?,
            mapped: *stats.get("mapped")?,
            retained: *stats.get("retained")?,
        })
    }

    fn bytes_json(self) -> BTreeMap<&'static str, Value> {
        [
            ("allocated", self.allocated),
            ("active", self.active),
            ("metadata", self.metadata),
            ("resident", self.resident),
            ("mapped", self.mapped),
            ("retained", self.retained),
        ]
        .into_iter()
        .map(|(key, value)| (key, json!(value.to_string())))
        .collect()
    }
}

#[derive(Clone, Debug)]
struct LastAllocatorReclaim {
    reason: &'static str,
    profile: &'static str,
    status: String,
    detail: Value,
}

static STARTUP_CONTROL_BUILT_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static RELOAD_COMPLETED_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static RELOAD_FAILED_AFTER_CLEANUP_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static STOP_RUNTIME_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static IDLE_MEMORY_PRESSURE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static MANUAL_LATENCY_PROBE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static GROUP_HEALTH_PROBE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static GEODATA_UPDATE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static TOTAL_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static LAST_RECLAIM: OnceLock<Mutex<Option<LastAllocatorReclaim>>> = OnceLock::new();

pub fn allocator_profile() -> &'static str {
    if cfg!(feature = "allocator-jemalloc") {
        "jemalloc"
    } else {
        "system"
    }
}

pub fn allocator_live_heap_bytes() -> Option<u64> {
    allocator_stats_snapshot().map(|stats| stats.allocated)
}

pub fn allocator_stats_json_from(snapshot: Option<&AllocatorStatsSnapshot>) -> Value {
    match snapshot {
        Some(stats) => json!({
            "available": true,
            "profile": allocator_profile(),
            "bytes": stats.bytes_json(),
        }),
        None => json!({
            "available": false,
            "profile": allocator_profile(),
        }),
    }
}

pub fn allocator_stats_snapshot() -> Option<AllocatorStatsSnapshot> {
    allocator_stats_bytes().and_then(AllocatorStatsSnapshot::from_bytes)
}

pub fn allocator_derived_stats_json_from(
    snapshot: Option<&AllocatorStatsSnapshot>,
    anonymous_rss_bytes: u64,
) -> Value {
    match snapshot {
        Some(stats) => json!({
            "available": true,
            "profile": allocator_profile(),
            "bytes": {
                "activeMinusAllocated": stats.active_minus_allocated().to_string(),
                "residentMinusActive": stats.resident_minus_active().to_string(),
                "retained": stats.retained.to_string(),
                "rssAnonMinusAllocated": stats.rss_anon_minus_allocated(anonymous_rss_bytes).to_string(),
                "idleReclaimPressure": stats.idle_reclaim_pressure_bytes().to_string(),
            },
        }),
        None => json!({
            "available": false,
            "profile": allocator_profile(),
        }),
    }
}

pub fn allocator_reclaim(reason: AllocatorReclaimReason) -> Value {
    increment_reason_counter(reason);
    TOTAL_RECLAIMS.fetch_add(1, Ordering::Relaxed);

    let (status, detail) = allocator_reclaim_impl();
    let report = LastAllocatorReclaim {
        reason: reason.as_str(),
        profile: allocator_profile(),
        status: status.to_owned(),
        detail,
    };
    if let Ok(mut guard) = LAST_RECLAIM.get_or_init(|| Mutex::new(None)).lock() {
        *guard = Some(report.clone());
    }
    last_allocator_reclaim_json(&report)
}

pub fn allocator_reclaim_snapshot_json() -> Value {
    let last = LAST_RECLAIM
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|guard| guard.clone());
    json!({
        "profile": allocator_profile(),
        "total": TOTAL_RECLAIMS.load(Ordering::Relaxed),
        "reasons": {
            "startup_control_built": STARTUP_CONTROL_BUILT_RECLAIMS.load(Ordering::Relaxed),
            "reload_completed": RELOAD_COMPLETED_RECLAIMS.load(Ordering::Relaxed),
            "reload_failed_after_cleanup": RELOAD_FAILED_AFTER_CLEANUP_RECLAIMS.load(Ordering::Relaxed),
            "stop_runtime": STOP_RUNTIME_RECLAIMS.load(Ordering::Relaxed),
            "idle_memory_pressure": IDLE_MEMORY_PRESSURE_RECLAIMS.load(Ordering::Relaxed),
            "manual_latency_probe": MANUAL_LATENCY_PROBE_RECLAIMS.load(Ordering::Relaxed),
            "group_health_probe": GROUP_HEALTH_PROBE_RECLAIMS.load(Ordering::Relaxed),
            "geodata_update": GEODATA_UPDATE_RECLAIMS.load(Ordering::Relaxed),
        },
        "last": last.as_ref().map(last_allocator_reclaim_json),
    })
}

fn increment_reason_counter(reason: AllocatorReclaimReason) {
    match reason {
        AllocatorReclaimReason::StartupControlBuilt => {
            STARTUP_CONTROL_BUILT_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::ReloadCompleted => {
            RELOAD_COMPLETED_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::ReloadFailedAfterCleanup => {
            RELOAD_FAILED_AFTER_CLEANUP_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::StopRuntime => {
            STOP_RUNTIME_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::IdleMemoryPressure => {
            IDLE_MEMORY_PRESSURE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::ManualLatencyProbe => {
            MANUAL_LATENCY_PROBE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::GroupHealthProbe => {
            GROUP_HEALTH_PROBE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::GeodataUpdate => {
            GEODATA_UPDATE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
    };
}

fn last_allocator_reclaim_json(reclaim: &LastAllocatorReclaim) -> Value {
    json!({
        "reason": reclaim.reason,
        "profile": reclaim.profile,
        "status": reclaim.status,
        "detail": reclaim.detail,
    })
}

#[cfg(feature = "allocator-jemalloc")]
fn allocator_reclaim_impl() -> (&'static str, Value) {
    use tikv_jemalloc_ctl::{arenas, epoch, raw};

    let epoch_before = epoch::advance().ok();
    let (thread_cache_flush_ok, thread_cache_flush) =
        match jemalloc_void_mallctl(b"thread.tcache.flush\0") {
            Ok(()) => (true, json!({"status": "pass"})),
            Err(err) => (
                false,
                json!({
                    "status": "fail",
                    "error": err,
                }),
            ),
        };
    let narenas = match arenas::narenas::read() {
        Ok(value) => value,
        Err(err) => {
            return (
                "fail",
                json!({
                    "operation": "jemalloc_arena_purge",
                    "threadCacheFlush": thread_cache_flush,
                    "error": err.to_string(),
                }),
            );
        }
    };
    let mut failures = Vec::new();
    let mut skipped = 0_u64;
    let mut attempted = 0_u64;
    for arena in 0..narenas {
        let initialized_key = format!("arena.{arena}.initialized\0");
        match unsafe { raw::read::<bool>(initialized_key.as_bytes()) } {
            Ok(true) => {}
            Ok(false) => {
                skipped += 1;
                continue;
            }
            Err(err) => {
                failures.push(json!({
                    "arena": arena,
                    "step": "read_initialized",
                    "error": err.to_string(),
                }));
                continue;
            }
        }

        attempted += 1;
        let key = format!("arena.{arena}.purge\0");
        if let Err(err) = jemalloc_void_mallctl(key.as_bytes()) {
            failures.push(json!({
                "arena": arena,
                "step": "purge",
                "error": err,
            }));
        }
    }
    let epoch_after = epoch::advance().ok();
    let status = if failures.is_empty() && thread_cache_flush_ok {
        "pass"
    } else {
        "partial"
    };
    (
        status,
        json!({
            "operation": "jemalloc_thread_tcache_flush_and_arena_purge",
            "threadCacheFlush": thread_cache_flush,
            "arenasObserved": narenas,
            "arenasAttempted": attempted,
            "arenasSkipped": skipped,
            "failures": failures,
            "epochBefore": epoch_before,
            "epochAfter": epoch_after,
        }),
    )
}

#[cfg(feature = "allocator-jemalloc")]
fn jemalloc_void_mallctl(name: &[u8]) -> Result<(), String> {
    use std::os::raw::c_char;
    use std::ptr;

    if !name.ends_with(&[0]) {
        return Err("mallctl name must be null-terminated".to_owned());
    }

    let rc = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr().cast::<c_char>(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(jemalloc_mallctl_error(rc))
    }
}

#[cfg(feature = "allocator-jemalloc")]
fn jemalloc_mallctl_error(rc: i32) -> String {
    let err = std::io::Error::from_raw_os_error(rc);
    format!("mallctl returned {rc}: {err}")
}

#[cfg(not(feature = "allocator-jemalloc"))]
fn allocator_reclaim_impl() -> (&'static str, Value) {
    if !system_allocator_trim_enabled() {
        return (
            "skipped",
            json!({
                "operation": "system_allocator_noop",
                "reason": format!(
                    "system allocator trim is disabled; set {ALLOCATOR_SYSTEM_TRIM_ENV}=1 for an explicit diagnostic trim"
                ),
            }),
        );
    }
    system_allocator_trim()
}

#[cfg(not(feature = "allocator-jemalloc"))]
fn system_allocator_trim_enabled() -> bool {
    std::env::var(ALLOCATOR_SYSTEM_TRIM_ENV)
        .or_else(|_| std::env::var(ALLOCATOR_SYSTEM_TRIM_LEGACY_ENV))
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES"
            )
        })
        .unwrap_or(false)
}

#[cfg(all(
    not(feature = "allocator-jemalloc"),
    target_os = "linux",
    target_env = "gnu"
))]
fn system_allocator_trim() -> (&'static str, Value) {
    let result = unsafe { libc::malloc_trim(0) };
    (
        "pass",
        json!({
            "operation": "malloc_trim",
            "result": result,
        }),
    )
}

#[cfg(all(
    not(feature = "allocator-jemalloc"),
    not(all(target_os = "linux", target_env = "gnu"))
))]
fn system_allocator_trim() -> (&'static str, Value) {
    (
        "unsupported",
        json!({
            "operation": "malloc_trim",
            "reason": "malloc_trim is only available on Linux glibc targets",
        }),
    )
}

#[cfg(feature = "allocator-jemalloc")]
fn allocator_stats_bytes() -> Option<BTreeMap<&'static str, u64>> {
    use tikv_jemalloc_ctl::{epoch, stats};

    let _ = epoch::advance();
    let mut values = BTreeMap::new();
    values.insert("allocated", stats::allocated::read().ok()? as u64);
    values.insert("active", stats::active::read().ok()? as u64);
    values.insert("metadata", stats::metadata::read().ok()? as u64);
    values.insert("resident", stats::resident::read().ok()? as u64);
    values.insert("mapped", stats::mapped::read().ok()? as u64);
    values.insert("retained", stats::retained::read().ok()? as u64);
    Some(values)
}

#[cfg(not(feature = "allocator-jemalloc"))]
fn allocator_stats_bytes() -> Option<BTreeMap<&'static str, u64>> {
    None
}
