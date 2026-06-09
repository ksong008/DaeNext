use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

#[cfg(not(any(feature = "allocator-mimalloc", feature = "allocator-jemalloc")))]
const ALLOCATOR_SYSTEM_TRIM_ENV: &str = "ALLOCATOR_SYSTEM_TRIM";
#[cfg(not(any(feature = "allocator-mimalloc", feature = "allocator-jemalloc")))]
const ALLOCATOR_SYSTEM_TRIM_LEGACY_ENV: &str = "DAED_ALLOCATOR_SYSTEM_TRIM";

#[cfg(all(feature = "allocator-mimalloc", feature = "allocator-jemalloc"))]
compile_error!("allocator-mimalloc and allocator-jemalloc are mutually exclusive");

#[cfg(all(
    feature = "allocator-system",
    any(feature = "allocator-mimalloc", feature = "allocator-jemalloc")
))]
compile_error!("allocator-system cannot be combined with allocator-mimalloc or allocator-jemalloc");

#[cfg(feature = "allocator-mimalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "allocator-jemalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone, Copy, Debug)]
pub enum AllocatorReclaimReason {
    StartupControlBuilt,
    ReloadCompleted,
    StopRuntime,
}

impl AllocatorReclaimReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::StartupControlBuilt => "startup_control_built",
            Self::ReloadCompleted => "reload_completed",
            Self::StopRuntime => "stop_runtime",
        }
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
static STOP_RUNTIME_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static TOTAL_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static LAST_RECLAIM: OnceLock<Mutex<Option<LastAllocatorReclaim>>> = OnceLock::new();

pub fn allocator_profile() -> &'static str {
    if cfg!(feature = "allocator-mimalloc") {
        "mimalloc"
    } else if cfg!(feature = "allocator-jemalloc") {
        "jemalloc"
    } else {
        "system"
    }
}

pub fn allocator_live_heap_bytes() -> Option<u64> {
    allocator_stats_bytes().and_then(|stats| stats.get("allocated").copied())
}

pub fn allocator_stats_json() -> Value {
    match allocator_stats_bytes() {
        Some(stats) => json!({
            "available": true,
            "profile": allocator_profile(),
            "bytes": stats
                .into_iter()
                .map(|(key, value)| (key.to_owned(), json!(value.to_string())))
                .collect::<BTreeMap<_, _>>(),
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
            "stop_runtime": STOP_RUNTIME_RECLAIMS.load(Ordering::Relaxed),
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
        AllocatorReclaimReason::StopRuntime => {
            STOP_RUNTIME_RECLAIMS.fetch_add(1, Ordering::Relaxed);
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

#[cfg(feature = "allocator-mimalloc")]
fn allocator_reclaim_impl() -> (&'static str, Value) {
    unsafe {
        libmimalloc_sys::mi_collect(true);
    }
    ("pass", json!({"operation": "mi_collect", "force": true}))
}

#[cfg(feature = "allocator-jemalloc")]
fn allocator_reclaim_impl() -> (&'static str, Value) {
    use tikv_jemalloc_ctl::{arenas, epoch, raw};

    let narenas = match arenas::narenas::read() {
        Ok(value) => value,
        Err(err) => {
            return (
                "fail",
                json!({
                    "operation": "jemalloc_arena_purge",
                    "error": err.to_string(),
                }),
            );
        }
    };
    let mut failures = Vec::new();
    let mut attempted = 0_u64;
    for arena in 0..narenas {
        attempted += 1;
        let key = format!("arena.{arena}.purge\0");
        let result = unsafe { raw::write::<()>(key.as_bytes(), ()) };
        if let Err(err) = result {
            failures.push(json!({
                "arena": arena,
                "error": err.to_string(),
            }));
        }
    }
    let epoch_after = epoch::advance().ok();
    let status = if failures.is_empty() {
        "pass"
    } else {
        "partial"
    };
    (
        status,
        json!({
            "operation": "jemalloc_arena_purge",
            "arenasAttempted": attempted,
            "failures": failures,
            "epochAfter": epoch_after,
        }),
    )
}

#[cfg(not(any(feature = "allocator-mimalloc", feature = "allocator-jemalloc")))]
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

#[cfg(not(any(feature = "allocator-mimalloc", feature = "allocator-jemalloc")))]
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
    not(any(feature = "allocator-mimalloc", feature = "allocator-jemalloc")),
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
    not(any(feature = "allocator-mimalloc", feature = "allocator-jemalloc")),
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
