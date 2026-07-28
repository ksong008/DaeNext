use super::*;
use std::sync::{Mutex, OnceLock, TryLockError};

static ALLOCATOR_RECLAIM_GATE: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) fn allocator_reclaim_impl() -> (&'static str, Value) {
    let gate = ALLOCATOR_RECLAIM_GATE.get_or_init(|| Mutex::new(()));
    let _guard = match gate.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => {
            return (
                "coalesced",
                json!({
                    "operation": "allocator_reclaim_gate",
                    "reason": "reclaim_in_progress",
                }),
            );
        }
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
    };
    allocator_reclaim_backend()
}

#[cfg(feature = "allocator-jemalloc")]
fn allocator_reclaim_backend() -> (&'static str, Value) {
    use tikv_jemalloc_ctl::epoch;

    let epoch_before = epoch::advance().ok();
    let (thread_cache_flush_ok, thread_cache_flush) =
        cooperative::allocator_flush_registered_worker_caches();
    let narenas = match mallctl::read_u32(b"arenas.narenas\0") {
        Ok(value) => value,
        Err(err) => {
            return (
                "fail",
                json!({
                    "operation": "jemalloc_arena_purge",
                    "threadCacheFlush": thread_cache_flush,
                    "workerCacheFlush": thread_cache_flush,
                    "threadCacheScope": "registered-workers-and-calling-thread",
                    "arenaPurgeScope": "all-initialized-arenas",
                    "error": err,
                }),
            );
        }
    };
    let mut failures = Vec::new();
    let mut skipped = 0_u64;
    let mut attempted = 0_u64;
    for arena in 0..narenas {
        let initialized_key = format!("arena.{arena}.initialized\0");
        match mallctl::read_bool(initialized_key.as_bytes()) {
            Ok(true) => {}
            Ok(false) => {
                skipped = skipped.saturating_add(1);
                continue;
            }
            Err(error) => {
                failures.push(json!({
                    "arena": arena,
                    "step": "read_initialized",
                    "error": error,
                }));
                continue;
            }
        }

        attempted = attempted.saturating_add(1);
        let key = format!("arena.{arena}.purge\0");
        if let Err(error) = mallctl::command(key.as_bytes()) {
            failures.push(json!({
                "arena": arena,
                "step": "purge",
                "error": error,
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
            "workerCacheFlush": thread_cache_flush,
            "threadCacheScope": "registered-workers-and-calling-thread",
            "arenaPurgeScope": "all-initialized-arenas",
            "arenasObserved": narenas,
            "arenasAttempted": attempted,
            "arenasSkipped": skipped,
            "failures": failures,
            "epochBefore": epoch_before,
            "epochAfter": epoch_after,
        }),
    )
}

#[cfg(all(test, feature = "allocator-jemalloc"))]
mod tests {
    use super::*;

    #[test]
    fn generic_reclaim_purges_every_initialized_arena() {
        let (status, report) = allocator_reclaim_impl();

        assert_eq!(status, "pass");
        assert_eq!(report["arenaPurgeScope"], json!("all-initialized-arenas"));
        assert!(report["arenasObserved"].as_u64().unwrap_or(0) > 0);
        assert!(report["arenasAttempted"].as_u64().unwrap_or(0) > 0);
        assert_eq!(report["failures"], json!([]));
    }
}

#[cfg(not(feature = "allocator-jemalloc"))]
fn allocator_reclaim_backend() -> (&'static str, Value) {
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
