use super::*;
use std::sync::{Mutex, OnceLock, TryLockError};

static ALLOCATOR_RECLAIM_GATE: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) fn allocator_reclaim_impl(_reason: AllocatorReclaimReason) -> (&'static str, Value) {
    allocator_with_reclaim_gate("global", || {}, allocator_reclaim_backend)
}

pub(super) fn allocator_with_reclaim_gate<F, B>(
    scope: &'static str,
    on_busy: B,
    operation: F,
) -> (&'static str, Value)
where
    F: FnOnce() -> (&'static str, Value),
    B: FnOnce(),
{
    let gate = ALLOCATOR_RECLAIM_GATE.get_or_init(|| Mutex::new(()));
    let _guard = match gate.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => {
            on_busy();
            return (
                "merged_pending",
                json!({
                    "operation": "allocator_reclaim_gate",
                    "reason": "reclaim_in_progress",
                    "scope": scope,
                    "trailingEvaluation": true,
                }),
            );
        }
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
    };
    operation()
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
    use std::sync::Arc;

    #[test]
    fn generic_reclaim_purges_every_initialized_arena() {
        let (status, report) = (0..200)
            .find_map(|_| {
                let result = allocator_reclaim_impl(AllocatorReclaimReason::IdleMemoryPressure);
                if result.0 == "merged_pending" {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    None
                } else {
                    Some(result)
                }
            })
            .expect("allocator reclaim gate remained occupied");
        let _ = allocator_take_reclaim_requests();

        assert_eq!(status, "pass");
        assert_eq!(report["arenaPurgeScope"], json!("all-initialized-arenas"));
        assert!(report["arenasObserved"].as_u64().unwrap_or(0) > 0);
        assert!(report["arenasAttempted"].as_u64().unwrap_or(0) > 0);
        assert_eq!(report["failures"], json!([]));
    }

    #[test]
    fn scoped_and_global_reclaim_never_overlap() {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let global = std::thread::spawn(move || {
            allocator_with_reclaim_gate(
                "global",
                || {},
                || {
                    worker_entered.wait();
                    worker_release.wait();
                    ("pass", json!({"operation": "test-global"}))
                },
            )
        });

        entered.wait();
        let (status, detail) = allocator_purge_control_plane_arena();
        release.wait();
        let (global_status, _) = global.join().unwrap();

        assert_eq!(global_status, "pass");
        assert_eq!(status, "subsumed");
        assert_eq!(detail["subsumedBy"], json!("global"));
        assert_eq!(detail["gateDetail"]["trailingEvaluation"], json!(true));
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
