use super::*;
use crate::allocator::mallctl::fault::{Operation, fail_once};

fn on_worker(
    test: impl FnOnce(AllocatorRuntimeReclaimHooks, Arc<AllocatorWorkerState>) + Send + 'static,
) {
    // Each scenario observes process-wide diagnostics. A subprocess isolates
    // its epochs/counters from other allocator tests run in parallel by CI.
    let current = std::thread::current();
    let name = current.name().unwrap();
    if std::env::var("DAED_ALLOCATOR_CACHE_TEST").as_deref() != Ok(name) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--test-threads=1"])
            .env("DAED_ALLOCATOR_CACHE_TEST", name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    std::thread::spawn(move || {
        mallctl::write_bool(b"thread.tcache.enabled\0", true).unwrap();
        let hooks = AllocatorRuntimeReclaimHooks::new(AllocatorWorkerKind::ResidentData, 1);
        hooks.thread_start();
        hooks.thread_poll();
        let worker = RUNTIME_WORKER.with(|slot| slot.borrow().as_ref().unwrap().clone());
        test(hooks.clone(), worker);
        hooks.thread_poll();
        hooks.thread_stop();
    })
    .join()
    .unwrap();
}

fn next_epoch() -> u64 {
    worker_reclaim()
        .desired_epoch
        .fetch_add(1, Ordering::AcqRel)
        + 1
}

fn counter(name: &str) -> u64 {
    worker_reclaim().diagnostics.json()["errorsByOperation"][name]
        .as_u64()
        .unwrap()
}

#[test]
fn park_recovery_preserves_flush_error_evidence() {
    on_worker(|hooks, worker| {
        let epoch = next_epoch();
        let before = counter("flush");
        let recovered = worker_reclaim().diagnostics.json()["flushRecoveriesTotal"]
            .as_u64()
            .unwrap();
        let _fault = fail_once(&[Operation::Flush]);
        hooks.thread_park();
        assert_eq!(worker.failed_epoch.load(Ordering::Acquire), epoch);
        assert!(!worker.flush_failed(epoch));
        assert!(worker.parked_cache_empty.load(Ordering::Acquire));
        let report = flush_runtime_workers(&hooks.state, false, Instant::now());
        assert_eq!(report.acknowledged, 1);
        assert_eq!(report.failures, 0);
        assert_eq!(counter("flush"), before + 1);
        assert_eq!(
            worker_reclaim().diagnostics.json()["flushRecoveriesTotal"],
            recovered + 1
        );
        let last = worker_reclaim().diagnostics.json()["lastError"].clone();
        assert_eq!(last["operation"], "flush");
        assert_eq!(last["epoch"], epoch);
        assert!(last["error"].as_str().unwrap().contains("injected"));
        hooks.thread_poll();
        let later = next_epoch();
        hooks.thread_poll();
        assert!(!worker.flush_failed(later));
        assert_eq!(worker.failed_epoch.load(Ordering::Acquire), epoch);
        assert_eq!(counter("flush"), before + 1);
        assert_eq!(
            worker_reclaim().diagnostics.json()["flushRecoveriesTotal"],
            recovered + 1
        );
    });
}

#[test]
fn failed_flush_and_disable_cannot_publish_empty_cache_or_pass() {
    on_worker(|hooks, worker| {
        let epoch = next_epoch();
        let _fault = fail_once(&[Operation::Flush, Operation::Disable]);
        hooks.thread_park();
        assert!(worker.flush_failed(epoch));
        assert!(!worker.parked_cache_empty.load(Ordering::Acquire));
        let report = flush_runtime_workers(&hooks.state, false, Instant::now());
        assert_eq!(report.failures, 1);
        assert_eq!(
            worker_reclaim().diagnostics.json()["lastError"]["operation"],
            "parkDisable"
        );
    });
}

#[test]
fn disabled_cache_is_empty_without_a_flush_error() {
    on_worker(|hooks, worker| {
        mallctl::write_bool(b"thread.tcache.enabled\0", false).unwrap();
        let epoch = next_epoch();
        let before = counter("flush");
        // A command fault would fire if the disabled cache reached mallctl flush.
        let _fault = fail_once(&[Operation::Flush]);
        hooks.thread_park();
        assert!(!worker.flush_failed(epoch));
        assert!(worker.parked_cache_empty.load(Ordering::Acquire));
        assert_eq!(counter("flush"), before);
        hooks.thread_poll();
        assert!(!mallctl::read_bool(b"thread.tcache.enabled\0").unwrap());
    });
}

#[test]
fn failed_cache_state_read_is_not_treated_as_empty() {
    on_worker(|hooks, worker| {
        // Leave poll acknowledged so the injected read belongs to park itself.
        let before = counter("parkReadEnabled");
        let _fault = fail_once(&[Operation::ReadEnabled]);
        hooks.thread_park();
        assert!(!worker.parked_cache_empty.load(Ordering::Acquire));
        assert_eq!(counter("parkReadEnabled"), before + 1);
    });
}

#[test]
fn failed_restore_keeps_original_setting_across_another_park() {
    on_worker(|hooks, _| {
        mallctl::write_bool(b"thread.tcache.enabled\0", true).unwrap();
        hooks.thread_park();
        let before = counter("unparkRestore");
        {
            let _fault = fail_once(&[Operation::Restore]);
            // park starts by trying to restore the previous true setting. That
            // attempt fails; this park must retain true instead of saving false.
            hooks.thread_park();
        }
        assert!(!mallctl::read_bool(b"thread.tcache.enabled\0").unwrap());
        assert_eq!(PARKED_TCACHE_ENABLED.with(Cell::get), Some(true));
        assert_eq!(counter("unparkRestore"), before + 1);
        hooks.thread_poll();
        assert!(mallctl::read_bool(b"thread.tcache.enabled\0").unwrap());
        assert_eq!(PARKED_TCACHE_ENABLED.with(Cell::get), None);
    });
}

#[test]
fn park_flushes_populated_cache_bytes_and_unpark_restores_it() {
    on_worker(|hooks, worker| {
        let arena = mallctl::read_command_u32(b"arenas.create\0").unwrap();
        mallctl::write_u32(b"thread.arena\0", arena).unwrap();
        let key = format!("stats.arenas.{arena}.tcache_bytes\0");
        let blocks = (0..64).map(|_| vec![1_u8; 1024]).collect::<Vec<_>>();
        std::hint::black_box(&blocks);
        drop(blocks);
        tikv_jemalloc_ctl::epoch::advance().unwrap();
        assert!(mallctl::read_usize(key.as_bytes()).unwrap() > 0);
        hooks.thread_park();
        tikv_jemalloc_ctl::epoch::advance().unwrap();
        assert_eq!(mallctl::read_usize(key.as_bytes()).unwrap(), 0);
        assert!(worker.parked_cache_empty.load(Ordering::Acquire));
        assert!(!mallctl::read_bool(b"thread.tcache.enabled\0").unwrap());
        hooks.thread_poll();
        assert!(mallctl::read_bool(b"thread.tcache.enabled\0").unwrap());
    });
}
