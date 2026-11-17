use super::*;

#[test]
fn production_resident_allocator_hooks_flush_on_park_and_restore_on_unpark() {
    std::thread::spawn(|| {
        let hooks = DaemonResidentAllocatorHooks
            .runtime_hooks(ResidentAllocatorWorkerKind::ResidentData, 1);
        hooks.thread_start();
        for enabled in [true, false] {
            // SAFETY: thread.tcache.enabled has the documented bool type and
            // both operations apply to this test's dedicated OS thread.
            unsafe {
                tikv_jemalloc_ctl::raw::write(b"thread.tcache.enabled\0", enabled).unwrap();
            }
            hooks.thread_park();
            assert!(!unsafe {
                tikv_jemalloc_ctl::raw::read::<bool>(b"thread.tcache.enabled\0").unwrap()
            });
            hooks.thread_poll();
            assert_eq!(
                unsafe {
                    tikv_jemalloc_ctl::raw::read::<bool>(b"thread.tcache.enabled\0").unwrap()
                },
                enabled
            );
        }
        hooks.thread_stop();
    })
    .join()
    .unwrap();
}
