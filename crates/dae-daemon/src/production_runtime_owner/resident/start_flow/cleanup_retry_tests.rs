//! Exercise the public cleanup caller with a real, recoverable setns failure.
use super::*;

struct EffectiveCapabilities([u32; 6]);
impl EffectiveCapabilities {
    fn without_sys_admin() -> Self {
        let mut header = [0x20080522_u32, 0];
        let mut data = [0_u32; 6];
        // SAFETY: Linux capability version 3 uses this two-word header and
        // two initialized effective/permitted/inheritable data records.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capget, header.as_mut_ptr(), data.as_mut_ptr()) },
            0
        );
        let saved = Self(data);
        assert_ne!(data[0] & (1 << 21), 0, "test needs CAP_SYS_ADMIN");
        data[0] &= !(1 << 21);
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), data.as_ptr()) },
            0
        );
        saved
    }
}
impl Drop for EffectiveCapabilities {
    fn drop(&mut self) {
        let header = [0x20080522_u32, 0];
        // Retain permitted caps, so restoring the original effective set is valid.
        let result = unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), self.0.as_ptr()) };
        if result != 0 {
            eprintln!(
                "failed to restore test effective capabilities: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

pub(super) fn check_cleanup_retry(runtime: &mut ResidentProductionRuntime, backend: AttachBackend) {
    if backend == AttachBackend::TcNetlink {
        let pins = runtime.native_runtime.pin_root().unwrap().to_owned();
        let caps = EffectiveCapabilities::without_sys_admin();
        let mut expected_pending = None;
        for _ in 0..2 {
            let report = runtime.cleanup().unwrap();
            assert_eq!(report["status"], "fail", "{report}");
            assert!(!runtime.cleaned);
            assert_eq!(
                report["reload_conflict_cleanup"]["native_cleanup_pending"],
                true
            );
            let pending = runtime.native_runtime.cleanup_evidence().unwrap()["pendingAttachments"]
                .as_u64()
                .unwrap();
            assert!(pending >= 7, "physical attachments were discarded");
            if let Some(expected) = expected_pending {
                assert_eq!(pending, expected);
            }
            expected_pending = Some(pending);
            assert!(pins.join("cleanup-pending").is_dir());
        }
        drop(caps);
    }
    let cleanup = runtime.cleanup().unwrap();
    assert_eq!(cleanup["status"], "pass", "{cleanup}");
    assert!(runtime.cleaned);
    assert!(runtime.cleanup().is_none());
}
