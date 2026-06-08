#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn ffi_rejects_null_pointer_with_nonzero_len() {
        let rc = unsafe {
            dae_control_apply_domain_routing_map_by_id(0, std::ptr::null(), 1, std::ptr::null(), 0)
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("nonnull pointer required"));
    }

    #[test]
    fn ffi_abi_version_is_stable() {
        assert_eq!(unsafe { dae_control_ffi_abi_version() }, 1);
    }

    #[test]
    fn ffi_reload_dns_cache_plan_requires_report() {
        let rc = unsafe { dae_control_reload_dns_cache_plan(1, 1, 1, std::ptr::null_mut()) };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("reload DNS cache plan"));
    }

    #[test]
    fn ffi_runtime_state_report_requires_report() {
        let rc = unsafe {
            dae_control_runtime_state_report(1, 1, 1, 1, 1, 1, 1, 1, std::ptr::null_mut())
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("runtime state report"));
    }

    #[test]
    fn ffi_routing_owner_rejects_null_owner() {
        let rc = unsafe {
            dae_control_routing_owner_apply_snapshot_by_id(
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("routing owner"));
    }

    #[test]
    fn ffi_domain_routing_owner_rejects_null_owner() {
        let owner_key = CString::new("owner-a").unwrap();
        let rc = unsafe {
            dae_control_domain_routing_owner_apply_snapshot_by_id(
                std::ptr::null_mut(),
                0,
                owner_key.as_ptr(),
                &[0; 32],
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("domain routing owner"));
    }

    #[test]
    fn ffi_outbound_connectivity_owner_rejects_null_owner() {
        let rc = unsafe {
            dae_control_outbound_connectivity_owner_apply_event_by_id(
                std::ptr::null_mut(),
                0,
                FfiConnectivityEvent::default(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("outbound connectivity owner"));
    }
}
