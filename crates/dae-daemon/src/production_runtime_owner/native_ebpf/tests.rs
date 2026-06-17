#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;

    #[test]
    fn tcx_runtime_uses_requested_backend_for_netkit_l2_roles() {
        assert_eq!(
            native_backend_for_role(NativeEbpfAttachRole::PeerIngress, AttachBackend::Tcx),
            AttachBackend::Tcx
        );
        assert_eq!(
            native_backend_for_role(NativeEbpfAttachRole::HostIngress, AttachBackend::Tcx),
            AttachBackend::Tcx
        );
        assert_eq!(
            native_backend_for_role(NativeEbpfAttachRole::LanIngress, AttachBackend::Tcx),
            AttachBackend::Tcx
        );
    }

    #[test]
    fn transient_missing_map_ids_are_skipped_during_native_map_collection() {
        let err = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(is_transient_missing_map_id(&err));

        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(!is_transient_missing_map_id(&err));
    }
}
