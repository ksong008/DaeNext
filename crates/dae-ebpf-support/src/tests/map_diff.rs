use super::*;
use std::io;

#[test]
pub(super) fn runtime_map_update_diff_skips_unchanged_and_reports_counts() {
    let current = vec![(1_u32, 10_u32), (2, 20), (3, 30)];
    let desired = vec![(1_u32, 10_u32), (2, 22), (4, 40)];
    let mut updates = Vec::new();
    let mut deletes = Vec::new();
    let report = apply_runtime_map_update_diff(
        current,
        desired,
        |key, value| {
            updates.push((*key, *value));
            Ok(())
        },
        |key| {
            deletes.push(*key);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(
        report,
        RuntimeMapUpdateDiffReport {
            entries_inserted: 1,
            entries_updated: 1,
            entries_deleted: 1,
            entries_unchanged: 1,
        }
    );
    assert_eq!(report.entries_changed(), 3);
    assert_eq!(updates, vec![(2, 22), (4, 40)]);
    assert_eq!(deletes, vec![3]);
}

#[test]
pub(super) fn bpf_error_classification_maps_common_kernel_failures() {
    assert_eq!(
        classify_bpf_io_error(&io::Error::from_raw_os_error(libc::EPERM)),
        BpfErrorClass::Permission
    );
    assert_eq!(
        classify_bpf_io_error(&io::Error::from_raw_os_error(libc::ENOSPC)),
        BpfErrorClass::Capacity
    );
    assert_eq!(
        classify_bpf_io_error(&io::Error::from_raw_os_error(libc::ENOENT)),
        BpfErrorClass::MissingObject
    );
    assert_eq!(
        classify_bpf_io_error(&io::Error::from_raw_os_error(libc::EBUSY)),
        BpfErrorClass::Busy
    );
    assert_eq!(
        classify_bpf_io_error(&io::Error::new(
            io::ErrorKind::InvalidData,
            "program load failed; verifier: rejected packet access",
        )),
        BpfErrorClass::Verifier
    );
}
