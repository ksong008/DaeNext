use super::*;

#[path = "read_only_report/runtime_defaults.rs"]
mod runtime_defaults;
use self::runtime_defaults::*;
#[path = "read_only_report/typed_report.rs"]
mod typed_report;
use self::typed_report::*;
#[path = "read_only_report/native_owner.rs"]
mod native_owner;
use self::native_owner::*;
#[path = "read_only_report/ebpf_backend.rs"]
mod ebpf_backend;
use self::ebpf_backend::*;

#[test]
pub(super) fn production_runtime_owner_report_is_read_only_by_default() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-default-{}",
        std::process::id()
    ));
    let report =
        production_runtime_owner_report(&root, &ProductionRuntimeOwnerOptions::default()).unwrap();

    assert_runtime_defaults(&report);
    assert_typed_report_defaults(&report);
    assert_native_owner_and_deep_area(&report);
    assert_ebpf_backend_defaults(&report);
}
