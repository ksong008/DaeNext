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
#[path = "read_only_report/kernel_program.rs"]
mod kernel_program;
use self::kernel_program::*;
#[path = "read_only_report/tproxy_admission.rs"]
mod tproxy_admission;
use self::tproxy_admission::*;
#[path = "read_only_report/trace_gates.rs"]
mod trace_gates;
use self::trace_gates::*;
#[path = "read_only_report/fallback_retirement.rs"]
mod fallback_retirement;
use self::fallback_retirement::*;
#[path = "read_only_report/evidence_contract.rs"]
mod evidence_contract;
use self::evidence_contract::*;

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
    assert_kernel_program_gates(&report);
    assert_tproxy_dataplane_admission(&report);
    assert_trace_gates(&report);
    assert_kernel_fallback_retirement_gate(&report);
    assert_kernel_evidence_and_contract(&report);
}
