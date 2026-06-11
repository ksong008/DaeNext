use super::*;
pub(super) fn evidence_queue_admitted(queue: &[KernelProgramParityEvidenceLine]) -> bool {
    queue
        .iter()
        .all(|line| line.status == KernelProgramParityEvidenceStatus::Passed)
}

pub(super) const fn status_from(passed: bool) -> KernelProgramParityEvidenceStatus {
    if passed {
        KernelProgramParityEvidenceStatus::Passed
    } else {
        KernelProgramParityEvidenceStatus::Missing
    }
}

pub(super) const fn evidence_line(
    check: KernelProgramParityCheck,
    item: &'static str,
    status: KernelProgramParityEvidenceStatus,
    source: &'static str,
) -> KernelProgramParityEvidenceLine {
    KernelProgramParityEvidenceLine {
        check,
        item,
        status,
        source,
        required_before_production_admission: true,
    }
}

pub fn kernel_program_feasibility_report() -> KernelProgramFeasibilityReport {
    let tproxy_coverage = tproxy_kernel_program_coverage();
    let trace_coverage = trace_kernel_program_coverage();
    let rust_tproxy_classifier_covered = tproxy_coverage
        .iter()
        .filter(|line| {
            line.surface == KernelProgramSurface::TproxyClassifier
                && line.status == KernelProgramCoverageStatus::RustNativeAdmitted
        })
        .count();
    let rust_tproxy_cgroup_covered = tproxy_coverage
        .iter()
        .filter(|line| {
            line.surface == KernelProgramSurface::TproxyCgroup
                && line.status == KernelProgramCoverageStatus::RustNativeAdmitted
        })
        .count();
    let rust_trace_kprobe_covered = trace_coverage
        .iter()
        .filter(|line| line.status == KernelProgramCoverageStatus::RustNativeAdmitted)
        .count();
    KernelProgramFeasibilityReport {
        schema: "kernel-program-feasibility",
        tproxy_classifier_total: TPROXY_CLASSIFIER_COVERAGE.len(),
        rust_tproxy_classifier_covered,
        tproxy_cgroup_total: TPROXY_CGROUP_COVERAGE.len(),
        rust_tproxy_cgroup_covered,
        trace_kprobe_total: TRACE_KPROBE_COVERAGE.len(),
        rust_trace_kprobe_covered,
        rust_tproxy_runtime_admitted: true,
        trace_rust_native_admitted: false,
        production_admission_allowed: false,
        kernel_program_parity_required_before_production: true,
        external_ebpf_tproxy_object_required: false,
        external_ebpf_trace_object_required: false,
        tc_command_backend_required: true,
        native_userspace_control_plane_ready: true,
        native_bpf_loader_production_ready: true,
        external_bpf_dependency_absent_before_production: true,
        param_model: "load-time PARAM with volatile accessors; runtime_param_map is a later evaluation item",
        tproxy_coverage,
        trace_coverage,
    }
}

pub(super) fn kernel_program_parity_check_passed(
    evidence: KernelProgramParityEvidence,
    check: KernelProgramParityCheck,
) -> bool {
    match check {
        KernelProgramParityCheck::TproxyClassifierCoverage => {
            evidence.tproxy_classifier_coverage_passed
        }
        KernelProgramParityCheck::TproxyCgroupCoverage => evidence.tproxy_cgroup_coverage_passed,
        KernelProgramParityCheck::TraceKprobeCoverage => evidence.trace_kprobe_coverage_passed,
        KernelProgramParityCheck::MapAbiBtfVerifierParity => {
            evidence.map_abi_btf_verifier_parity_passed
        }
        KernelProgramParityCheck::PacketLevelGoldenParity => {
            evidence.packet_level_golden_parity_passed
        }
        KernelProgramParityCheck::RuntimeAdmission => evidence.runtime_admission_passed,
        KernelProgramParityCheck::NativeBenchmark => evidence.native_benchmark_passed,
        KernelProgramParityCheck::RemoteHostWriteAdmission => {
            evidence.remote_host_write_admission_passed
        }
        KernelProgramParityCheck::ExternalEbpfObjectAbsent => evidence.external_ebpf_object_absent,
        KernelProgramParityCheck::NativeUserspaceBoundaryReady => {
            evidence.native_userspace_boundary_ready
        }
    }
}
