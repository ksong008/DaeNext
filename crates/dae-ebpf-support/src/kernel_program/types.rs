use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProgramSurface {
    TproxyClassifier,
    TproxyCgroup,
    TraceKprobe,
}

impl KernelProgramSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TproxyClassifier => "tproxy_classifier",
            Self::TproxyCgroup => "tproxy_cgroup",
            Self::TraceKprobe => "trace_kprobe",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProgramCoverageStatus {
    RustNativeAdmitted,
    NativeTraceDisabled,
}

impl KernelProgramCoverageStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustNativeAdmitted => "rust_native_admitted",
            Self::NativeTraceDisabled => "native_trace_disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProgramCoverageLine {
    pub surface: KernelProgramSurface,
    pub section: &'static str,
    pub rust_section: Option<&'static str>,
    pub program_name: &'static str,
    pub status: KernelProgramCoverageStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProgramFeasibilityReport {
    pub schema: &'static str,
    pub tproxy_classifier_total: usize,
    pub rust_tproxy_classifier_covered: usize,
    pub tproxy_cgroup_total: usize,
    pub rust_tproxy_cgroup_covered: usize,
    pub trace_kprobe_total: usize,
    pub rust_trace_kprobe_covered: usize,
    pub rust_tproxy_runtime_admitted: bool,
    pub trace_rust_native_admitted: bool,
    pub production_admission_allowed: bool,
    pub kernel_program_parity_required_before_production: bool,
    pub external_ebpf_tproxy_object_required: bool,
    pub external_ebpf_trace_object_required: bool,
    pub tc_command_backend_required: bool,
    pub native_userspace_control_plane_ready: bool,
    pub native_bpf_loader_production_ready: bool,
    pub external_bpf_dependency_absent_before_production: bool,
    pub param_model: &'static str,
    pub tproxy_coverage: Vec<KernelProgramCoverageLine>,
    pub trace_coverage: Vec<KernelProgramCoverageLine>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProgramParityCheck {
    TproxyClassifierCoverage,
    TproxyCgroupCoverage,
    TraceKprobeCoverage,
    MapAbiBtfVerifierParity,
    PacketLevelGoldenParity,
    RuntimeAdmission,
    NativeBenchmark,
    RemoteHostWriteAdmission,
    ExternalEbpfObjectAbsent,
    NativeUserspaceBoundaryReady,
}

impl KernelProgramParityCheck {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TproxyClassifierCoverage => "tproxy_classifier_coverage",
            Self::TproxyCgroupCoverage => "tproxy_cgroup_coverage",
            Self::TraceKprobeCoverage => "trace_kprobe_coverage",
            Self::MapAbiBtfVerifierParity => "map_abi_btf_verifier_parity",
            Self::PacketLevelGoldenParity => "packet_level_golden_parity",
            Self::RuntimeAdmission => "runtime_admission",
            Self::NativeBenchmark => "native_benchmark",
            Self::RemoteHostWriteAdmission => "remote_host_write_admission",
            Self::ExternalEbpfObjectAbsent => "external_ebpf_object_absent",
            Self::NativeUserspaceBoundaryReady => "native_userspace_boundary_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProgramParityEvidence {
    pub tproxy_classifier_coverage_passed: bool,
    pub tproxy_cgroup_coverage_passed: bool,
    pub trace_kprobe_coverage_passed: bool,
    pub map_abi_btf_verifier_parity_passed: bool,
    pub packet_level_golden_parity_passed: bool,
    pub runtime_admission_passed: bool,
    pub native_benchmark_passed: bool,
    pub remote_host_write_admission_passed: bool,
    pub external_ebpf_object_absent: bool,
    pub native_userspace_boundary_ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProgramParityEvidenceStatus {
    Passed,
    Missing,
}

impl KernelProgramParityEvidenceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Missing => "missing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProgramParityEvidenceLine {
    pub check: KernelProgramParityCheck,
    pub item: &'static str,
    pub status: KernelProgramParityEvidenceStatus,
    pub source: &'static str,
    pub required_before_production_admission: bool,
}

impl KernelProgramParityEvidence {
    pub fn from_feasibility(report: &KernelProgramFeasibilityReport) -> Self {
        Self {
            tproxy_classifier_coverage_passed: report.rust_tproxy_classifier_covered
                == report.tproxy_classifier_total,
            tproxy_cgroup_coverage_passed: report.rust_tproxy_cgroup_covered
                == report.tproxy_cgroup_total,
            trace_kprobe_coverage_passed: report.rust_trace_kprobe_covered
                == report.trace_kprobe_total
                && trace_kprobe_evidence_admitted(),
            map_abi_btf_verifier_parity_passed: map_abi_btf_verifier_evidence_admitted(),
            packet_level_golden_parity_passed: packet_level_golden_evidence_admitted(),
            runtime_admission_passed: report.rust_tproxy_runtime_admitted,
            native_benchmark_passed: native_benchmark_evidence_admitted(),
            remote_host_write_admission_passed: remote_host_write_runtime_evidence_admitted(),
            external_ebpf_object_absent: !report.external_ebpf_tproxy_object_required
                && !report.external_ebpf_trace_object_required,
            native_userspace_boundary_ready: report.native_userspace_control_plane_ready,
        }
    }

    pub const fn complete_for_tests() -> Self {
        Self {
            tproxy_classifier_coverage_passed: true,
            tproxy_cgroup_coverage_passed: true,
            trace_kprobe_coverage_passed: true,
            map_abi_btf_verifier_parity_passed: true,
            packet_level_golden_parity_passed: true,
            runtime_admission_passed: true,
            native_benchmark_passed: true,
            remote_host_write_admission_passed: true,
            external_ebpf_object_absent: true,
            native_userspace_boundary_ready: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProgramParityAdmissionReport {
    pub schema: &'static str,
    pub admitted: bool,
    pub production_admission_allowed: bool,
    pub external_ebpf_tproxy_object_absent: bool,
    pub external_ebpf_trace_object_absent: bool,
    pub external_bpf_dependency_absent: bool,
    pub additional_evidence_required: bool,
    pub required_checks: Vec<KernelProgramParityCheck>,
    pub missing_checks: Vec<KernelProgramParityCheck>,
    pub evidence_queue: Vec<KernelProgramParityEvidenceLine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TproxyDataplaneAdmissionReport {
    pub schema: &'static str,
    pub admitted: bool,
    pub production_candidate_allowed: bool,
    pub native_bpf_loader_production_candidate: bool,
    pub external_ebpf_tproxy_object_absent: bool,
    pub external_ebpf_tproxy_object_required: bool,
    pub external_ebpf_trace_object_required: bool,
    pub trace_diagnostic_excluded_from_production_candidate: bool,
    pub tc_command_backend_required: bool,
    pub native_userspace_control_plane_ready: bool,
    pub required_checks: Vec<KernelProgramParityCheck>,
    pub missing_checks: Vec<KernelProgramParityCheck>,
    pub evidence_queue: Vec<KernelProgramParityEvidenceLine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceDiagnosticGateReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub participates_in_tproxy_production_candidate: bool,
    pub external_ebpf_trace_object_required: bool,
    pub external_trace_dependency_required: bool,
    pub rust_core_sideload_enabled: bool,
    pub native_trace_restore_allowed: bool,
    pub missing_checks: Vec<KernelProgramParityCheck>,
    pub evidence_queue: Vec<KernelProgramParityEvidenceLine>,
    pub restore_gate: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProgramProductionBlocker {
    KernelProgramParityMissing,
    TproxyDataplaneAdmissionMissing,
    TraceCoreSideloadDisabled,
    RemoteHostWriteAdmissionMissing,
    ExplicitUserApprovalMissing,
    FinalStateCertificationMissing,
}

impl KernelProgramProductionBlocker {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelProgramParityMissing => "kernel_program_parity_missing",
            Self::TproxyDataplaneAdmissionMissing => "tproxy_dataplane_admission_missing",
            Self::TraceCoreSideloadDisabled => "trace_core_sideload_disabled",
            Self::RemoteHostWriteAdmissionMissing => "remote_host_write_admission_missing",
            Self::ExplicitUserApprovalMissing => "explicit_user_approval_missing",
            Self::FinalStateCertificationMissing => "final_state_certification_missing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProgramProductionEvidence {
    pub explicit_user_approval: bool,
    pub final_state_certified: bool,
}

impl KernelProgramProductionEvidence {
    pub const fn read_only() -> Self {
        Self {
            explicit_user_approval: false,
            final_state_certified: false,
        }
    }

    pub const fn completed_for_tests() -> Self {
        Self {
            explicit_user_approval: true,
            final_state_certified: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProgramProductionGateReport {
    pub schema: &'static str,
    pub admitted: bool,
    pub production_admission_allowed: bool,
    pub external_ebpf_tproxy_object_absent: bool,
    pub external_ebpf_trace_object_absent: bool,
    pub external_bpf_dependency_absent: bool,
    pub tc_command_backend_required: bool,
    pub trace_diagnostic_restore_allowed: bool,
    pub external_ebpf_tproxy_object_required: bool,
    pub external_ebpf_trace_object_required: bool,
    pub external_trace_dependency_required: bool,
    pub native_userspace_control_plane_ready: bool,
    pub production_scope: &'static str,
    pub explicit_user_approval_recorded: bool,
    pub final_state_certified: bool,
    pub blockers: Vec<KernelProgramProductionBlocker>,
    pub missing_parity_checks: Vec<KernelProgramParityCheck>,
    pub trace_restore_gate: &'static str,
}
