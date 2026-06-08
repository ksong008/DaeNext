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
    COracleRequired,
}

impl KernelProgramCoverageStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustNativeAdmitted => "rust_native_admitted",
            Self::COracleRequired => "c_oracle_required",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProgramCoverageLine {
    pub surface: KernelProgramSurface,
    pub c_section: &'static str,
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
    pub default_switch_allowed: bool,
    pub formal_kernel_program_parity_stage_required: bool,
    pub c_tproxy_object_fallback_required: bool,
    pub c_trace_object_fallback_required: bool,
    pub tc_command_fallback_required: bool,
    pub go_userspace_control_plane_authoritative: bool,
    pub go_bpf_loader_restored_by_this_stage: bool,
    pub go_bpf_fallback_deletion_allowed_by_this_stage: bool,
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
    MatchedGoRustBenchmark,
    RemoteHostWriteAdmission,
    CObjectFallbackPreserved,
    GoUserspaceBoundaryPreserved,
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
            Self::MatchedGoRustBenchmark => "matched_go_rust_benchmark",
            Self::RemoteHostWriteAdmission => "remote_host_write_admission",
            Self::CObjectFallbackPreserved => "c_object_fallback_preserved",
            Self::GoUserspaceBoundaryPreserved => "go_userspace_boundary_preserved",
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
    pub matched_go_rust_benchmark_passed: bool,
    pub remote_host_write_admission_passed: bool,
    pub c_object_fallback_preserved: bool,
    pub go_userspace_boundary_preserved: bool,
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
    pub required_before_default: bool,
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
            matched_go_rust_benchmark_passed: matched_go_rust_benchmark_evidence_admitted(),
            remote_host_write_admission_passed: remote_host_write_runtime_evidence_admitted(),
            c_object_fallback_preserved: report.c_tproxy_object_fallback_required
                && report.c_trace_object_fallback_required,
            go_userspace_boundary_preserved: report.go_userspace_control_plane_authoritative,
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
            matched_go_rust_benchmark_passed: true,
            remote_host_write_admission_passed: true,
            c_object_fallback_preserved: true,
            go_userspace_boundary_preserved: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProgramParityAdmissionReport {
    pub schema: &'static str,
    pub admitted: bool,
    pub default_switch_allowed: bool,
    pub c_tproxy_object_deletion_allowed: bool,
    pub c_trace_object_deletion_allowed: bool,
    pub go_bpf_fallback_deletion_allowed: bool,
    pub fallback_required: bool,
    pub required_checks: Vec<KernelProgramParityCheck>,
    pub missing_checks: Vec<KernelProgramParityCheck>,
    pub evidence_queue: Vec<KernelProgramParityEvidenceLine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TproxyDataplaneAdmissionReport {
    pub schema: &'static str,
    pub admitted: bool,
    pub default_candidate_allowed: bool,
    pub go_bpf_loader_retirement_candidate: bool,
    pub c_tproxy_object_retirement_candidate: bool,
    pub c_tproxy_object_required: bool,
    pub c_trace_object_required: bool,
    pub trace_diagnostic_excluded_from_default_candidate: bool,
    pub tc_command_fallback_required: bool,
    pub go_userspace_control_plane_preserved: bool,
    pub required_checks: Vec<KernelProgramParityCheck>,
    pub missing_checks: Vec<KernelProgramParityCheck>,
    pub evidence_queue: Vec<KernelProgramParityEvidenceLine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceDiagnosticGateReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub participates_in_tproxy_default_candidate: bool,
    pub c_trace_object_required: bool,
    pub go_trace_fallback_required: bool,
    pub rust_core_sideload_enabled: bool,
    pub fallback_retirement_allowed: bool,
    pub missing_checks: Vec<KernelProgramParityCheck>,
    pub evidence_queue: Vec<KernelProgramParityEvidenceLine>,
    pub restore_gate: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProgramFallbackRetirementBlocker {
    KernelProgramParityMissing,
    TproxyDataplaneAdmissionMissing,
    TraceCoreSideloadDisabled,
    RemoteHostWriteAdmissionMissing,
    ExplicitUserApprovalMissing,
    ProductChainRecertificationMissing,
}

impl KernelProgramFallbackRetirementBlocker {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelProgramParityMissing => "kernel_program_parity_missing",
            Self::TproxyDataplaneAdmissionMissing => "tproxy_dataplane_admission_missing",
            Self::TraceCoreSideloadDisabled => "trace_core_sideload_disabled",
            Self::RemoteHostWriteAdmissionMissing => "remote_host_write_admission_missing",
            Self::ExplicitUserApprovalMissing => "explicit_user_approval_missing",
            Self::ProductChainRecertificationMissing => "product_chain_recertification_missing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProgramFallbackRetirementEvidence {
    pub explicit_user_approval: bool,
    pub product_chain_recertified: bool,
}

impl KernelProgramFallbackRetirementEvidence {
    pub const fn read_only() -> Self {
        Self {
            explicit_user_approval: false,
            product_chain_recertified: false,
        }
    }

    pub const fn completed_for_tests() -> Self {
        Self {
            explicit_user_approval: true,
            product_chain_recertified: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProgramFallbackRetirementGateReport {
    pub schema: &'static str,
    pub admitted: bool,
    pub default_switch_allowed: bool,
    pub c_tproxy_object_retirement_allowed: bool,
    pub c_trace_object_retirement_allowed: bool,
    pub go_bpf_fallback_retirement_allowed: bool,
    pub tc_command_fallback_retirement_allowed: bool,
    pub trace_diagnostic_retirement_allowed: bool,
    pub c_tproxy_object_required: bool,
    pub c_trace_object_required: bool,
    pub go_bpf_fallback_required: bool,
    pub go_trace_fallback_required: bool,
    pub tc_command_fallback_required: bool,
    pub go_userspace_control_plane_preserved: bool,
    pub retirement_scope: &'static str,
    pub explicit_user_approval_recorded: bool,
    pub product_chain_recertified: bool,
    pub blockers: Vec<KernelProgramFallbackRetirementBlocker>,
    pub missing_parity_checks: Vec<KernelProgramParityCheck>,
    pub trace_restore_gate: &'static str,
}
