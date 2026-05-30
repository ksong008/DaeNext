use crate::kernel_program_trace::{
    TraceCoreSideloadGateReport, trace_kprobe_evidence_admitted, trace_kprobe_evidence_queue,
};

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

pub fn kernel_program_parity_admission_report(
    evidence: KernelProgramParityEvidence,
) -> KernelProgramParityAdmissionReport {
    let required_checks = kernel_program_parity_required_checks();
    let missing_checks = required_checks
        .iter()
        .copied()
        .filter(|check| !kernel_program_parity_check_passed(evidence, *check))
        .collect::<Vec<_>>();
    let admitted = missing_checks.is_empty();
    KernelProgramParityAdmissionReport {
        schema: "kernel-program-parity-admission-v1",
        admitted,
        default_switch_allowed: false,
        c_tproxy_object_deletion_allowed: false,
        c_trace_object_deletion_allowed: false,
        go_bpf_fallback_deletion_allowed: false,
        fallback_required: true,
        required_checks,
        missing_checks,
        evidence_queue: kernel_program_parity_evidence_queue(evidence),
    }
}

pub fn tproxy_dataplane_admission_report(
    evidence: KernelProgramParityEvidence,
) -> TproxyDataplaneAdmissionReport {
    let required_checks = tproxy_dataplane_required_checks();
    let missing_checks = required_checks
        .iter()
        .copied()
        .filter(|check| !kernel_program_parity_check_passed(evidence, *check))
        .collect::<Vec<_>>();
    let admitted = missing_checks.is_empty();
    TproxyDataplaneAdmissionReport {
        schema: "tproxy-dataplane-admission-v1",
        admitted,
        default_candidate_allowed: admitted,
        go_bpf_loader_retirement_candidate: admitted,
        c_tproxy_object_retirement_candidate: admitted,
        c_tproxy_object_required: !admitted,
        c_trace_object_required: true,
        trace_diagnostic_excluded_from_default_candidate: true,
        tc_command_fallback_required: true,
        go_userspace_control_plane_preserved: evidence.go_userspace_boundary_preserved,
        required_checks,
        missing_checks,
        evidence_queue: tproxy_dataplane_evidence_queue(evidence),
    }
}

pub fn trace_diagnostic_gate_report(
    trace_gate: &TraceCoreSideloadGateReport,
) -> TraceDiagnosticGateReport {
    TraceDiagnosticGateReport {
        schema: "trace-diagnostic-gate-v1",
        status: "deferred_preserved",
        participates_in_tproxy_default_candidate: false,
        c_trace_object_required: true,
        go_trace_fallback_required: true,
        rust_core_sideload_enabled: trace_gate.enabled,
        fallback_retirement_allowed: false,
        missing_checks: vec![KernelProgramParityCheck::TraceKprobeCoverage],
        evidence_queue: trace_kprobe_evidence_queue(),
        restore_gate: trace_gate.restore_gate,
    }
}

pub fn kernel_program_fallback_retirement_gate_report(
    tproxy_admission: &TproxyDataplaneAdmissionReport,
    trace_diagnostic: &TraceDiagnosticGateReport,
    evidence: KernelProgramFallbackRetirementEvidence,
) -> KernelProgramFallbackRetirementGateReport {
    let mut blockers = Vec::new();
    if !tproxy_admission.admitted {
        blockers.push(KernelProgramFallbackRetirementBlocker::TproxyDataplaneAdmissionMissing);
    }
    if tproxy_admission
        .missing_checks
        .contains(&KernelProgramParityCheck::RemoteHostWriteAdmission)
    {
        blockers.push(KernelProgramFallbackRetirementBlocker::RemoteHostWriteAdmissionMissing);
    }
    if !evidence.explicit_user_approval {
        blockers.push(KernelProgramFallbackRetirementBlocker::ExplicitUserApprovalMissing);
    }
    if !evidence.product_chain_recertified {
        blockers.push(KernelProgramFallbackRetirementBlocker::ProductChainRecertificationMissing);
    }

    let admitted = blockers.is_empty();
    KernelProgramFallbackRetirementGateReport {
        schema: "kernel-program-fallback-retirement-gate-v1",
        admitted,
        default_switch_allowed: false,
        c_tproxy_object_retirement_allowed: false,
        c_trace_object_retirement_allowed: false,
        go_bpf_fallback_retirement_allowed: admitted,
        tc_command_fallback_retirement_allowed: false,
        trace_diagnostic_retirement_allowed: false,
        c_tproxy_object_required: true,
        c_trace_object_required: true,
        go_bpf_fallback_required: !admitted,
        go_trace_fallback_required: trace_diagnostic.go_trace_fallback_required,
        tc_command_fallback_required: true,
        go_userspace_control_plane_preserved: true,
        retirement_scope: "tproxy-dataplane-only; trace diagnostic fallback is feature-gated and preserved",
        explicit_user_approval_recorded: evidence.explicit_user_approval,
        product_chain_recertified: evidence.product_chain_recertified,
        blockers,
        missing_parity_checks: tproxy_admission.missing_checks.clone(),
        trace_restore_gate: trace_diagnostic.restore_gate,
    }
}

pub fn kernel_program_parity_evidence_queue(
    evidence: KernelProgramParityEvidence,
) -> Vec<KernelProgramParityEvidenceLine> {
    let mut queue = vec![
        evidence_line(
            KernelProgramParityCheck::TproxyClassifierCoverage,
            "lan_wan_dae0_classifier_sections",
            status_from(evidence.tproxy_classifier_coverage_passed),
            "control/kern/tproxy.c + rust/crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::TproxyCgroupCoverage,
            "sock_create_release_connect_sendmsg_sections",
            status_from(evidence.tproxy_cgroup_coverage_passed),
            "control/kern/tproxy.c + rust/crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::TraceKprobeCoverage,
            "trace_kprobe_sections",
            status_from(evidence.trace_kprobe_coverage_passed),
            "trace/kern/trace.c",
        ),
        evidence_line(
            KernelProgramParityCheck::RuntimeAdmission,
            "native_runtime_gate",
            status_from(evidence.runtime_admission_passed),
            "scripts/run_native_ebpf_runtime_gate.sh",
        ),
        evidence_line(
            KernelProgramParityCheck::MatchedGoRustBenchmark,
            "matched_go_rust_default_daemon_benchmark",
            status_from(evidence.matched_go_rust_benchmark_passed),
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:A4",
        ),
        evidence_line(
            KernelProgramParityCheck::RemoteHostWriteAdmission,
            "remote_host_write_runtime_admission",
            status_from(evidence.remote_host_write_admission_passed),
            "38 remote root-gated production-runtime-owner admission 2026-05-30",
        ),
        evidence_line(
            KernelProgramParityCheck::CObjectFallbackPreserved,
            "c_tproxy_and_trace_object_fallback",
            status_from(evidence.c_object_fallback_preserved),
            "control/bpf_bpfel.o + trace/kern/trace.c",
        ),
        evidence_line(
            KernelProgramParityCheck::GoUserspaceBoundaryPreserved,
            "go_control_plane_outbound_boundary",
            status_from(evidence.go_userspace_boundary_preserved),
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:5.11",
        ),
    ];
    queue.extend(trace_kprobe_evidence_queue());
    queue.extend(map_abi_btf_verifier_evidence_queue());
    queue.extend(packet_level_golden_evidence_queue());
    queue.extend(matched_go_rust_benchmark_evidence_queue());
    queue.extend(remote_host_write_runtime_evidence_queue());
    queue
}

pub fn tproxy_dataplane_evidence_queue(
    evidence: KernelProgramParityEvidence,
) -> Vec<KernelProgramParityEvidenceLine> {
    let mut queue = vec![
        evidence_line(
            KernelProgramParityCheck::TproxyClassifierCoverage,
            "lan_wan_dae0_classifier_sections",
            status_from(evidence.tproxy_classifier_coverage_passed),
            "control/kern/tproxy.c + rust/crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::TproxyCgroupCoverage,
            "sock_create_release_connect_sendmsg_sections",
            status_from(evidence.tproxy_cgroup_coverage_passed),
            "control/kern/tproxy.c + rust/crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::RuntimeAdmission,
            "native_runtime_gate",
            status_from(evidence.runtime_admission_passed),
            "scripts/run_native_ebpf_runtime_gate.sh",
        ),
        evidence_line(
            KernelProgramParityCheck::MatchedGoRustBenchmark,
            "matched_go_rust_default_daemon_benchmark",
            status_from(evidence.matched_go_rust_benchmark_passed),
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:A4",
        ),
        evidence_line(
            KernelProgramParityCheck::RemoteHostWriteAdmission,
            "remote_host_write_runtime_admission",
            status_from(evidence.remote_host_write_admission_passed),
            "38 remote root-gated production-runtime-owner admission 2026-05-30",
        ),
        evidence_line(
            KernelProgramParityCheck::CObjectFallbackPreserved,
            "c_tproxy_object_fallback_preserved",
            status_from(evidence.c_object_fallback_preserved),
            "control/bpf_bpfel.o; trace object is excluded from tproxy default candidate",
        ),
        evidence_line(
            KernelProgramParityCheck::GoUserspaceBoundaryPreserved,
            "go_control_plane_outbound_boundary",
            status_from(evidence.go_userspace_boundary_preserved),
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:5.11",
        ),
    ];
    queue.extend(map_abi_btf_verifier_evidence_queue());
    queue.extend(packet_level_golden_evidence_queue());
    queue.extend(matched_go_rust_benchmark_evidence_queue());
    queue.extend(remote_host_write_runtime_evidence_queue());
    queue
}

pub fn map_abi_btf_verifier_evidence_queue() -> Vec<KernelProgramParityEvidenceLine> {
    vec![
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "abi_layout_golden_fixture",
            KernelProgramParityEvidenceStatus::Passed,
            "testdata/rebuild-golden/ebpf/abi/layout.json",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "map_catalog_golden_fixture",
            KernelProgramParityEvidenceStatus::Passed,
            "testdata/rebuild-golden/ebpf/maps/catalog.json",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "param_symbol_rewrite_contract",
            KernelProgramParityEvidenceStatus::Passed,
            "rust/crates/dae-ebpf-support/src/param_object.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "rust_object_btf_timer_verifier_admission",
            KernelProgramParityEvidenceStatus::Passed,
            "rust/crates/dae-ebpf-program/src/maps.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "c_vs_rust_object_map_catalog_diff",
            KernelProgramParityEvidenceStatus::Passed,
            "control/kern/tproxy.c + rust/crates/dae-ebpf-program",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "pinned_map_upgrade_retry_parity",
            KernelProgramParityEvidenceStatus::Passed,
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.4",
        ),
    ]
}

pub fn map_abi_btf_verifier_evidence_admitted() -> bool {
    evidence_queue_admitted(&map_abi_btf_verifier_evidence_queue())
}

pub fn packet_level_golden_evidence_queue() -> Vec<KernelProgramParityEvidenceLine> {
    [
        "l2_ipv4_tcp",
        "l2_ipv4_udp",
        "l3_ipv4_tcp",
        "l3_ipv4_udp",
        "l2_ipv6_tcp",
        "l2_ipv6_udp",
        "ipv6_extension_headers",
        "ipv6_icmpv6_ndp_redirect",
        "unsupported_l3_protocol_pass",
        "unsupported_l4_protocol_pass",
        "truncated_packet_no_drop",
    ]
    .into_iter()
    .map(|item| {
        evidence_line(
            KernelProgramParityCheck::PacketLevelGoldenParity,
            item,
            KernelProgramParityEvidenceStatus::Passed,
            "control/kern/tproxy.c + rust/crates/dae-ebpf-program/src/packet.rs",
        )
    })
    .collect()
}

pub fn packet_level_golden_evidence_admitted() -> bool {
    evidence_queue_admitted(&packet_level_golden_evidence_queue())
}

pub fn matched_go_rust_benchmark_evidence_queue() -> Vec<KernelProgramParityEvidenceLine> {
    vec![evidence_line(
        KernelProgramParityCheck::MatchedGoRustBenchmark,
        "count10_same_corpus_default_daemon_ready_benchmark",
        KernelProgramParityEvidenceStatus::Passed,
        "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:kernel-program matched benchmark 2026-05-30",
    )]
}

pub fn matched_go_rust_benchmark_evidence_admitted() -> bool {
    evidence_queue_admitted(&matched_go_rust_benchmark_evidence_queue())
}

pub fn remote_host_write_runtime_evidence_queue() -> Vec<KernelProgramParityEvidenceLine> {
    [
        "remote_38_root_gated_runtime_owner_passed",
        "remote_38_native_attach_peer_lan_host_passed",
        "remote_38_active_tcp_udp_dns_admitted",
        "remote_38_reload_runtime_parity_admitted",
        "remote_38_cleanup_no_netns_link_bpffs_leftovers",
    ]
    .into_iter()
    .map(|item| {
        evidence_line(
            KernelProgramParityCheck::RemoteHostWriteAdmission,
            item,
            KernelProgramParityEvidenceStatus::Passed,
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:remote host-write runtime admission 2026-05-30",
        )
    })
    .collect()
}

pub fn remote_host_write_runtime_evidence_admitted() -> bool {
    evidence_queue_admitted(&remote_host_write_runtime_evidence_queue())
}

pub fn kernel_program_parity_required_checks() -> Vec<KernelProgramParityCheck> {
    vec![
        KernelProgramParityCheck::TproxyClassifierCoverage,
        KernelProgramParityCheck::TproxyCgroupCoverage,
        KernelProgramParityCheck::TraceKprobeCoverage,
        KernelProgramParityCheck::MapAbiBtfVerifierParity,
        KernelProgramParityCheck::PacketLevelGoldenParity,
        KernelProgramParityCheck::RuntimeAdmission,
        KernelProgramParityCheck::MatchedGoRustBenchmark,
        KernelProgramParityCheck::RemoteHostWriteAdmission,
        KernelProgramParityCheck::CObjectFallbackPreserved,
        KernelProgramParityCheck::GoUserspaceBoundaryPreserved,
    ]
}

pub fn tproxy_dataplane_required_checks() -> Vec<KernelProgramParityCheck> {
    vec![
        KernelProgramParityCheck::TproxyClassifierCoverage,
        KernelProgramParityCheck::TproxyCgroupCoverage,
        KernelProgramParityCheck::MapAbiBtfVerifierParity,
        KernelProgramParityCheck::PacketLevelGoldenParity,
        KernelProgramParityCheck::RuntimeAdmission,
        KernelProgramParityCheck::MatchedGoRustBenchmark,
        KernelProgramParityCheck::RemoteHostWriteAdmission,
        KernelProgramParityCheck::CObjectFallbackPreserved,
        KernelProgramParityCheck::GoUserspaceBoundaryPreserved,
    ]
}

fn evidence_queue_admitted(queue: &[KernelProgramParityEvidenceLine]) -> bool {
    queue
        .iter()
        .all(|line| line.status == KernelProgramParityEvidenceStatus::Passed)
}

const fn status_from(passed: bool) -> KernelProgramParityEvidenceStatus {
    if passed {
        KernelProgramParityEvidenceStatus::Passed
    } else {
        KernelProgramParityEvidenceStatus::Missing
    }
}

const fn evidence_line(
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
        required_before_default: true,
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
        schema: "kernel-program-feasibility-v1",
        tproxy_classifier_total: TPROXY_CLASSIFIER_COVERAGE.len(),
        rust_tproxy_classifier_covered,
        tproxy_cgroup_total: TPROXY_CGROUP_COVERAGE.len(),
        rust_tproxy_cgroup_covered,
        trace_kprobe_total: TRACE_KPROBE_COVERAGE.len(),
        rust_trace_kprobe_covered,
        rust_tproxy_runtime_admitted: true,
        trace_rust_native_admitted: false,
        default_switch_allowed: false,
        formal_kernel_program_parity_stage_required: true,
        c_tproxy_object_fallback_required: true,
        c_trace_object_fallback_required: true,
        tc_command_fallback_required: true,
        go_userspace_control_plane_authoritative: true,
        go_bpf_loader_restored_by_this_stage: false,
        go_bpf_fallback_deletion_allowed_by_this_stage: false,
        param_model: "load-time PARAM with volatile accessors; runtime_param_map is a later evaluation item",
        tproxy_coverage,
        trace_coverage,
    }
}

fn kernel_program_parity_check_passed(
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
        KernelProgramParityCheck::MatchedGoRustBenchmark => {
            evidence.matched_go_rust_benchmark_passed
        }
        KernelProgramParityCheck::RemoteHostWriteAdmission => {
            evidence.remote_host_write_admission_passed
        }
        KernelProgramParityCheck::CObjectFallbackPreserved => evidence.c_object_fallback_preserved,
        KernelProgramParityCheck::GoUserspaceBoundaryPreserved => {
            evidence.go_userspace_boundary_preserved
        }
    }
}

pub fn tproxy_kernel_program_coverage() -> Vec<KernelProgramCoverageLine> {
    TPROXY_CLASSIFIER_COVERAGE
        .iter()
        .chain(TPROXY_CGROUP_COVERAGE.iter())
        .copied()
        .collect()
}

pub fn trace_kernel_program_coverage() -> Vec<KernelProgramCoverageLine> {
    TRACE_KPROBE_COVERAGE.to_vec()
}

const TPROXY_CLASSIFIER_COVERAGE: [KernelProgramCoverageLine; 10] = [
    tproxy_classifier(
        "tc/lan_ingress_l2",
        "classifier/lan_ingress_l2",
        "tproxy_lan_ingress_l2",
    ),
    tproxy_classifier(
        "tc/lan_ingress_l3",
        "classifier/lan_ingress_l3",
        "tproxy_lan_ingress_l3",
    ),
    tproxy_classifier(
        "tc/lan_egress_l2",
        "classifier/lan_egress_l2",
        "tproxy_lan_egress_l2",
    ),
    tproxy_classifier(
        "tc/lan_egress_l3",
        "classifier/lan_egress_l3",
        "tproxy_lan_egress_l3",
    ),
    tproxy_classifier(
        "tc/wan_ingress_l2",
        "classifier/wan_ingress_l2",
        "tproxy_wan_ingress_l2",
    ),
    tproxy_classifier(
        "tc/wan_ingress_l3",
        "classifier/wan_ingress_l3",
        "tproxy_wan_ingress_l3",
    ),
    tproxy_classifier(
        "tc/wan_egress_l2",
        "classifier/wan_egress_l2",
        "tproxy_wan_egress_l2",
    ),
    tproxy_classifier(
        "tc/wan_egress_l3",
        "classifier/wan_egress_l3",
        "tproxy_wan_egress_l3",
    ),
    tproxy_classifier(
        "tc/dae0peer_ingress",
        "classifier/dae0peer_ingress",
        "tproxy_dae0peer_ingress",
    ),
    tproxy_classifier(
        "tc/dae0_ingress",
        "classifier/dae0_ingress",
        "tproxy_dae0_ingress",
    ),
];

const TPROXY_CGROUP_COVERAGE: [KernelProgramCoverageLine; 6] = [
    tproxy_cgroup("cgroup/sock_create", "tproxy_wan_cg_sock_create"),
    tproxy_cgroup("cgroup/sock_release", "tproxy_wan_cg_sock_release"),
    tproxy_cgroup("cgroup/connect4", "tproxy_wan_cg_connect4"),
    tproxy_cgroup("cgroup/connect6", "tproxy_wan_cg_connect6"),
    tproxy_cgroup("cgroup/sendmsg4", "tproxy_wan_cg_sendmsg4"),
    tproxy_cgroup("cgroup/sendmsg6", "tproxy_wan_cg_sendmsg6"),
];

const TRACE_KPROBE_COVERAGE: [KernelProgramCoverageLine; 6] = [
    trace_kprobe("kprobe/skb-1", "kprobe_skb_1"),
    trace_kprobe("kprobe/skb-2", "kprobe_skb_2"),
    trace_kprobe("kprobe/skb-3", "kprobe_skb_3"),
    trace_kprobe("kprobe/skb-4", "kprobe_skb_4"),
    trace_kprobe("kprobe/skb-5", "kprobe_skb_5"),
    trace_kprobe(
        "kprobe/skb_lifetime_termination",
        "kprobe_skb_lifetime_termination",
    ),
];

const fn tproxy_classifier(
    c_section: &'static str,
    rust_section: &'static str,
    program_name: &'static str,
) -> KernelProgramCoverageLine {
    KernelProgramCoverageLine {
        surface: KernelProgramSurface::TproxyClassifier,
        c_section,
        rust_section: Some(rust_section),
        program_name,
        status: KernelProgramCoverageStatus::RustNativeAdmitted,
    }
}

const fn tproxy_cgroup(
    section: &'static str,
    program_name: &'static str,
) -> KernelProgramCoverageLine {
    KernelProgramCoverageLine {
        surface: KernelProgramSurface::TproxyCgroup,
        c_section: section,
        rust_section: Some(section),
        program_name,
        status: KernelProgramCoverageStatus::RustNativeAdmitted,
    }
}

const fn trace_kprobe(
    c_section: &'static str,
    program_name: &'static str,
) -> KernelProgramCoverageLine {
    KernelProgramCoverageLine {
        surface: KernelProgramSurface::TraceKprobe,
        c_section,
        rust_section: None,
        program_name,
        status: KernelProgramCoverageStatus::COracleRequired,
    }
}
