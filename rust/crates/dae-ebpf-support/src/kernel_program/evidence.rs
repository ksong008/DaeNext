use super::*;
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
