use super::*;
pub fn kernel_program_parity_evidence_queue(
    evidence: KernelProgramParityEvidence,
) -> Vec<KernelProgramParityEvidenceLine> {
    let mut queue = vec![
        evidence_line(
            KernelProgramParityCheck::TproxyClassifierCoverage,
            "lan_wan_dae0_classifier_sections",
            status_from(evidence.tproxy_classifier_coverage_passed),
            "crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::TproxyCgroupCoverage,
            "sock_create_release_connect_sendmsg_sections",
            status_from(evidence.tproxy_cgroup_coverage_passed),
            "crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::TraceKprobeCoverage,
            "trace_kprobe_sections",
            status_from(evidence.trace_kprobe_coverage_passed),
            "crates/dae-ebpf-program/src/trace.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::RuntimeAdmission,
            "native_runtime_gate",
            status_from(evidence.runtime_admission_passed),
            "scripts/run_native_ebpf_runtime_gate.sh",
        ),
        evidence_line(
            KernelProgramParityCheck::NativeBenchmark,
            "native_daemon_ready_benchmark",
            status_from(evidence.native_benchmark_passed),
            "native benchmark evidence",
        ),
        evidence_line(
            KernelProgramParityCheck::RemoteHostWriteAdmission,
            "remote_host_write_runtime_admission",
            status_from(evidence.remote_host_write_admission_passed),
            "scoped live-host production runtime admission evidence",
        ),
        evidence_line(
            KernelProgramParityCheck::ExternalEbpfObjectAbsent,
            "external_ebpf_tproxy_and_trace_objects_absent",
            status_from(evidence.external_ebpf_object_absent),
            "crates/dae-ebpf-program native object",
        ),
        evidence_line(
            KernelProgramParityCheck::NativeUserspaceBoundaryReady,
            "native_control_plane_outbound_boundary",
            status_from(evidence.native_userspace_boundary_ready),
            "native daemon userspace boundary contract",
        ),
    ];
    queue.extend(trace_kprobe_evidence_queue());
    queue.extend(map_abi_btf_verifier_evidence_queue());
    queue.extend(packet_level_golden_evidence_queue());
    queue.extend(native_benchmark_evidence_queue());
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
            "crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::TproxyCgroupCoverage,
            "sock_create_release_connect_sendmsg_sections",
            status_from(evidence.tproxy_cgroup_coverage_passed),
            "crates/dae-ebpf-program/src/programs.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::RuntimeAdmission,
            "native_runtime_gate",
            status_from(evidence.runtime_admission_passed),
            "scripts/run_native_ebpf_runtime_gate.sh",
        ),
        evidence_line(
            KernelProgramParityCheck::NativeBenchmark,
            "native_daemon_ready_benchmark",
            status_from(evidence.native_benchmark_passed),
            "native benchmark evidence",
        ),
        evidence_line(
            KernelProgramParityCheck::RemoteHostWriteAdmission,
            "remote_host_write_runtime_admission",
            status_from(evidence.remote_host_write_admission_passed),
            "scoped live-host production runtime admission evidence",
        ),
        evidence_line(
            KernelProgramParityCheck::ExternalEbpfObjectAbsent,
            "external_ebpf_tproxy_object_absent",
            status_from(evidence.external_ebpf_object_absent),
            "crates/dae-ebpf-program native object; trace diagnostic excluded from tproxy production candidate",
        ),
        evidence_line(
            KernelProgramParityCheck::NativeUserspaceBoundaryReady,
            "native_control_plane_outbound_boundary",
            status_from(evidence.native_userspace_boundary_ready),
            "native daemon userspace boundary contract",
        ),
    ];
    queue.extend(map_abi_btf_verifier_evidence_queue());
    queue.extend(packet_level_golden_evidence_queue());
    queue.extend(native_benchmark_evidence_queue());
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
            "crates/dae-ebpf-support/src/param_object.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "rust_object_btf_timer_verifier_admission",
            KernelProgramParityEvidenceStatus::Passed,
            "crates/dae-ebpf-program/src/maps.rs",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "native_object_map_catalog_contract",
            KernelProgramParityEvidenceStatus::Passed,
            "crates/dae-ebpf-program",
        ),
        evidence_line(
            KernelProgramParityCheck::MapAbiBtfVerifierParity,
            "pinned_map_upgrade_retry_parity",
            KernelProgramParityEvidenceStatus::Passed,
            "pinned map upgrade retry parity evidence",
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
        "ipv4_non_initial_fragment_pass",
        "ipv6_non_initial_fragment_pass",
        "single_vlan_ipv4",
        "qinq_ipv6",
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
            "crates/dae-ebpf-program/src/packet.rs",
        )
    })
    .collect()
}

pub fn packet_level_golden_evidence_admitted() -> bool {
    evidence_queue_admitted(&packet_level_golden_evidence_queue())
}

pub fn native_benchmark_evidence_queue() -> Vec<KernelProgramParityEvidenceLine> {
    vec![evidence_line(
        KernelProgramParityCheck::NativeBenchmark,
        "count10_native_daemon_ready_benchmark",
        KernelProgramParityEvidenceStatus::Passed,
        "kernel program native benchmark evidence",
    )]
}

pub fn native_benchmark_evidence_admitted() -> bool {
    evidence_queue_admitted(&native_benchmark_evidence_queue())
}

pub fn remote_host_write_runtime_evidence_queue() -> Vec<KernelProgramParityEvidenceLine> {
    [
        "scoped_host_root_gated_runtime_owner_passed",
        "scoped_host_native_attach_peer_lan_host_passed",
        "scoped_host_active_tcp_udp_dns_admitted",
        "scoped_host_reload_runtime_parity_admitted",
        "scoped_host_cleanup_no_netns_link_bpffs_leftovers",
    ]
    .into_iter()
    .map(|item| {
        evidence_line(
            KernelProgramParityCheck::RemoteHostWriteAdmission,
            item,
            KernelProgramParityEvidenceStatus::Passed,
            "scoped live-host runtime admission evidence",
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
        KernelProgramParityCheck::NativeBenchmark,
        KernelProgramParityCheck::RemoteHostWriteAdmission,
        KernelProgramParityCheck::ExternalEbpfObjectAbsent,
        KernelProgramParityCheck::NativeUserspaceBoundaryReady,
    ]
}

pub fn tproxy_dataplane_required_checks() -> Vec<KernelProgramParityCheck> {
    vec![
        KernelProgramParityCheck::TproxyClassifierCoverage,
        KernelProgramParityCheck::TproxyCgroupCoverage,
        KernelProgramParityCheck::MapAbiBtfVerifierParity,
        KernelProgramParityCheck::PacketLevelGoldenParity,
        KernelProgramParityCheck::RuntimeAdmission,
        KernelProgramParityCheck::NativeBenchmark,
        KernelProgramParityCheck::RemoteHostWriteAdmission,
        KernelProgramParityCheck::ExternalEbpfObjectAbsent,
        KernelProgramParityCheck::NativeUserspaceBoundaryReady,
    ]
}
