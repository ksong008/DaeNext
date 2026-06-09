use super::*;
use dae_ebpf_support::AttachBackend;
#[test]
pub(super) fn production_runtime_owner_fallback_gate_accepts_product_chain_prereq() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-product-chain-prereq-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        fallback_retirement_product_chain_recertified: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let report = production_runtime_owner_report(&root, &options).unwrap();
    let gate = &report["ebpf_backend_capabilities"]["kernel_program_fallback_retirement_gate"];
    assert!(gate["product_chain_recertified"].as_bool().unwrap());
    assert!(!gate["explicit_user_approval_recorded"].as_bool().unwrap());
    assert!(!gate["admitted"].as_bool().unwrap());
    assert!(!gate["default_switch_allowed"].as_bool().unwrap());
    assert!(gate["go_bpf_fallback_required"].as_bool().unwrap());
    assert!(
        !gate["go_bpf_fallback_retirement_allowed"]
            .as_bool()
            .unwrap()
    );
    let blockers = gate["blockers"].as_array().unwrap();
    assert!(
        blockers
            .iter()
            .any(|entry| entry.as_str().unwrap() == "explicit_user_approval_missing")
    );
    assert!(
        !blockers
            .iter()
            .any(|entry| entry.as_str().unwrap() == "product_chain_recertification_missing")
    );
    assert!(report["go_bpf_fallback_required"].as_bool().unwrap());
    assert!(!report["go_bpf_fallback_retired"].as_bool().unwrap());
    assert!(
        !report["go_bpf_fallback_retirement_gate_admitted"]
            .as_bool()
            .unwrap()
    );
}

#[test]
pub(super) fn production_runtime_owner_fallback_gate_admits_with_explicit_approval() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-explicit-fallback-retirement-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        fallback_retirement_product_chain_recertified: true,
        fallback_retirement_explicit_user_approval: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let report = production_runtime_owner_report(&root, &options).unwrap();
    let gate = &report["ebpf_backend_capabilities"]["kernel_program_fallback_retirement_gate"];
    assert!(gate["product_chain_recertified"].as_bool().unwrap());
    assert!(gate["explicit_user_approval_recorded"].as_bool().unwrap());
    assert!(gate["admitted"].as_bool().unwrap());
    assert!(gate["default_switch_allowed"].as_bool().unwrap());
    assert!(!gate["go_bpf_fallback_required"].as_bool().unwrap());
    assert!(
        gate["go_bpf_fallback_retirement_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().is_empty());
    assert!(!report["go_bpf_fallback_required"].as_bool().unwrap());
    assert!(report["go_bpf_fallback_retired"].as_bool().unwrap());
    assert!(
        report["go_bpf_fallback_retirement_gate_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["default_switch_allowed"].as_bool().unwrap(),
        "A5 admits fallback retirement but does not mutate the daemon default path"
    );
    assert!(
        report["go_default_path_preserved"].as_bool().unwrap(),
        "A5 does not mutate the daemon default path"
    );
    assert!(
            report["ebpf_backend_capabilities"]["kernel_program_fallback_retirement_gate"]
                ["c_trace_object_retirement_allowed"]
                .as_bool()
                .unwrap()
        );
    assert!(
            !report["ebpf_backend_capabilities"]["kernel_program_fallback_retirement_gate"]
                ["tc_command_fallback_retirement_allowed"]
                .as_bool()
                .unwrap()
        );
}

#[test]
pub(super) fn production_runtime_owner_report_admits_generic_udp_dns_with_evidence_and_benchmarks()
{
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-udp-dns-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("run").join("production-runtime-owner");
    let manifest_file = artifact_dir.join("production-runtime-owner.json");
    let param_object = artifact_dir.join("bpf_bpfel.param.o");
    let evidence = ExecutionEvidence {
        active_udp: ActiveUdpEvidence {
            enabled: true,
            passed: true,
            original_destination_observed: true,
            endpoint_pool_live_recorded: true,
            outbound_packet_conn_recorded: true,
            sendpkt_reply_recorded: true,
            so_mark_observed: true,
            benchmark: serde_json::json!({"status": "pass"}),
            ..ActiveUdpEvidence::default()
        },
        active_dns: ActiveDnsEvidence {
            enabled: true,
            passed: true,
            original_destination_observed: true,
            dns_controller_recorded: true,
            dns_upstream_query_recorded: true,
            dns_response_validation_recorded: true,
            dns_cache_restore_recorded: true,
            domain_routing_owner_migration_recorded: true,
            sendpkt_reply_recorded: true,
            so_mark_observed: true,
            benchmark: serde_json::json!({"status": "pass"}),
            ..ActiveDnsEvidence::default()
        },
        ..ExecutionEvidence::default()
    };
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        execute_active_udp: true,
        execute_active_dns: true,
        ..ProductionRuntimeOwnerOptions::default()
    };

    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        &param_object,
        Vec::new(),
        evidence,
    );

    assert!(
        report["generic_udp_dns_datapath_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["generic_udp_dns_datapath_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["generic_udp_dns_datapath_go_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["generic_udp_dns_default_switch_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["default_switch_allowed"].as_bool().unwrap(),
        "UDP/DNS admission alone must not open default daemon switching"
    );
}

#[test]
pub(super) fn production_runtime_owner_native_ebpf_opt_in_requires_compiled_loader() {
    let options = ProductionRuntimeOwnerOptions {
        native_ebpf_opt_in: true,
        native_ebpf_backend: AttachBackend::TcNetlink,
        native_ebpf_completed_a3_admission: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let decision = native_ebpf::native_backend_runtime_decision(&options);
    assert!(decision.opt_in_enabled);
    assert!(decision.admission_admitted);
    assert_eq!(
        decision.native_loader_available,
        cfg!(feature = "native-ebpf")
    );
    assert!(decision.fallback_required);
    assert!(decision.fallback_preserved);
    assert!(!decision.default_enable_allowed);
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-native-ebpf-{}",
        std::process::id()
    ));
    let report = production_runtime_owner_report(&root, &options).unwrap();
    assert!(
        report["go_bpf_loader_retirement_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["go_bpf_fallback_retirement_gate_admitted"]
            .as_bool()
            .unwrap(),
        "A3/native admission is not explicit fallback retirement approval"
    );
    assert!(report["go_bpf_fallback_required"].as_bool().unwrap());
    assert!(!report["go_bpf_fallback_retired"].as_bool().unwrap());
    assert!(
        report["ebpf_backend_capabilities"]["native_backend_admission"]["admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["ebpf_backend_capabilities"]["cgroup_attach"]["go_attachcgroup_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["ebpf_backend_capabilities"]["cgroup_attach"]["go_attachcgroup_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    if cfg!(feature = "native-ebpf") {
        assert!(decision.attempt_native_backend);
        assert_eq!(decision.selected_backend, Some(AttachBackend::TcNetlink));
    } else {
        assert!(!decision.attempt_native_backend);
        assert_eq!(
            decision.selected_backend,
            Some(AttachBackend::TcCommandFallback)
        );
        assert_eq!(
            decision.reason,
            dae_ebpf_support::NativeBackendOptInReason::NativeLoaderUnavailable
        );
    }
}

#[test]
pub(super) fn production_runtime_owner_native_param_object_keeps_fallback_without_native_object() {
    let options = ProductionRuntimeOwnerOptions {
        native_ebpf_opt_in: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let fallback = std::env::temp_dir().join("dae-native-fallback-param.o");
    let native = std::env::temp_dir().join("dae-native-param.o");
    let (selected, report) = native_ebpf::prepare_native_param_object(
        &options,
        &fallback,
        &native,
        7,
        [1, 2, 3, 4, 5, 6],
        49,
    );
    assert_eq!(selected, fallback);
    assert_eq!(report["status"].as_str().unwrap(), "skipped");
    assert!(
        report["reason"]
            .as_str()
            .unwrap()
            .contains("native eBPF object is not configured")
    );
    assert_eq!(
        report["fallback_param_object"].as_str().unwrap(),
        selected.display().to_string()
    );
}

#[test]
pub(super) fn production_runtime_owner_execute_requires_root_gate_ack() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-noack-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("--ack-root-gate"));
}

#[test]
pub(super) fn production_runtime_owner_rejects_zero_tproxy_port() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-zero-port-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        tproxy_port: 0,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("tproxy port"));
}

#[test]
pub(super) fn production_runtime_active_tcp_requires_owner_execution() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-active-tcp-without-owner-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        ack_root_gate: true,
        execute_active_tcp: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("--execute-production-runtime-owner"));
}

#[test]
pub(super) fn production_runtime_active_tcp_relay_requires_active_tcp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-active-tcp-relay-without-tcp-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        execute_active_tcp_relay: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("--execute-production-runtime-active-tcp"));
}

#[test]
pub(super) fn production_runtime_active_udp_requires_active_tcp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-active-udp-without-tcp-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        execute_active_udp: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("--execute-production-runtime-active-tcp"));
}

#[test]
pub(super) fn production_runtime_active_dns_requires_active_udp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-active-dns-without-udp-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        execute_active_tcp: true,
        execute_active_dns: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("--execute-production-runtime-active-udp"));
}

const CONFIGURED_ACTIVE_DNS_TEST_PORT: u16 = 8053;

#[test]
pub(super) fn production_runtime_active_dns_requires_nonzero_target_port() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-active-dns-zero-port-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        active_dns_target_port: 0,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("target port must be non-zero"));
}

#[test]
pub(super) fn production_runtime_active_dns_accepts_configured_target_port() {
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        execute_active_tcp: true,
        execute_active_udp: true,
        execute_active_dns: true,
        active_dns_target_ip: std::net::Ipv4Addr::LOCALHOST.to_string(),
        active_dns_target_port: CONFIGURED_ACTIVE_DNS_TEST_PORT,
        ..ProductionRuntimeOwnerOptions::default()
    };
    validate_options(&options).unwrap();
}

#[test]
pub(super) fn production_reload_runtime_parity_requires_active_tcp() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-reload-without-tcp-{}",
        std::process::id()
    ));
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        execute_reload_runtime_parity: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let err = production_runtime_owner_report(&root, &options).unwrap_err();
    assert!(err.contains("--execute-production-runtime-active-tcp"));
}
