use super::*;
use dae_ebpf_support::AttachBackend;

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
        report["generic_udp_dns_datapath_native_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["generic_udp_dns_production_admission_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["production_admission_allowed"].as_bool().unwrap(),
        "UDP/DNS admission alone must not open production daemon switching"
    );
}

#[test]
pub(super) fn production_runtime_owner_native_ebpf_requested_requires_compiled_loader() {
    let options = ProductionRuntimeOwnerOptions {
        native_ebpf_requested: true,
        native_ebpf_backend: AttachBackend::TcNetlink,
        native_ebpf_completed_a3_admission: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let decision = native_ebpf::native_backend_runtime_decision_for_options(&options);
    assert!(decision.native_backend_requested);
    assert!(decision.admission_admitted);
    assert_eq!(
        decision.native_loader_available,
        cfg!(feature = "native-ebpf")
    );
    assert!(decision.command_backend_required);
    assert!(decision.command_backend_available);
    assert!(!decision.automatic_enable_allowed);
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-production-runtime-native-ebpf-{}",
        std::process::id()
    ));
    let report = production_runtime_owner_report(&root, &options).unwrap();
    assert!(
        report["ebpf_backend_capabilities"]["native_backend_admission"]["admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["ebpf_backend_capabilities"]["cgroup_attach"]["aya_cgroup_required"]
            .as_bool()
            .unwrap()
    );
    if cfg!(feature = "native-ebpf") {
        assert!(decision.attempt_native_backend);
        assert_eq!(decision.selected_backend, Some(AttachBackend::TcNetlink));
    } else {
        assert!(!decision.attempt_native_backend);
        assert_eq!(decision.selected_backend, Some(AttachBackend::TcCommand));
        assert_eq!(
            decision.reason,
            dae_ebpf_support::NativeBackendRuntimeReason::NativeLoaderUnavailable
        );
    }
}

#[test]
pub(super) fn production_runtime_owner_native_param_object_keeps_command_param_without_native_request()
 {
    let options = ProductionRuntimeOwnerOptions::default();
    let command_param = std::env::temp_dir().join("dae-native-command-param.o");
    let preparation = native_ebpf::prepare_native_param_object(
        &options,
        &command_param,
        7,
        [1, 2, 3, 4, 5, 6],
        49,
    );
    let selected = preparation.selected_param_object;
    let report = preparation.report;
    assert_eq!(selected, command_param);
    assert_eq!(report["status"].as_str().unwrap(), "skipped");
    assert!(
        report["reason"]
            .as_str()
            .unwrap()
            .contains("native eBPF backend was not requested")
    );
    assert_eq!(
        report["command_param_object"].as_str().unwrap(),
        selected.display().to_string()
    );
}

#[test]
pub(super) fn production_runtime_owner_native_param_object_uses_memory_identity_for_embedded() {
    let options = ProductionRuntimeOwnerOptions {
        native_ebpf_requested: true,
        native_ebpf_embedded_object: true,
        ..ProductionRuntimeOwnerOptions::default()
    };
    let command_param = std::env::temp_dir().join("dae-native-command-param.o");
    let preparation = native_ebpf::prepare_native_param_object(
        &options,
        &command_param,
        7,
        [1, 2, 3, 4, 5, 6],
        49,
    );

    assert_eq!(
        preparation.selected_param_object,
        PathBuf::from(native_ebpf::NATIVE_PARAM_OBJECT_IDENTITY)
    );
    assert_eq!(preparation.report["status"].as_str().unwrap(), "pass");
    assert_eq!(
        preparation.report["source_kind"].as_str().unwrap(),
        "embedded"
    );
    assert_eq!(
        preparation.report["source_object"].as_str().unwrap(),
        native_ebpf::EMBEDDED_NATIVE_OBJECT_IDENTITY
    );
    assert!(!preparation.report["materialized_object"].as_bool().unwrap());
    assert_eq!(
        preparation.report["param_delivery"].as_str().unwrap(),
        "aya-set-global"
    );
    let load_input = preparation.load_input.unwrap();
    assert_eq!(load_input.param.dae0_ifindex, 7);
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
pub(super) fn production_runtime_active_udp_loopback_target_cidr_is_address_family_aware() {
    assert_eq!(
        active_udp_loopback_target_cidr("127.0.0.1").unwrap(),
        "127.0.0.1/32"
    );
    assert_eq!(active_udp_loopback_target_cidr("::1").unwrap(), "::1/128");
}

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
