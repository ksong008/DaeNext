use super::*;

#[test]
fn source_shape_registry_reports_connect_udp_rows_with_matrix_scope() {
    let contract = source_shape_registry_contract();

    assert_eq!(contract.schema, "outbound-source-shape-registry");
    assert_eq!(contract.schema_version, 2);
    assert!(contract.source_shape_registry_open);
    assert!(contract.expanded_source_matrix_open);
    assert!(!contract.expanded_source_matrix_complete);
    assert!(!contract.production_readiness_may_use_current_config_matrix_as_source_matrix);
    assert!(contract.rows.len() >= 20);
    assert!(
        !contract
            .scoped_expanded_source_matrix_evidence
            .production_ready
    );
    assert_eq!(
        contract
            .scoped_expanded_source_matrix_evidence
            .excluded_stream_wrappers,
        &[] as &[&str]
    );
}

#[test]
fn source_shape_registry_current_baseline_rows_follow_matrix_contract() {
    let rows = source_shape_registry_rows();
    let baseline_rows = rows
        .iter()
        .filter(|row| row.shape_id.starts_with("baseline-"))
        .filter(|row| row.resident_status == "admitted-baseline")
        .collect::<Vec<_>>();

    assert!(baseline_rows.len() >= 10);
    for row in baseline_rows {
        assert!(!row.protocol_family.is_empty(), "{}", row.shape_id);
        assert!(!row.link_schemes.is_empty(), "{}", row.shape_id);
        assert_eq!(row.source_support, "source-supported");
        assert_eq!(row.state_ledger.resident_graph, "admitted");
        assert_eq!(row.executor_proof.proof_state, "runtime-executable");
        assert!(!row.expanded_live_matrix.blocked_rows_reduce_pass_threshold);
        assert!(row.redacted_identity.starts_with("registry:"));
    }
}

#[test]
fn source_shape_registry_link_schemes_are_common_import_carriers() {
    let allowed_schemes = [
        "anytls",
        "chain",
        "http",
        "https",
        "hy2",
        "hysteria2",
        "juicity",
        "masque",
        "ss",
        "shadowsocks",
        "socks",
        "socks5",
        "ssr",
        "shadowsocksr",
        "trojan",
        "trojan-go",
        "tuic",
        "vless",
        "vmess",
    ];
    let transport_only_labels = ["tls", "utls", "reality", "mux", "passthrough-udp"];

    for row in source_shape_registry_rows() {
        if row.source_support != "source-supported" {
            continue;
        }
        for scheme in row.link_schemes {
            assert!(
                allowed_schemes.contains(scheme),
                "{} uses non-import link scheme {}",
                row.shape_id,
                scheme
            );
            assert!(
                !transport_only_labels.contains(scheme),
                "{} must describe transport capabilities outside link_schemes: {}",
                row.shape_id,
                scheme
            );
        }
    }
}

#[test]
fn source_shape_registry_admits_h2_and_h3_connect_udp_independently() {
    let rows = source_shape_registry_rows();
    let connect_udp = rows
        .iter()
        .filter(|row| row.protocol_family == "connect-udp")
        .collect::<Vec<_>>();

    assert_eq!(
        connect_udp
            .iter()
            .map(|row| row.shape_id)
            .collect::<Vec<_>>(),
        ["connect-udp-h2-endpoint", "connect-udp-h3-endpoint"]
    );
    assert!(connect_udp.iter().all(|row| {
        row.resident_status == "admitted-baseline"
            && row.link_schemes == ["masque"]
            && row.executor_proof.proof_state == "runtime-executable"
    }));
}

#[test]
fn source_shape_registry_marks_expanded_rows_with_scoped_live_evidence() {
    let rows = source_shape_registry_rows();
    for expected in [
        "insecure-secure-endpoint-underlay",
        "fingerprint-secure-endpoint-underlay",
        "insecure-frame-stream-underlay",
        "tls-fragment-security-underlay",
        "reality-security-underlay",
        "shared-reality-security-underlay",
        "mux-transport-wrapper",
        "legacy-cipher-protocol-shape",
        "xhttp-h3-wrapper",
    ] {
        let row = rows
            .iter()
            .find(|row| row.shape_id == expected)
            .unwrap_or_else(|| panic!("missing admitted underlay row {expected}"));
        assert_eq!(row.resident_status, "admitted-baseline", "{expected}");
        assert_eq!(row.blocker_id, None, "{expected}");
        assert_eq!(
            row.expanded_live_matrix.ledger_state, "scoped-live-host-evidence-ready",
            "{expected}"
        );
        assert!(
            row.production_readiness.expanded_source_agrees,
            "{expected}"
        );
        assert!(
            row.production_readiness.service_contract_agrees,
            "{expected}"
        );
        assert!(
            row.production_readiness.cleanup_evidence_ready,
            "{expected}"
        );
    }
}

#[test]
fn source_shape_registry_represents_official_common_fixture_shapes() {
    let rows = source_shape_registry_rows();
    let row_shape_ids = rows.iter().map(|row| row.shape_id).collect::<Vec<_>>();
    let official_common_shape_ids = official_common_source_shape_ids();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/rebuild-golden/outbound/protocol");

    for shape_id in official_common_shape_ids {
        assert!(
            row_shape_ids.contains(shape_id),
            "official/common shape {shape_id} is absent from source registry"
        );
    }

    for requirement in official_common_fixture_requirements() {
        assert!(
            official_common_shape_ids.contains(&requirement.shape_id),
            "fixture requirement {} points to non-official/common shape {}",
            requirement.marker,
            requirement.shape_id
        );
        assert!(
            row_shape_ids.contains(&requirement.shape_id),
            "fixture requirement {} points to absent registry row {}",
            requirement.marker,
            requirement.shape_id
        );
        let fixture = root.join(requirement.fixture);
        let text = std::fs::read_to_string(&fixture)
            .unwrap_or_else(|err| panic!("read {}: {err}", fixture.display()));
        assert!(
            text.contains(requirement.marker),
            "{} must retain marker {} for source registry coverage",
            requirement.fixture,
            requirement.marker
        );
    }
}

#[test]
fn source_shape_registry_admitted_rows_are_runtime_executable_and_evidence_gated() {
    let rows = source_shape_registry_rows();
    let scoped_evidence = source_shape_registry_contract().scoped_expanded_source_matrix_evidence;

    for row in rows
        .iter()
        .filter(|row| row.source_support == "source-supported")
        .filter(|row| row.resident_status == "admitted-baseline")
    {
        assert_eq!(row.blocker_id, None, "{}", row.shape_id);
        assert_eq!(
            row.state_ledger.resident_graph, "admitted",
            "{}",
            row.shape_id
        );
        assert_eq!(
            row.executor_proof.proof_state, "runtime-executable",
            "{}",
            row.shape_id
        );
        assert_eq!(
            row.runtime_selection.selected_runtime_scope, "current-selected-resident-graph",
            "{}",
            row.shape_id
        );
        if scoped_evidence.opened_rows.contains(&row.shape_id) {
            assert_eq!(
                row.expanded_live_matrix.ledger_state, "scoped-live-host-evidence-ready",
                "{}",
                row.shape_id
            );
            assert!(
                row.production_readiness.expanded_source_agrees,
                "{}",
                row.shape_id
            );
            assert!(
                row.production_readiness.service_contract_agrees,
                "{}",
                row.shape_id
            );
            assert!(
                row.production_readiness.cleanup_evidence_ready,
                "{}",
                row.shape_id
            );
            assert!(
                !row.production_readiness.final_state_ready,
                "{}",
                row.shape_id
            );
        } else {
            assert_eq!(
                row.expanded_live_matrix.ledger_state, "pending-live-host-evidence",
                "{}",
                row.shape_id
            );
        }
        for required in ["large-page-live", "benchmark", "cleanup"] {
            assert!(
                row.evidence_requirements.contains(&required),
                "{} missing {required}",
                row.shape_id
            );
        }
        assert!(
            row.redacted_identity.starts_with("registry:"),
            "{}",
            row.shape_id
        );
    }
}

#[test]
fn source_shape_registry_rows_have_typed_capability_contracts() {
    for row in source_shape_registry_rows() {
        let typed = row
            .typed_capability_contract()
            .unwrap_or_else(|| panic!("{} has no typed capability contract", row.shape_id));
        assert_eq!(
            typed.protocol_framing.as_report_str(),
            row.protocol_family,
            "{}",
            row.shape_id
        );
        assert_eq!(
            typed.security_underlay.as_report_str(),
            row.security_underlay,
            "{}",
            row.shape_id
        );
        assert_eq!(
            typed.stream_wrapper.as_report_str(),
            row.stream_wrapper,
            "{}",
            row.shape_id
        );
        assert_eq!(
            typed.packet_semantics.as_report_str(),
            row.packet_semantics,
            "{}",
            row.shape_id
        );
        assert_eq!(typed.schema_version, 1, "{}", row.shape_id);
        assert!(
            !typed.executor.as_report_str().is_empty(),
            "{}",
            row.shape_id
        );
        match row.resident_status {
            "admitted-baseline" => {
                assert_eq!(
                    typed.source_shape_state,
                    SourceShapeState::Admitted,
                    "{}",
                    row.shape_id
                )
            }
            "blocked" => {
                assert_eq!(
                    typed.source_shape_state,
                    SourceShapeState::Blocked,
                    "{}",
                    row.shape_id
                );
                assert_eq!(
                    typed.executor,
                    ExecutorKind::PolicyClosed,
                    "{}",
                    row.shape_id
                );
            }
            "not-source-supported" => assert_eq!(
                typed.source_shape_state,
                SourceShapeState::NotSourceSupported,
                "{}",
                row.shape_id
            ),
            other => panic!("{} has unexpected resident status {other}", row.shape_id),
        }
    }
}

#[test]
fn source_shape_registry_rows_have_explicit_security_underlay_policy() {
    for row in source_shape_registry_rows() {
        let policy = row
            .security_underlay_policy_contract()
            .unwrap_or_else(|| panic!("{} has no security underlay policy", row.shape_id));
        assert_eq!(policy.schema_version, 1, "{}", row.shape_id);
        assert_eq!(policy.blocked_reason, row.blocker_id, "{}", row.shape_id);
        assert!(!policy.pin_requirement.is_empty(), "{}", row.shape_id);

        if row.security_underlay == "insecure-tls" {
            assert!(policy.allow_insecure_support, "{}", row.shape_id);
        }
        if row.security_underlay.contains("reality") {
            assert!(policy.reality_support, "{}", row.shape_id);
        }
        if (row.security_underlay.contains("fingerprint")
            && !row.security_underlay.contains("without-fingerprint"))
            || row.security_underlay == "full-utls"
        {
            assert!(policy.fingerprint_utls_support, "{}", row.shape_id);
        }
        if row.security_underlay.contains("without-fingerprint") {
            assert!(!policy.fingerprint_utls_support, "{}", row.shape_id);
        }
        if row.security_underlay == "tls-fragment" {
            assert!(policy.tls_fragment_support, "{}", row.shape_id);
        }
    }
}

#[test]
fn source_shape_registry_rows_have_explicit_runtime_ownership_ledgers() {
    for row in source_shape_registry_rows() {
        let ledger = row.runtime_ownership_ledger();
        assert_eq!(
            ledger["schema"], "runtime-shape-ownership-ledger",
            "{}",
            row.shape_id
        );
        assert_eq!(ledger["schemaVersion"], 2, "{}", row.shape_id);
        assert_eq!(
            ledger["redactedIdentity"], row.redacted_identity,
            "{}",
            row.shape_id
        );
        assert!(
            !ledger["model"].as_str().unwrap().is_empty(),
            "{}",
            row.shape_id
        );
        assert!(
            matches!(
                ledger["disposition"].as_str().unwrap(),
                "implemented" | "intentionally-per-flow" | "fail-closed" | "blocked"
            ),
            "{}",
            row.shape_id
        );
        assert!(
            ledger["allowedMaterializedModels"]
                .as_array()
                .is_some_and(|models| !models.is_empty()),
            "{}",
            row.shape_id
        );
        assert!(
            !row.runtime_ownership
                .allowed_materialized_models
                .contains(&RuntimeOwnershipModel::MaterializedProtocolTransport),
            "{} may not use an aggregate model as a materialized escape hatch",
            row.shape_id
        );
        if row.runtime_ownership.model != RuntimeOwnershipModel::MaterializedProtocolTransport {
            assert_eq!(
                row.runtime_ownership.allowed_materialized_models,
                &[row.runtime_ownership.model],
                "{} exact ownership rows require one exact materialized model",
                row.shape_id
            );
        }
        for caller in [
            "dataTcp",
            "dataUdp",
            "healthTcp",
            "healthDns",
            "manual",
            "configuredDns",
            "forcedManagedDns",
        ] {
            let route = &ledger["callers"][caller];
            assert!(route["admission"].is_string(), "{} {caller}", row.shape_id);
            assert!(
                route["physicalCarrier"].is_string(),
                "{} {caller}",
                row.shape_id
            );
            assert!(
                route["logicalLease"].is_string(),
                "{} {caller}",
                row.shape_id
            );
            assert!(
                route["lifecycleOwner"].is_string(),
                "{} {caller}",
                row.shape_id
            );
            assert!(
                route["keyContract"].is_string(),
                "{} {caller}",
                row.shape_id
            );
            assert!(
                route["budgetContract"].is_string(),
                "{} {caller}",
                row.shape_id
            );
        }
        for evidence in [
            "scope",
            "parser",
            "configurationMaterialization",
            "localExecutablePath",
            "resourceValidation",
            "immutableArtifact",
            "authorizedLiveInteroperability",
        ] {
            assert!(
                ledger["evidence"][evidence].is_string(),
                "{} {evidence}",
                row.shape_id
            );
        }
    }
}

#[test]
fn runtime_ownership_ledger_keeps_raw_streams_intentionally_per_flow() {
    for shape_id in [
        "baseline-aead-cipher-endpoint",
        "baseline-tls-auth-endpoint",
        "baseline-aead-framed-endpoint",
        "baseline-tls-vision-endpoint",
    ] {
        let row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == shape_id)
            .unwrap();
        let ledger = row.runtime_ownership_ledger();
        assert_eq!(
            ledger["disposition"], "intentionally-per-flow",
            "{shape_id}"
        );
        assert_eq!(
            ledger["callers"]["dataTcp"]["physicalCarrier"], "per-flow-stream",
            "{shape_id}"
        );
        assert_eq!(
            ledger["callers"]["dataTcp"]["lifecycleOwner"], "flow",
            "{shape_id}"
        );
    }
}

#[test]
fn runtime_ownership_ledger_exposes_caller_scoped_quic_cost_boundary() {
    for (shape_id, model, packet_lease) in [
        (
            "baseline-quic-auth-endpoint",
            "caller-scoped-hysteria2-transport",
            "hysteria2-session",
        ),
        (
            "baseline-quic-uuid-endpoint",
            "caller-scoped-tuic-transport",
            "tuic-association",
        ),
        (
            "baseline-quic-password-endpoint",
            "caller-scoped-juicity-transport",
            "juicity-packet-stream",
        ),
        (
            "quic-port-hopping-surface",
            "caller-scoped-hysteria2-transport",
            "hysteria2-session",
        ),
        (
            "verified-quic-security-underlay",
            "caller-scoped-tuic-transport",
            "tuic-association",
        ),
    ] {
        let row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == shape_id)
            .unwrap();
        let ledger = row.runtime_ownership_ledger();
        assert_eq!(ledger["model"], model, "{shape_id}");
        assert_eq!(ledger["disposition"], "blocked", "{shape_id}");
        assert_eq!(
            ledger["callers"]["dataUdp"]["logicalLease"], packet_lease,
            "{shape_id}"
        );
        for caller in [
            "dataTcp",
            "dataUdp",
            "healthTcp",
            "healthDns",
            "manual",
            "configuredDns",
            "forcedManagedDns",
        ] {
            assert_eq!(
                ledger["callers"][caller]["physicalCarrier"], "quic-endpoint-and-connection",
                "{shape_id} {caller}"
            );
            assert_eq!(
                ledger["callers"][caller]["budgetContract"],
                "physical-owner-count-and-charged-bytes-missing",
                "{shape_id} {caller}"
            );
        }
    }
}

#[test]
fn runtime_ownership_source_evidence_does_not_claim_materialized_execution() {
    for row in source_shape_registry_rows()
        .iter()
        .filter(|row| row.resident_status == "admitted-baseline")
    {
        let source = row.runtime_ownership_ledger();
        assert_eq!(
            source["evidence"]["scope"], "source-contract",
            "{}",
            row.shape_id
        );
        assert_eq!(
            source["evidence"]["configurationMaterialization"], "pending",
            "{}",
            row.shape_id
        );
        assert_eq!(
            source["evidence"]["localExecutablePath"], "pending",
            "{}",
            row.shape_id
        );

        let materialized = row
            .runtime_ownership
            .to_materialized_value(row.redacted_identity);
        assert_eq!(materialized["evidence"]["scope"], "materialized-runtime");
        assert_eq!(
            materialized["evidence"]["configurationMaterialization"],
            "verified"
        );
        assert_eq!(materialized["evidence"]["localExecutablePath"], "verified");
    }
}

#[test]
fn runtime_ownership_dns_callers_keep_distinct_lifecycle_contracts() {
    let row = source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "baseline-quic-auth-endpoint")
        .unwrap();
    let ledger = row.runtime_ownership_ledger();
    let callers = &ledger["callers"];
    assert_eq!(
        callers["configuredDns"]["lifecycleOwner"],
        "configured-dns-forwarder"
    );
    assert_eq!(
        callers["configuredDns"]["keyContract"],
        "generation-graph-and-transport"
    );
    assert_eq!(
        callers["forcedManagedDns"]["lifecycleOwner"],
        "udp-session-manager"
    );
    assert_eq!(
        callers["forcedManagedDns"]["keyContract"],
        "udp-session-graph-target-and-transport"
    );
}

#[test]
fn configured_http_owner_remains_blocked_until_byte_charging_is_present() {
    for shape_id in [
        "stream-wrapper-xhttp",
        "xhttp-h3-wrapper",
        "xhttp-extended-settings-wrapper",
    ] {
        let row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == shape_id)
            .unwrap();
        let ledger = row.runtime_ownership_ledger();
        assert_eq!(ledger["model"], "configured-http-transport", "{shape_id}");
        assert_eq!(ledger["disposition"], "blocked", "{shape_id}");
        assert_eq!(
            ledger["callers"]["dataTcp"]["budgetContract"],
            "configured-connection-count-with-charged-bytes-missing",
            "{shape_id}"
        );
    }
}

#[test]
fn materialized_owner_models_require_explicit_source_allow_lists() {
    assert!(
        MATERIALIZED_STREAM_SECURITY_OWNERSHIP
            .accepts_materialized(RuntimeOwnershipModel::FlowStreamAndPacketSession)
    );
    assert!(
        MATERIALIZED_STREAM_SECURITY_OWNERSHIP
            .accepts_materialized(RuntimeOwnershipModel::ConfiguredHttpTransport)
    );
    assert!(
        !MATERIALIZED_STREAM_SECURITY_OWNERSHIP
            .accepts_materialized(RuntimeOwnershipModel::CallerScopedHysteria2Transport)
    );
    assert!(
        !MATERIALIZED_CHAIN_OWNERSHIP
            .accepts_materialized(RuntimeOwnershipModel::SourceAdmissionRejected)
    );
    assert!(
        MATERIALIZED_CHAIN_OWNERSHIP
            .accepts_materialized(RuntimeOwnershipModel::FlowStreamAndPacketSession)
    );
    assert!(
        MATERIALIZED_CHAIN_OWNERSHIP
            .accepts_materialized(RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed)
    );
    for impossible_chain_model in [
        RuntimeOwnershipModel::FlowStreamAndAssociation,
        RuntimeOwnershipModel::CallerScopedHysteria2Transport,
        RuntimeOwnershipModel::CallerScopedTuicTransport,
        RuntimeOwnershipModel::CallerScopedJuicityTransport,
        RuntimeOwnershipModel::GenerationConnectUdpTransport,
        RuntimeOwnershipModel::ConfiguredHttpTransport,
    ] {
        assert!(
            !MATERIALIZED_CHAIN_OWNERSHIP.accepts_materialized(impossible_chain_model),
            "nested chain must not admit {impossible_chain_model:?}"
        );
    }
    assert!(
        !QUIC_FAMILY_MATERIALIZED_OWNERSHIP
            .accepts_materialized(RuntimeOwnershipModel::ConfiguredHttpTransport)
    );
}

#[test]
fn materialized_shape_rejection_records_no_carrier_and_is_not_source_rejection() {
    let rejection = MATERIALIZED_SHAPE_REJECTED_OWNERSHIP;

    assert_eq!(
        rejection.model,
        RuntimeOwnershipModel::MaterializedShapeRejected
    );
    assert_eq!(
        rejection.disposition,
        RuntimeOwnershipDisposition::FailClosed
    );
    assert_eq!(
        rejection.data_tcp.admission,
        RuntimeRouteAdmission::FailClosed
    );
    assert_eq!(
        rejection.data_tcp.physical_carrier,
        PhysicalCarrierKind::None
    );
    assert_eq!(rejection.data_tcp.logical_lease, LogicalLeaseKind::None);
    assert_eq!(
        rejection.data_tcp.lifecycle_owner,
        RuntimeLifecycleOwner::ResolvedAtMaterialization
    );
    assert!(rejection.accepts_materialized(RuntimeOwnershipModel::MaterializedShapeRejected));
    assert!(!rejection.accepts_materialized(RuntimeOwnershipModel::SourceAdmissionRejected));
    assert!(source_shape_registry_rows().iter().all(|row| {
        !row.runtime_ownership
            .accepts_materialized(RuntimeOwnershipModel::MaterializedShapeRejected)
    }));

    let ledger = rejection.to_materialization_rejected_value("runtime:redacted");
    assert_eq!(ledger["evidence"]["scope"], "materialized-runtime");
    assert_eq!(
        ledger["evidence"]["configurationMaterialization"],
        "rejected"
    );
    assert_eq!(ledger["evidence"]["localExecutablePath"], "rejected");
}

#[test]
fn runtime_ownership_ledger_keeps_policy_rejection_pre_network() {
    for row in source_shape_registry_rows()
        .iter()
        .filter(|row| row.source_support == "not-source-supported")
    {
        let ledger = row.runtime_ownership_ledger();
        assert_eq!(
            ledger["model"], "source-admission-rejected",
            "{}",
            row.shape_id
        );
        assert_eq!(ledger["disposition"], "fail-closed", "{}", row.shape_id);
        assert_eq!(ledger["evidence"]["parser"], "rejected", "{}", row.shape_id);
        assert_eq!(
            ledger["callers"]["dataTcp"]["admission"], "fail-closed",
            "{}",
            row.shape_id
        );
        assert_eq!(
            ledger["callers"]["dataUdp"]["admission"], "fail-closed",
            "{}",
            row.shape_id
        );
    }
}

#[test]
fn source_shape_registry_records_scoped_production_readiness_evidence() {
    let evidence = source_shape_registry_contract().scoped_expanded_source_matrix_evidence;

    assert_eq!(evidence.schema, "scoped-expanded-source-evidence");
    assert_eq!(evidence.schema_version, 1);
    assert_eq!(evidence.scope_id, "validated-expanded-source-subset");
    assert_eq!(evidence.source_scope, "historical-live-evidence-subset");
    assert!(evidence.excluded_stream_wrappers.is_empty());
    assert_eq!(
        evidence.validation_boundary,
        "external-client-through-resident-proxy"
    );
    assert_eq!(evidence.upstream_boundary, "external-proxy-server-path");
    assert_eq!(evidence.row_count, 23);
    assert_eq!(evidence.pass_count, 23);
    assert!(evidence.all_pass);
    assert!(evidence.large_page_all_pass);
    assert!(evidence.proxy_evidence_all_pass);
    assert!(evidence.benchmark_evidence_ready);
    assert_eq!(
        evidence.benchmark_evidence_kind,
        "large-page-threshold-and-body-hash"
    );
    assert!(evidence.cleanup_evidence_ready);
    assert!(!evidence.raw_links_retained);
    assert!(!evidence.raw_bodies_retained);
    assert!(!evidence.raw_state_retained);
    assert!(!evidence.production_ready);
    for expected in [
        "secure-endpoint-capability",
        "nested-chain-shape",
        "plugin-wrapper-layer",
        "stream-wrapper-meek",
        "stream-wrapper-xhttp",
        "secure-websocket-framed-endpoint",
        "secure-httpupgrade-framed-endpoint",
        "verified-quic-security-underlay",
        "quic-port-hopping-surface",
        "inner-encryption-stream-wrapper",
        "obfs-tls-plugin-wrapper",
        "tls-websocket-plugin-wrapper",
        "aead-2022-plugin-wrapper",
        "proxy-transport-mode",
        "insecure-secure-endpoint-underlay",
        "fingerprint-secure-endpoint-underlay",
        "insecure-frame-stream-underlay",
        "tls-fragment-security-underlay",
        "reality-security-underlay",
        "shared-reality-security-underlay",
        "mux-transport-wrapper",
        "legacy-cipher-protocol-shape",
        "xhttp-h3-wrapper",
    ] {
        assert!(evidence.opened_rows.contains(&expected), "{expected}");
    }
}

#[test]
fn source_shape_registry_rejects_non_native_policy_shapes() {
    let rows = source_shape_registry_rows();
    for expected in [
        "non-native-abi-outbound-shape",
        "external-runtime-dependent-shape",
        "non-native-executor-dependent-shape",
    ] {
        let row = rows
            .iter()
            .find(|row| row.shape_id == expected)
            .unwrap_or_else(|| panic!("missing rejected row {expected}"));
        assert_eq!(row.source_support, "not-source-supported");
        assert_eq!(row.resident_status, "not-source-supported");
        assert_eq!(row.blocker_id, Some("unsupported-source-policy"));
        assert_eq!(row.parser_coverage, "rejected");
    }
}

#[test]
fn source_shape_registry_contains_no_runtime_version_suffix_labels() {
    let rendered = source_shape_registry_contract().to_value().to_string();
    let forbidden = ["-", "v", "1"].concat();
    assert!(
        !rendered.contains(&forbidden),
        "source shape registry must not expose runtime version suffix labels"
    );
}

#[test]
fn source_shape_registry_uses_protocol_generic_matrix_semantics() {
    let rendered = source_shape_registry_contract().to_value().to_string();
    let forbidden = [
        "matrix-",
        "://matrix",
        "/matrix-",
        "#matrix-",
        "tag=matrix-",
        "name=matrix-",
    ];

    for needle in forbidden {
        assert!(
            !rendered.contains(needle),
            "source shape registry must use protocol-generic matrix semantics, found {needle}"
        );
    }
    for digit in '0'..='9' {
        let needle = format!("{}{}{}", "sta", "ge", digit);
        assert!(
            !rendered.contains(&needle),
            "source shape registry must use protocol-generic semantics, found {needle}"
        );
    }
}
