use super::*;

#[test]
fn source_shape_registry_reports_pending_connect_udp_rows() {
    let contract = source_shape_registry_contract();

    assert_eq!(contract.schema, "outbound-source-shape-registry");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.source_shape_registry_open);
    assert!(contract.expanded_source_matrix_open);
    assert!(!contract.expanded_source_matrix_complete);
    assert!(!contract.production_readiness_may_use_current_config_matrix_as_source_matrix);
    assert!(contract.rows.len() >= 20);
    assert!(
        contract
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
        "socks",
        "socks5",
        "ssr",
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
fn source_shape_registry_keeps_only_explicit_connect_udp_rows_blocked() {
    let rows = source_shape_registry_rows();
    let blocked = rows
        .iter()
        .filter(|row| row.resident_status == "blocked")
        .collect::<Vec<_>>();

    assert_eq!(
        blocked.iter().map(|row| row.shape_id).collect::<Vec<_>>(),
        ["connect-udp-h2-endpoint", "connect-udp-h3-endpoint"]
    );
    assert!(blocked.iter().all(|row| {
        row.protocol_family == "connect-udp"
            && row.link_schemes == ["masque"]
            && row.executor_proof.proof_state == "descriptor-only-fail-closed"
    }));
}

#[test]
fn source_shape_registry_marks_expanded_rows_with_scoped_live_evidence() {
    let rows = source_shape_registry_rows();
    for expected in [
        "insecure-secure-endpoint-underlay",
        "fingerprint-secure-endpoint-underlay",
        "insecure-frame-stream-underlay",
        "full-utls-security-underlay",
        "tls-fragment-security-underlay",
        "reality-security-underlay",
        "shared-reality-security-underlay",
        "mux-transport-wrapper",
        "passthrough-udp-transport",
        "legacy-cipher-protocol-shape",
        "xhttp-h3-wrapper",
        "xhttp-extended-settings-wrapper",
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
        if row.security_underlay.contains("fingerprint") || row.security_underlay == "full-utls" {
            assert!(policy.fingerprint_utls_support, "{}", row.shape_id);
        }
        if row.security_underlay == "tls-fragment" {
            assert!(policy.tls_fragment_support, "{}", row.shape_id);
        }
    }
}

#[test]
fn source_shape_registry_records_scoped_production_readiness_evidence() {
    let evidence = source_shape_registry_contract().scoped_expanded_source_matrix_evidence;

    assert_eq!(evidence.schema, "scoped-expanded-source-evidence");
    assert_eq!(evidence.schema_version, 1);
    assert_eq!(evidence.scope_id, "full-expanded-source-scope");
    assert_eq!(evidence.source_scope, "expanded-source-closure-rows");
    assert!(evidence.excluded_stream_wrappers.is_empty());
    assert_eq!(
        evidence.validation_boundary,
        "external-client-through-resident-proxy"
    );
    assert_eq!(evidence.upstream_boundary, "external-proxy-server-path");
    assert_eq!(evidence.row_count, 27);
    assert_eq!(evidence.pass_count, 27);
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
    assert!(evidence.production_ready);
    for expected in [
        "secure-endpoint-capability",
        "nested-chain-shape",
        "plugin-wrapper-layer",
        "legacy-layer-shape",
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
        "full-utls-security-underlay",
        "tls-fragment-security-underlay",
        "reality-security-underlay",
        "shared-reality-security-underlay",
        "mux-transport-wrapper",
        "passthrough-udp-transport",
        "legacy-cipher-protocol-shape",
        "xhttp-h3-wrapper",
        "xhttp-extended-settings-wrapper",
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
