use super::*;

#[test]
fn security_underlay_capability_admits_common_underlays_only() {
    let contract = security_underlay_capability_contract();

    assert_eq!(contract.schema, "security-underlay-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.common_security_underlay_ready);
    assert!(!contract.expanded_security_underlay_complete);
    assert!(!contract.release_gate_ready);

    for expected in [
        "standard-tls-common-underlay",
        "fingerprint-aware-tls-common-underlay",
        "verification-policy-surface",
        "underlay-routing-options",
    ] {
        let row = contract
            .rows
            .iter()
            .find(|row| row.capability_id == expected)
            .unwrap_or_else(|| panic!("missing common underlay row {expected}"));
        assert_eq!(row.status, "admitted");
        assert_eq!(row.executor_proof, "runtime-executable");
        assert!(row.no_silent_fallback);
        assert!(!row.evidence_requirements.is_empty());
    }
}

#[test]
fn security_underlay_capability_blocks_deferred_or_unsafe_variants() {
    let contract = security_underlay_capability_contract();

    for expected in [
        ("reality-security-underlay", "missing-security-underlay"),
        ("explicit-insecure-live-variant", "missing-live-evidence"),
        ("unknown-fingerprint-request", "missing-security-underlay"),
    ] {
        let row = contract
            .rows
            .iter()
            .find(|row| row.capability_id == expected.0)
            .unwrap_or_else(|| panic!("missing blocked underlay row {}", expected.0));
        assert_eq!(row.status, "blocked");
        assert_eq!(row.blocker_id, Some(expected.1));
        assert_eq!(row.executor_proof, "fail-closed-pending-evidence");
        assert!(row.no_silent_fallback);
    }
}

#[test]
fn security_underlay_capability_keeps_fingerprint_away_from_rustls_fallback() {
    let rows = security_underlay_capability_rows();
    let fingerprint = rows
        .iter()
        .find(|row| row.capability_id == "fingerprint-aware-tls-common-underlay")
        .unwrap();

    assert_eq!(fingerprint.provider, "boringssl");
    assert_eq!(fingerprint.security_underlay, "fingerprint-aware-tls");
    assert!(fingerprint.no_silent_fallback);

    let unknown = rows
        .iter()
        .find(|row| row.capability_id == "unknown-fingerprint-request")
        .unwrap();
    assert_eq!(unknown.status, "blocked");
    assert_eq!(unknown.provider, "fail-closed");
}

#[test]
fn security_underlay_capability_contains_no_runtime_version_suffix_labels() {
    let rendered = security_underlay_capability_contract()
        .to_value()
        .to_string();
    let forbidden = ["-", "v", "1"].concat();

    assert!(
        !rendered.contains(&forbidden),
        "security underlay capability must not expose runtime version suffix labels"
    );
}
