use super::*;

#[test]
fn security_underlay_capability_admits_common_underlays_only() {
    let contract = security_underlay_capability_contract();

    assert_eq!(contract.schema, "security-underlay-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.common_security_underlay_ready);
    assert!(contract.expanded_security_underlay_complete);
    assert!(contract.production_ready);

    for expected in [
        "standard-tls-common-underlay",
        "fingerprint-aware-tls-common-underlay",
        "reality-common-underlay",
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
        assert!(row.no_silent_downgrade);
        assert!(!row.evidence_requirements.is_empty());
    }
}

#[test]
fn security_underlay_capability_closes_non_xhttp_boundaries() {
    let contract = security_underlay_capability_contract();

    for row in contract.rows {
        assert!(
            matches!(row.status, "admitted" | "fail-closed-final"),
            "{}",
            row.capability_id
        );
        assert_eq!(row.blocker_id, None, "{}", row.capability_id);
        assert!(row.no_silent_downgrade);
        assert!(!row.evidence_requirements.is_empty());
        if row.status == "fail-closed-final" {
            assert_eq!(row.executor_proof, "negative-boundary-proved");
            assert!(row.evidence_requirements.contains(&"negative-fixture"));
        } else {
            assert_eq!(row.executor_proof, "runtime-executable");
        }
    }
}

#[test]
fn security_underlay_capability_keeps_fingerprint_on_boringssl() {
    let rows = security_underlay_capability_rows();
    let fingerprint = rows
        .iter()
        .find(|row| row.capability_id == "fingerprint-aware-tls-common-underlay")
        .unwrap();

    assert_eq!(fingerprint.provider, "boringssl");
    assert_eq!(fingerprint.security_underlay, "fingerprint-aware-tls");
    assert!(fingerprint.no_silent_downgrade);

    let unknown = rows
        .iter()
        .find(|row| row.capability_id == "fingerprint-registry-boundary")
        .unwrap();
    assert_eq!(unknown.status, "fail-closed-final");
    assert_eq!(unknown.provider, "resident-fingerprint-policy");
    assert_eq!(unknown.blocker_id, None);
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
