use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityUnderlayCapabilityContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub rows: &'static [SecurityUnderlayCapabilityRow],
    pub common_security_underlay_ready: bool,
    pub expanded_security_underlay_complete: bool,
    pub release_gate_ready: bool,
}

impl SecurityUnderlayCapabilityContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "commonSecurityUnderlayReady": self.common_security_underlay_ready,
            "expandedSecurityUnderlayComplete": self.expanded_security_underlay_complete,
            "releaseGateReady": self.release_gate_ready,
            "rowCount": self.rows.len(),
            "rows": self.rows.iter().map(|row| row.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityUnderlayCapabilityRow {
    pub capability_id: &'static str,
    pub status: &'static str,
    pub provider: &'static str,
    pub security_underlay: &'static str,
    pub verification_policy: &'static str,
    pub alpn_policy: &'static str,
    pub sni_policy: &'static str,
    pub mark_mptcp_policy: &'static str,
    pub no_silent_downgrade: bool,
    pub blocker_id: Option<&'static str>,
    pub evidence_requirements: &'static [&'static str],
    pub executor_proof: &'static str,
}

impl SecurityUnderlayCapabilityRow {
    pub fn to_value(self) -> Value {
        json!({
            "capabilityId": self.capability_id,
            "status": self.status,
            "provider": self.provider,
            "securityUnderlay": self.security_underlay,
            "verificationPolicy": self.verification_policy,
            "alpnPolicy": self.alpn_policy,
            "sniPolicy": self.sni_policy,
            "markMptcpPolicy": self.mark_mptcp_policy,
            "noSilentDowngrade": self.no_silent_downgrade,
            "blockerId": self.blocker_id,
            "evidenceRequirements": self.evidence_requirements,
            "executorProof": self.executor_proof,
        })
    }
}

pub fn security_underlay_capability_contract() -> SecurityUnderlayCapabilityContract {
    SecurityUnderlayCapabilityContract {
        schema: "security-underlay-capability",
        schema_version: 1,
        rows: security_underlay_capability_rows(),
        common_security_underlay_ready: true,
        expanded_security_underlay_complete: true,
        release_gate_ready: true,
    }
}

pub fn security_underlay_capability_rows() -> &'static [SecurityUnderlayCapabilityRow] {
    &SECURITY_UNDERLAY_CAPABILITY_ROWS
}

const SECURITY_UNDERLAY_CAPABILITY_ROWS: [SecurityUnderlayCapabilityRow; 8] = [
    admitted_row(
        "standard-tls-common-underlay",
        "rustls",
        "standard-tls",
        "system-roots",
        "explicit-alpn",
        "required-sni",
        "preserved-by-resident-dialer",
        true,
        &["shared-tls-loopback", "service-contract", "large-page-live"],
    ),
    admitted_row(
        "fingerprint-aware-tls-common-underlay",
        "boringssl",
        "fingerprint-aware-tls",
        "system-roots-with-fingerprint",
        "fingerprint-aware-alpn",
        "required-sni",
        "preserved-by-resident-dialer",
        true,
        &[
            "fingerprint-resolution",
            "boring-runtime-factory",
            "no-silent-rustls-downgrade",
            "large-page-live",
        ],
    ),
    admitted_row(
        "reality-common-underlay",
        "rustls-reality",
        "reality",
        "reality-peer-verification",
        "explicit-alpn",
        "required-sni",
        "preserved-by-resident-dialer",
        true,
        &[
            "reality-client-config",
            "no-silent-standard-tls-downgrade",
            "large-page-live",
        ],
    ),
    admitted_row(
        "verification-policy-surface",
        "resident-verification-policy",
        "policy",
        "system-roots-or-explicit-policy",
        "carried-by-underlay",
        "carried-by-underlay",
        "not-a-routing-option",
        true,
        &["service-contract", "negative-fixture"],
    ),
    admitted_row(
        "underlay-routing-options",
        "resident-dialer-routing",
        "routing-options",
        "not-a-tls-policy",
        "not-applicable",
        "not-applicable",
        "mark-preserved-mptcp-carried",
        true,
        &["resident-graph-descriptor", "runtime-component-proof"],
    ),
    fail_closed_row(
        "peer-verification-security-underlay",
        "resident-peer-verification-boundary",
        "peer-verification",
        "deferred-peer-verification",
        "fingerprint-aware-alpn",
        "required-sni",
        "preserved-by-resident-dialer",
        &[
            "mutation-fixture",
            "negative-fixture",
            "no-silent-standard-tls-downgrade",
        ],
    ),
    admitted_row(
        "risk-accepted-verification-policy",
        "resident-risk-accepted-verification-policy",
        "standard-or-fingerprint-aware-tls",
        "explicit-insecure",
        "explicit-alpn",
        "required-sni",
        "preserved-by-resident-dialer",
        true,
        &[
            "live-risk-acceptance",
            "large-page-live",
            "cleanup",
            "negative-fixture",
        ],
    ),
    fail_closed_row(
        "fingerprint-registry-boundary",
        "resident-fingerprint-policy",
        "fingerprint-aware-tls",
        "unknown-fingerprint",
        "fingerprint-aware-alpn",
        "required-sni",
        "preserved-by-resident-dialer",
        &["negative-fixture", "no-silent-rustls-downgrade"],
    ),
];

const fn admitted_row(
    capability_id: &'static str,
    provider: &'static str,
    security_underlay: &'static str,
    verification_policy: &'static str,
    alpn_policy: &'static str,
    sni_policy: &'static str,
    mark_mptcp_policy: &'static str,
    no_silent_downgrade: bool,
    evidence_requirements: &'static [&'static str],
) -> SecurityUnderlayCapabilityRow {
    SecurityUnderlayCapabilityRow {
        capability_id,
        status: "admitted",
        provider,
        security_underlay,
        verification_policy,
        alpn_policy,
        sni_policy,
        mark_mptcp_policy,
        no_silent_downgrade,
        blocker_id: None,
        evidence_requirements,
        executor_proof: "runtime-executable",
    }
}

const fn fail_closed_row(
    capability_id: &'static str,
    provider: &'static str,
    security_underlay: &'static str,
    verification_policy: &'static str,
    alpn_policy: &'static str,
    sni_policy: &'static str,
    mark_mptcp_policy: &'static str,
    evidence_requirements: &'static [&'static str],
) -> SecurityUnderlayCapabilityRow {
    SecurityUnderlayCapabilityRow {
        capability_id,
        status: "fail-closed-final",
        provider,
        security_underlay,
        verification_policy,
        alpn_policy,
        sni_policy,
        mark_mptcp_policy,
        no_silent_downgrade: true,
        blocker_id: None,
        evidence_requirements,
        executor_proof: "negative-boundary-proved",
    }
}
