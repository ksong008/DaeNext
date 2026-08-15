#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hysteria2CapabilityDisposition {
    Admitted,
    Rejected,
}

impl Hysteria2CapabilityDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hysteria2CapabilityLedgerEntry {
    pub capability: &'static str,
    pub disposition: Hysteria2CapabilityDisposition,
    pub reason: &'static str,
}

const CAPABILITY_LEDGER: &[Hysteria2CapabilityLedgerEntry] = &[
    admitted(
        "tls-webpki-insecure-pin",
        "typed BoringSSL verification policy",
    ),
    admitted("obfs-salamander", "typed UDP underlay with PMTU accounting"),
    admitted(
        "periodic-port-hopping",
        "bounded current and previous socket runtime",
    ),
    admitted(
        "fixed-port-hop-interval",
        "normalized global UDP hop interval",
    ),
    admitted(
        "bandwidth-independent-directions",
        "MaxTx and MaxRx remain independent",
    ),
    admitted("congestion-bbr-standard", "Quinn BBR controller"),
    admitted("congestion-reno", "Quinn NewReno controller"),
    admitted("congestion-brutal", "negotiated fixed-rate controller"),
    admitted("brutal-loss-compensation", "bounded ACK and loss sample"),
    admitted(
        "randomized-protocol-padding",
        "official auth and TCP request ranges",
    ),
    admitted("udp-fixed-target", "consumer-bound target validation"),
    rejected("obfs-gecko", "no audited Quinn UDP Gecko underlay"),
    rejected("gecko-packet-sizing", "Gecko underlay is not admitted"),
    rejected(
        "tls-ech",
        "current BoringSSL QUIC provider has no admitted ECH executor",
    ),
    rejected(
        "tls-custom-ca",
        "share-link custom trust material is not admitted",
    ),
    rejected(
        "tls-mtls",
        "QUIC client certificate identity is not admitted",
    ),
    rejected(
        "bbr-conservative-profile",
        "Quinn exposes no equivalent profile controls",
    ),
    rejected(
        "bbr-aggressive-profile",
        "Quinn exposes no equivalent profile controls",
    ),
    rejected(
        "udp-full-cone",
        "the selected product contract is fixed target",
    ),
    rejected("realm-hole-punching", "no resident realm lifecycle owner"),
    rejected(
        "variable-port-hop-interval",
        "minimum and maximum interval ranges are not admitted",
    ),
    rejected(
        "quic-runtime-tuning",
        "window timeout keepalive and PMTU overrides are not admitted",
    ),
    rejected(
        "fast-open",
        "the resident owner has no admitted fast-open shape",
    ),
    rejected("transport-non-udp", "Hysteria2 transport is fixed to UDP"),
    rejected(
        "hysteria2-ip-mode",
        "address-family policy uses the resident dial mode",
    ),
    rejected(
        "unknown-query-field",
        "unknown external shapes fail during parsing",
    ),
];

pub const fn hysteria2_capability_ledger() -> &'static [Hysteria2CapabilityLedgerEntry] {
    CAPABILITY_LEDGER
}

const fn admitted(
    capability: &'static str,
    reason: &'static str,
) -> Hysteria2CapabilityLedgerEntry {
    Hysteria2CapabilityLedgerEntry {
        capability,
        disposition: Hysteria2CapabilityDisposition::Admitted,
        reason,
    }
}

const fn rejected(
    capability: &'static str,
    reason: &'static str,
) -> Hysteria2CapabilityLedgerEntry {
    Hysteria2CapabilityLedgerEntry {
        capability,
        disposition: Hysteria2CapabilityDisposition::Rejected,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_ledger_is_bounded_unique_and_decisive() {
        assert!(CAPABILITY_LEDGER.len() < 32);
        for (index, entry) in CAPABILITY_LEDGER.iter().enumerate() {
            assert!(!entry.capability.is_empty());
            assert!(!entry.reason.is_empty());
            assert!(
                CAPABILITY_LEDGER[index + 1..]
                    .iter()
                    .all(|candidate| candidate.capability != entry.capability)
            );
        }
        for capability in ["obfs-gecko", "tls-ech", "tls-custom-ca", "tls-mtls"] {
            assert!(CAPABILITY_LEDGER.iter().any(|entry| {
                entry.capability == capability
                    && entry.disposition == Hysteria2CapabilityDisposition::Rejected
            }));
        }
    }
}
