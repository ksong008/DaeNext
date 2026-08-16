use std::fmt;
use std::net::SocketAddr;

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::udp) struct UdpSessionFixedTarget {
    source: Option<SocketAddr>,
}

impl UdpSessionFixedTarget {
    pub(in crate::udp) fn bind(&mut self, source: SocketAddr, owner: &str) -> Result<(), String> {
        match self.source {
            None => {
                self.source = Some(source);
                Ok(())
            }
            Some(current) if same_fixed_target(current, source) => Ok(()),
            Some(current) => Err(format!(
                "{owner} is bound to UDP target {current}, cannot send to {source}"
            )),
        }
    }

    pub(in crate::udp) const fn source(self) -> Option<SocketAddr> {
        self.source
    }

    pub(in crate::udp) fn clear(&mut self) {
        self.source = None;
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(in crate::udp) struct UdpResponseIdentityToken([u8; 32]);

impl UdpResponseIdentityToken {
    /// Builds an opaque equality token for a protocol-owned identity.
    ///
    /// Callers should cache the expected token with the logical session and construct the
    /// observed token once while decoding a response. The forwarding path compares the fixed-size
    /// tokens and never re-hashes either identity.
    pub(in crate::udp) fn from_protocol_identity(domain: &[u8], identity: &[u8]) -> Option<Self> {
        if domain.is_empty() || identity.is_empty() {
            return None;
        }
        let mut digest = Sha256::new();
        digest.update((domain.len() as u64).to_be_bytes());
        digest.update(domain);
        digest.update((identity.len() as u64).to_be_bytes());
        digest.update(identity);
        Some(Self(digest.finalize().into()))
    }
}

impl fmt::Debug for UdpResponseIdentityToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpResponseIdentityToken(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::udp) struct UdpFixedTargetExpectation {
    source: SocketAddr,
    mode: UdpFixedTargetExpectationMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpFixedTargetExpectationMode {
    Compatibility,
    Decoded {
        protocol_identity: Option<UdpResponseIdentityToken>,
    },
}

impl UdpFixedTargetExpectation {
    pub(in crate::udp) const fn compatibility(source: SocketAddr) -> Self {
        Self {
            source,
            mode: UdpFixedTargetExpectationMode::Compatibility,
        }
    }

    pub(in crate::udp) const fn decoded_source(source: SocketAddr) -> Self {
        Self {
            source,
            mode: UdpFixedTargetExpectationMode::Decoded {
                protocol_identity: None,
            },
        }
    }

    #[cfg(test)]
    pub(in crate::udp) const fn with_protocol_identity(
        source: SocketAddr,
        protocol_identity: UdpResponseIdentityToken,
    ) -> Self {
        Self {
            source,
            mode: UdpFixedTargetExpectationMode::Decoded {
                protocol_identity: Some(protocol_identity),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::udp) enum UdpResponseDropReason {
    MissingWireSource,
    UnexpectedWireSource,
    MissingProtocolIdentity,
    UnexpectedProtocolIdentity,
    LateResponse,
    MalformedIdentity,
    CrossSessionIdentity,
    UnexpectedIdentityEvidence,
}

impl UdpResponseDropReason {
    pub(in crate::udp) const fn label(self) -> &'static str {
        match self {
            Self::MissingWireSource => "missing-wire-source",
            Self::UnexpectedWireSource => "unexpected-wire-source",
            Self::MissingProtocolIdentity => "missing-protocol-identity",
            Self::UnexpectedProtocolIdentity => "unexpected-protocol-identity",
            Self::LateResponse => "late-response",
            Self::MalformedIdentity => "malformed-identity",
            Self::CrossSessionIdentity => "cross-session-identity",
            Self::UnexpectedIdentityEvidence => "unexpected-identity-evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::udp) enum UdpResponseIdentityEvidence {
    CompatibilityUnverified,
    Decoded {
        wire_source: Option<SocketAddr>,
        observed_identity: Option<UdpResponseIdentityToken>,
    },
    SessionBound {
        wire_source: Option<SocketAddr>,
        observed_identity: Option<UdpResponseIdentityToken>,
    },
    Rejected(UdpResponseDropReason),
}

impl UdpResponseIdentityEvidence {
    pub(in crate::udp) fn validate_fixed_target(
        self,
        expectation: UdpFixedTargetExpectation,
    ) -> UdpFixedTargetValidation {
        match self {
            Self::CompatibilityUnverified => match expectation.mode {
                UdpFixedTargetExpectationMode::Compatibility => {
                    UdpFixedTargetValidation::CompatibilityUnverified
                }
                UdpFixedTargetExpectationMode::Decoded {
                    protocol_identity: Some(_),
                } => UdpFixedTargetValidation::Dropped(
                    UdpResponseDropReason::MissingProtocolIdentity,
                ),
                UdpFixedTargetExpectationMode::Decoded {
                    protocol_identity: None,
                } => UdpFixedTargetValidation::Dropped(UdpResponseDropReason::MissingWireSource),
            },
            Self::Rejected(reason) => UdpFixedTargetValidation::Dropped(reason),
            Self::Decoded {
                wire_source,
                observed_identity,
            } => {
                let UdpFixedTargetExpectationMode::Decoded { protocol_identity } = expectation.mode
                else {
                    return UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::UnexpectedIdentityEvidence,
                    );
                };
                let Some(wire_source) = wire_source else {
                    return UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::MissingWireSource,
                    );
                };
                if !same_fixed_target(wire_source, expectation.source) {
                    return UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::UnexpectedWireSource,
                    );
                }
                match (protocol_identity, observed_identity) {
                    (Some(_), None) => UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::MissingProtocolIdentity,
                    ),
                    (Some(expected), Some(observed)) if expected != observed => {
                        UdpFixedTargetValidation::Dropped(
                            UdpResponseDropReason::UnexpectedProtocolIdentity,
                        )
                    }
                    (None, Some(_)) => UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::UnexpectedProtocolIdentity,
                    ),
                    _ => UdpFixedTargetValidation::Validated,
                }
            }
            Self::SessionBound {
                wire_source,
                observed_identity,
            } => {
                let UdpFixedTargetExpectationMode::Decoded { protocol_identity } = expectation.mode
                else {
                    return UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::UnexpectedIdentityEvidence,
                    );
                };
                let Some(wire_source) = wire_source else {
                    return UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::MissingWireSource,
                    );
                };
                if !same_fixed_target(wire_source, expectation.source) {
                    return UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::UnexpectedWireSource,
                    );
                }
                match (protocol_identity, observed_identity) {
                    (Some(_), None) => UdpFixedTargetValidation::Dropped(
                        UdpResponseDropReason::MissingProtocolIdentity,
                    ),
                    (Some(expected), Some(observed)) if expected != observed => {
                        UdpFixedTargetValidation::Dropped(
                            UdpResponseDropReason::UnexpectedProtocolIdentity,
                        )
                    }
                    _ => UdpFixedTargetValidation::Validated,
                }
            }
        }
    }
}

fn same_fixed_target(observed: SocketAddr, expected: SocketAddr) -> bool {
    canonical_fixed_target(observed) == canonical_fixed_target(expected)
}

fn canonical_fixed_target(target: SocketAddr) -> SocketAddr {
    let SocketAddr::V6(ipv6_target) = target else {
        return target;
    };
    let Some(ipv4) = ipv6_target.ip().to_ipv4_mapped() else {
        return target;
    };
    SocketAddr::new(ipv4.into(), ipv6_target.port())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::udp) enum UdpFixedTargetValidation {
    Validated,
    CompatibilityUnverified,
    Dropped(UdpResponseDropReason),
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::udp) enum UdpFixedTargetPayload {
    Accepted {
        payload: Vec<u8>,
        validation: UdpFixedTargetValidation,
    },
    Rejected {
        payload_len: usize,
        reason: UdpResponseDropReason,
    },
}

impl UdpFixedTargetPayload {
    pub(in crate::udp) const fn validation(&self) -> UdpFixedTargetValidation {
        match self {
            Self::Accepted { validation, .. } => *validation,
            Self::Rejected { reason, .. } => UdpFixedTargetValidation::Dropped(*reason),
        }
    }

    pub(in crate::udp) fn payload_len(&self) -> usize {
        match self {
            Self::Accepted { payload, .. } => payload.len(),
            Self::Rejected { payload_len, .. } => *payload_len,
        }
    }

    pub(in crate::udp) fn into_payload(self) -> Result<Vec<u8>, UdpResponseDropReason> {
        match self {
            Self::Accepted { payload, .. } => Ok(payload),
            Self::Rejected { reason, .. } => Err(reason),
        }
    }
}

impl UdpFixedTargetValidation {
    pub(in crate::udp) const fn should_forward(self) -> bool {
        !matches!(self, Self::Dropped(_))
    }

    pub(in crate::udp) const fn label(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::CompatibilityUnverified => "compatibility-unverified",
            Self::Dropped(_) => "dropped",
        }
    }

    pub(in crate::udp) const fn drop_reason(self) -> Option<UdpResponseDropReason> {
        match self {
            Self::Dropped(reason) => Some(reason),
            Self::Validated | Self::CompatibilityUnverified => None,
        }
    }
}
