use serde_json::{Value, json};

use super::*;
use crate::source_shape_registry::SourceShapeRegistryRow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypedCapabilityContract {
    pub schema_version: u64,
    pub protocol_framing: ProtocolFraming,
    pub security_underlay: SecurityUnderlay,
    pub stream_wrapper: StreamWrapper,
    pub packet_semantics: PacketSemantics,
    pub executor: ExecutorKind,
    pub source_shape_state: SourceShapeState,
}

impl TypedCapabilityContract {
    pub fn to_value(self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "protocolFraming": self.protocol_framing.as_report_str(),
            "securityUnderlay": self.security_underlay.as_report_str(),
            "streamWrapper": self.stream_wrapper.as_report_str(),
            "packetSemantics": self.packet_semantics.as_report_str(),
            "executor": self.executor.as_report_str(),
            "sourceShapeState": self.source_shape_state.as_report_str(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityUnderlayPolicyContract {
    pub schema_version: u64,
    pub allow_insecure_support: bool,
    pub pin_requirement: &'static str,
    pub reality_support: bool,
    pub fingerprint_utls_support: bool,
    pub tls_fragment_support: bool,
    pub blocked_reason: Option<&'static str>,
}

impl SecurityUnderlayPolicyContract {
    pub fn to_value(self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "allowInsecureSupport": self.allow_insecure_support,
            "pinRequirement": self.pin_requirement,
            "realitySupport": self.reality_support,
            "fingerprintUtlsSupport": self.fingerprint_utls_support,
            "tlsFragmentSupport": self.tls_fragment_support,
            "blockedReason": self.blocked_reason,
        })
    }
}

impl SourceShapeRegistryRow {
    pub fn typed_capability_contract(self) -> Option<TypedCapabilityContract> {
        let protocol_framing = ProtocolFraming::from_report_str(self.protocol_family)?;
        let security_underlay = SecurityUnderlay::from_report_str(self.security_underlay)?;
        let stream_wrapper = StreamWrapper::from_report_str(self.stream_wrapper)?;
        let packet_semantics = PacketSemantics::from_report_str(self.packet_semantics)?;
        let source_shape_state = if self.source_support == "not-source-supported" {
            SourceShapeState::NotSourceSupported
        } else if self.resident_status == "blocked" {
            SourceShapeState::Blocked
        } else {
            SourceShapeState::Admitted
        };
        Some(TypedCapabilityContract {
            schema_version: 1,
            protocol_framing,
            security_underlay,
            stream_wrapper,
            packet_semantics,
            executor: if source_shape_state == SourceShapeState::Blocked {
                ExecutorKind::PolicyClosed
            } else {
                ExecutorKind::from_packet_semantics(packet_semantics)
            },
            source_shape_state,
        })
    }

    pub fn security_underlay_policy_contract(self) -> Option<SecurityUnderlayPolicyContract> {
        let security_underlay = SecurityUnderlay::from_report_str(self.security_underlay)?;
        Some(SecurityUnderlayPolicyContract {
            schema_version: 1,
            allow_insecure_support: security_underlay.supports_allow_insecure(),
            pin_requirement: self.pin_requirement(),
            reality_support: security_underlay.supports_reality(),
            fingerprint_utls_support: security_underlay.supports_fingerprint_utls(),
            tls_fragment_support: security_underlay.supports_tls_fragment(),
            blocked_reason: self.blocker_id,
        })
    }

    fn pin_requirement(self) -> &'static str {
        match self.protocol_family {
            "hysteria2" => "certificate-pin-required",
            "juicity" => "certificate-chain-pin-supported",
            _ if self.security_underlay == "verified-quic-tls" => {
                "certificate-verification-required"
            }
            _ if self.security_underlay == "reality" => "reality-public-key-required",
            _ if self.security_underlay == "standard-or-fingerprint-aware-tls-or-reality" => {
                "reality-public-key-when-reality-selected"
            }
            _ if self.security_underlay == "tls-stream-variants-or-reality" => {
                "reality-public-key-when-reality-selected"
            }
            _ if self.security_underlay == "plain-or-tls-stream-variants-or-reality" => {
                "reality-public-key-when-reality-selected"
            }
            _ => "none",
        }
    }
}
