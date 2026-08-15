use super::super::UdpPacketSemantics;
use super::ResidentUdpExecutorFactory;
use serde_json::{Value, json};

pub(crate) const RESIDENT_UDP_CLEANUP_OWNER: &str = "resident-udp-runtime-generation";
pub(crate) const RESIDENT_UDP_CLEANUP_POLICY: &str = "cancel-and-drain-on-generation-stop";

const MANAGED_TRAFFIC_SESSION_SCOPE: &str =
    "graph-outbound-peer-original-destination-packet-semantics";
const MANAGED_PROBE_SESSION_SCOPE: &str =
    "graph-outbound-probe-original-destination-packet-semantics";
const FIXED_TARGET_VALIDATION: &str = "required-before-payload-consumption-or-forwarding";
const FIXED_TARGET_REPLY_SOURCE: &str = "validated-original-destination";
const FIXED_TARGET_MULTI_TARGET_MODE: &str = "rejected-not-admitted";
const FIXED_TARGET_METRICS: &str = "fixed-low-cardinality-validation-counters";
const FIXED_TARGET_COMPATIBILITY: &str = "strict-fixed-target";
const POLICY_CLOSED: &str = "not-applicable-policy-closed";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentUdpWireIdentityContract {
    DecodedSource,
    DecodedSourceAndProtocolSession,
    SessionBoundTarget,
    ProtocolSessionAndDecodedSource,
    PolicyClosed,
}

impl ResidentUdpWireIdentityContract {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DecodedSource => "decoded-wire-source",
            Self::DecodedSourceAndProtocolSession => "decoded-wire-source-and-protocol-session",
            Self::SessionBoundTarget => "session-bound-fixed-target",
            Self::ProtocolSessionAndDecodedSource => "protocol-session-and-decoded-wire-source",
            Self::PolicyClosed => POLICY_CLOSED,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpSourceContract {
    traffic_session_scope: &'static str,
    probe_session_scope: &'static str,
    wire_identity: ResidentUdpWireIdentityContract,
    fixed_target_validation: &'static str,
    multi_target_mode: &'static str,
    reply_source: &'static str,
    metrics: &'static str,
    compatibility_mode: &'static str,
}

impl ResidentUdpSourceContract {
    pub(crate) const fn fixed_target(wire_identity: ResidentUdpWireIdentityContract) -> Self {
        Self {
            traffic_session_scope: MANAGED_TRAFFIC_SESSION_SCOPE,
            probe_session_scope: MANAGED_PROBE_SESSION_SCOPE,
            wire_identity,
            fixed_target_validation: FIXED_TARGET_VALIDATION,
            multi_target_mode: FIXED_TARGET_MULTI_TARGET_MODE,
            reply_source: FIXED_TARGET_REPLY_SOURCE,
            metrics: FIXED_TARGET_METRICS,
            compatibility_mode: FIXED_TARGET_COMPATIBILITY,
        }
    }

    pub(crate) const fn direct() -> Self {
        Self {
            traffic_session_scope: "peer-original-destination-mark",
            probe_session_scope: "probe-original-destination-mark",
            wire_identity: ResidentUdpWireIdentityContract::DecodedSource,
            fixed_target_validation: FIXED_TARGET_VALIDATION,
            multi_target_mode: FIXED_TARGET_MULTI_TARGET_MODE,
            reply_source: FIXED_TARGET_REPLY_SOURCE,
            metrics: FIXED_TARGET_METRICS,
            compatibility_mode: FIXED_TARGET_COMPATIBILITY,
        }
    }

    pub(crate) const fn managed_dns() -> Self {
        Self::fixed_target(ResidentUdpWireIdentityContract::SessionBoundTarget)
    }

    pub(crate) const fn policy_closed() -> Self {
        Self {
            traffic_session_scope: POLICY_CLOSED,
            probe_session_scope: POLICY_CLOSED,
            wire_identity: ResidentUdpWireIdentityContract::PolicyClosed,
            fixed_target_validation: POLICY_CLOSED,
            multi_target_mode: "rejected-policy-closed",
            reply_source: POLICY_CLOSED,
            metrics: "fixed-low-cardinality-rejection-counters",
            compatibility_mode: "fail-closed",
        }
    }

    pub(crate) const fn wire_identity(self) -> ResidentUdpWireIdentityContract {
        self.wire_identity
    }

    pub(crate) const fn multi_target_mode(self) -> &'static str {
        self.multi_target_mode
    }

    pub(crate) const fn compatibility_mode(self) -> &'static str {
        self.compatibility_mode
    }

    pub(crate) fn json(self) -> Value {
        json!({
            "schemaVersion": 1,
            "trafficSessionScope": self.traffic_session_scope,
            "probeSessionScope": self.probe_session_scope,
            "wireIdentity": self.wire_identity().as_str(),
            "fixedTargetValidation": self.fixed_target_validation,
            "multiTargetMode": self.multi_target_mode(),
            "replySource": self.reply_source,
            "metrics": self.metrics,
            "compatibilityMode": self.compatibility_mode(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentUdpExecutionDisposition {
    PacketRelay,
    PolicyClosed,
}

impl ResidentUdpExecutionDisposition {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PacketRelay => "packet-relay",
            Self::PolicyClosed => "policy-closed-negative-path",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpExecutionAgreement {
    factory: ResidentUdpExecutorFactory,
}

impl ResidentUdpExecutionAgreement {
    pub(super) const fn new(factory: ResidentUdpExecutorFactory) -> Self {
        Self { factory }
    }

    pub(crate) fn disposition(self) -> ResidentUdpExecutionDisposition {
        if self.factory.policy_closed() {
            ResidentUdpExecutionDisposition::PolicyClosed
        } else {
            ResidentUdpExecutionDisposition::PacketRelay
        }
    }

    pub(crate) fn executor_label(self) -> &'static str {
        self.factory.executor_label()
    }

    pub(crate) fn packet_semantics(self) -> UdpPacketSemantics {
        self.factory.packet_semantics()
    }

    pub(crate) const fn source_contract(self) -> ResidentUdpSourceContract {
        self.factory.source_contract()
    }

    pub(crate) fn policy_closed(self) -> bool {
        self.disposition() == ResidentUdpExecutionDisposition::PolicyClosed
    }

    pub(crate) fn unsupported_reason(self) -> Option<&'static str> {
        self.factory.policy_closed_reason()
    }

    pub(crate) fn component_status(self) -> &'static str {
        if self.policy_closed() {
            "fail-closed"
        } else {
            "admitted"
        }
    }

    pub(crate) fn negative_path_ready(self) -> bool {
        self.policy_closed()
    }

    pub(crate) fn admit_packet_relay(self, consumer: &str) -> Result<(), String> {
        match self.unsupported_reason() {
            None => Ok(()),
            Some(reason) => Err(format!(
                "{consumer} rejected by typed UDP agreement: executor={}, packetSemantics={}, reason={reason}",
                self.executor_label(),
                self.packet_semantics().as_str(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ResidentUdpPolicyClosedReason;
    use super::*;

    #[test]
    fn executable_and_policy_closed_agreements_have_distinct_contracts() {
        let executable = ResidentUdpExecutorFactory::ShadowsocksAead.agreement();
        assert_eq!(
            executable.disposition(),
            ResidentUdpExecutionDisposition::PacketRelay
        );
        assert_eq!(executable.component_status(), "admitted");
        assert!(!executable.negative_path_ready());
        assert!(executable.unsupported_reason().is_none());

        let closed =
            ResidentUdpExecutorFactory::PolicyClosed(ResidentUdpPolicyClosedReason::HttpConnect)
                .agreement();
        assert_eq!(
            closed.disposition(),
            ResidentUdpExecutionDisposition::PolicyClosed
        );
        assert_eq!(closed.component_status(), "fail-closed");
        assert!(closed.negative_path_ready());
        assert_eq!(closed.executor_label(), "http-connect-udp-protocol-closed");
        assert!(
            closed
                .admit_packet_relay("proxy-routed DNS UDP")
                .unwrap_err()
                .contains("HTTP CONNECT has no UDP relay semantics")
        );
    }

    #[test]
    fn every_udp_factory_has_an_explicit_source_contract() {
        use super::super::ResidentStreamPacketTransport as Stream;
        use ResidentUdpWireIdentityContract as Wire;

        let decoded_source = [
            ResidentUdpExecutorFactory::Socks5Associate,
            ResidentUdpExecutorFactory::ShadowsocksAead,
            ResidentUdpExecutorFactory::Trojan(Stream::TlsTcp),
            ResidentUdpExecutorFactory::JuicityStreamPacket,
        ];
        for factory in decoded_source {
            assert_eq!(
                factory.source_contract().wire_identity(),
                Wire::DecodedSource
            );
        }

        assert_eq!(
            ResidentUdpExecutorFactory::Shadowsocks2022
                .source_contract()
                .wire_identity(),
            Wire::DecodedSourceAndProtocolSession
        );
        for factory in [
            ResidentUdpExecutorFactory::VlessStandard(Stream::PlainTcp),
            ResidentUdpExecutorFactory::VlessVisionXudp,
            ResidentUdpExecutorFactory::Vmess(Stream::PlainTcp),
            ResidentUdpExecutorFactory::AnyTlsPacketStream,
        ] {
            assert_eq!(
                factory.source_contract().wire_identity(),
                Wire::SessionBoundTarget
            );
        }
        for factory in [
            ResidentUdpExecutorFactory::Hysteria2Datagram,
            ResidentUdpExecutorFactory::TuicPacket(dae_outbound::tuic::TuicUdpRelayMode::Native),
        ] {
            assert_eq!(
                factory.source_contract().wire_identity(),
                Wire::ProtocolSessionAndDecodedSource
            );
        }

        let admitted = [
            ResidentUdpExecutorFactory::Socks5Associate,
            ResidentUdpExecutorFactory::ShadowsocksAead,
            ResidentUdpExecutorFactory::Shadowsocks2022,
            ResidentUdpExecutorFactory::VlessStandard(Stream::XhttpH3),
            ResidentUdpExecutorFactory::VlessVisionXudp,
            ResidentUdpExecutorFactory::Trojan(Stream::GrpcTls),
            ResidentUdpExecutorFactory::Vmess(Stream::WebSocketTls),
            ResidentUdpExecutorFactory::AnyTlsPacketStream,
            ResidentUdpExecutorFactory::Hysteria2Datagram,
            ResidentUdpExecutorFactory::TuicPacket(dae_outbound::tuic::TuicUdpRelayMode::Native),
            ResidentUdpExecutorFactory::TuicPacket(dae_outbound::tuic::TuicUdpRelayMode::Quic),
            ResidentUdpExecutorFactory::JuicityStreamPacket,
        ];
        for factory in admitted {
            let source = factory.source_contract();
            assert_eq!(source.multi_target_mode(), "rejected-not-admitted");
            assert_eq!(source.compatibility_mode(), "strict-fixed-target");
        }

        let closed =
            ResidentUdpExecutorFactory::PolicyClosed(ResidentUdpPolicyClosedReason::HttpConnect)
                .source_contract();
        assert_eq!(closed.wire_identity(), Wire::PolicyClosed);
        assert_eq!(closed.multi_target_mode(), "rejected-policy-closed");
        assert_eq!(closed.compatibility_mode(), "fail-closed");
    }
}
