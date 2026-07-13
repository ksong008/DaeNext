use super::super::UdpPacketSemantics;
use super::ResidentUdpExecutorFactory;

pub(in crate::production_runtime_owner::resident_dataplane) const RESIDENT_UDP_CLEANUP_OWNER: &str =
    "resident-udp-runtime-generation";
pub(in crate::production_runtime_owner::resident_dataplane) const RESIDENT_UDP_CLEANUP_POLICY:
    &str = "cancel-and-drain-on-generation-stop";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentUdpExecutionDisposition {
    PacketRelay,
    PolicyClosed,
}

impl ResidentUdpExecutionDisposition {
    pub(in crate::production_runtime_owner::resident_dataplane) const fn as_str(
        self,
    ) -> &'static str {
        match self {
            Self::PacketRelay => "packet-relay",
            Self::PolicyClosed => "policy-closed-negative-path",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentUdpExecutionAgreement {
    factory: ResidentUdpExecutorFactory,
}

impl ResidentUdpExecutionAgreement {
    pub(super) const fn new(factory: ResidentUdpExecutorFactory) -> Self {
        Self { factory }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn disposition(
        self,
    ) -> ResidentUdpExecutionDisposition {
        if self.factory.policy_closed() {
            ResidentUdpExecutionDisposition::PolicyClosed
        } else {
            ResidentUdpExecutionDisposition::PacketRelay
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executor_label(
        self,
    ) -> &'static str {
        self.factory.executor_label()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn packet_semantics(
        self,
    ) -> UdpPacketSemantics {
        self.factory.packet_semantics()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn policy_closed(self) -> bool {
        self.disposition() == ResidentUdpExecutionDisposition::PolicyClosed
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn unsupported_reason(
        self,
    ) -> Option<&'static str> {
        self.factory.policy_closed_reason()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn component_status(
        self,
    ) -> &'static str {
        if self.policy_closed() {
            "fail-closed"
        } else {
            "admitted"
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn negative_path_ready(
        self,
    ) -> bool {
        self.policy_closed()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn admit_packet_relay(
        self,
        consumer: &str,
    ) -> Result<(), String> {
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
}
