use super::super::{append_runtime_execution_descriptor, udp_execution_descriptor};
use super::{
    UdpFixedTargetExpectation, UdpFixedTargetPayload, UdpFixedTargetValidation,
    UdpResponseDropReason, UdpResponseIdentityEvidence, UdpResponseIdentityToken,
};

const UDP_SESSION_OWNERSHIP_MANAGER_OWNED: &str = "manager-owned";

#[derive(Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::udp) struct UdpResponseEnvelope {
    payload: Vec<u8>,
    identity: UdpResponseIdentityEvidence,
    expected_protocol_identity: Option<UdpResponseIdentityToken>,
    pub(in crate::production_runtime_owner::resident_dataplane::udp) execution_label: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane::udp) tls_underlay:
        Option<&'static str>,
    pub(in crate::production_runtime_owner::resident_dataplane::udp) quic_underlay:
        Option<&'static str>,
    pub(in crate::production_runtime_owner::resident_dataplane::udp) session_executor:
        Option<&'static str>,
    pub(in crate::production_runtime_owner::resident_dataplane::udp) underlay_reuse:
        Option<&'static str>,
    pub(in crate::production_runtime_owner::resident_dataplane::udp) session_ownership:
        &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane::udp) reply_forwarded: bool,
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) type UdpExchangeResult =
    UdpResponseEnvelope;

impl UdpResponseEnvelope {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new(
        payload: Vec<u8>,
        execution_label: &'static str,
    ) -> Self {
        Self {
            payload,
            identity: UdpResponseIdentityEvidence::CompatibilityUnverified,
            expected_protocol_identity: None,
            execution_label,
            tls_underlay: None,
            quic_underlay: None,
            session_executor: None,
            underlay_reuse: None,
            session_ownership: UDP_SESSION_OWNERSHIP_MANAGER_OWNED,
            reply_forwarded: true,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn pending_response(
        execution_label: &'static str,
    ) -> Self {
        Self {
            payload: Vec::new(),
            identity: UdpResponseIdentityEvidence::CompatibilityUnverified,
            expected_protocol_identity: None,
            execution_label,
            tls_underlay: None,
            quic_underlay: None,
            session_executor: None,
            underlay_reuse: None,
            session_ownership: UDP_SESSION_OWNERSHIP_MANAGER_OWNED,
            reply_forwarded: false,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_tls_underlay(
        mut self,
        tls_underlay: &'static str,
    ) -> Self {
        self.tls_underlay = Some(tls_underlay);
        self
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_quic_underlay(
        mut self,
        quic_underlay: &'static str,
    ) -> Self {
        self.quic_underlay = Some(quic_underlay);
        self
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_session_executor(
        mut self,
        session_executor: &'static str,
    ) -> Self {
        self.session_executor = Some(session_executor);
        self
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_underlay_reuse(
        mut self,
        underlay_reuse: &'static str,
    ) -> Self {
        self.underlay_reuse = Some(underlay_reuse);
        self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_decoded_response_identity(
        mut self,
        wire_source: Option<std::net::SocketAddr>,
        observed_identity: Option<UdpResponseIdentityToken>,
    ) -> Self {
        self.identity = UdpResponseIdentityEvidence::Decoded {
            wire_source,
            observed_identity,
        };
        self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_session_bound_response_identity(
        mut self,
        source: std::net::SocketAddr,
        observed_identity: Option<UdpResponseIdentityToken>,
    ) -> Self {
        self.identity = UdpResponseIdentityEvidence::SessionBound {
            wire_source: Some(source),
            observed_identity,
        };
        self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_session_fixed_target(
        self,
        binding: super::UdpSessionFixedTarget,
    ) -> Self {
        match binding.source() {
            Some(source) => self.with_session_bound_response_identity(source, None),
            None => self.with_rejected_response_identity(UdpResponseDropReason::MissingWireSource),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_expected_protocol_identity(
        mut self,
        expected_identity: UdpResponseIdentityToken,
    ) -> Self {
        self.expected_protocol_identity = Some(expected_identity);
        self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_rejected_response_identity(
        mut self,
        reason: UdpResponseDropReason,
    ) -> Self {
        self.identity = UdpResponseIdentityEvidence::Rejected(reason);
        self
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn validate_fixed_target(
        &self,
        expectation: UdpFixedTargetExpectation,
    ) -> UdpFixedTargetValidation {
        self.identity.validate_fixed_target(expectation)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn fixed_target_expectation(
        &self,
        source: std::net::SocketAddr,
    ) -> UdpFixedTargetExpectation {
        match self.identity {
            UdpResponseIdentityEvidence::CompatibilityUnverified => {
                UdpFixedTargetExpectation::compatibility(source)
            }
            UdpResponseIdentityEvidence::Decoded {
                observed_identity: Some(_),
                ..
            }
            | UdpResponseIdentityEvidence::SessionBound {
                observed_identity: Some(_),
                ..
            } => self.expected_protocol_identity.map_or_else(
                || UdpFixedTargetExpectation::decoded_source(source),
                |identity| UdpFixedTargetExpectation::with_protocol_identity(source, identity),
            ),
            UdpResponseIdentityEvidence::Decoded { .. }
            | UdpResponseIdentityEvidence::SessionBound { .. }
            | UdpResponseIdentityEvidence::Rejected(_) => {
                UdpFixedTargetExpectation::decoded_source(source)
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn take_fixed_target_payload(
        &mut self,
        expectation: UdpFixedTargetExpectation,
    ) -> UdpFixedTargetPayload {
        let validation = self.validate_fixed_target(expectation);
        let payload = std::mem::take(&mut self.payload);
        match validation {
            UdpFixedTargetValidation::Validated
            | UdpFixedTargetValidation::CompatibilityUnverified => {
                UdpFixedTargetPayload::Accepted {
                    payload,
                    validation,
                }
            }
            UdpFixedTargetValidation::Dropped(reason) => UdpFixedTargetPayload::Rejected {
                payload_len: payload.len(),
                reason,
            },
        }
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn payload_for_test(
        &self,
    ) -> &[u8] {
        &self.payload
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn with_session_ownership(
        mut self,
        session_ownership: &'static str,
    ) -> Self {
        self.session_ownership = session_ownership;
        self
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn append_execution_fields(
        &self,
        value: &mut serde_json::Value,
        protocol_framing: &str,
        graph_id: &str,
    ) {
        let mut descriptor = udp_execution_descriptor(self.execution_label)
            .with_protocol_framing(protocol_framing)
            .with_session_ownership(self.session_ownership)
            .with_graph_id(graph_id);
        if let Some(tls_underlay) = self.tls_underlay {
            descriptor = descriptor.with_security_underlay(tls_underlay);
        }
        if let Some(quic_underlay) = self.quic_underlay {
            descriptor = descriptor.with_transport_underlay(quic_underlay);
        }
        append_runtime_execution_descriptor(value, descriptor);
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn append_session_fields(
        &self,
        value: &mut serde_json::Value,
    ) {
        if let Some(session_executor) = self.session_executor {
            value["sessionExecutor"] = serde_json::json!(session_executor);
        }
        if let Some(underlay_reuse) = self.underlay_reuse {
            value["underlayReuse"] = serde_json::json!(underlay_reuse);
        }
    }
}
