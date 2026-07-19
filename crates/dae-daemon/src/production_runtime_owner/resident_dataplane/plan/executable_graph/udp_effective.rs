use super::super::{
    ResidentUdpChainAdmission, ResidentUdpExecutionAgreement, ResidentUdpExecutionDisposition,
    ResidentUdpSourceContract, UdpPacketSemantics,
};

const CHAIN_POLICY_CLOSED_EXECUTOR: &str = "parent-connect-udp-policy-closed";

#[derive(Clone, Copy)]
pub(super) struct EffectiveUdpExecutionAgreement {
    raw: ResidentUdpExecutionAgreement,
    chain: ResidentUdpChainAdmission,
}

impl EffectiveUdpExecutionAgreement {
    pub(super) const fn new(
        raw: ResidentUdpExecutionAgreement,
        chain: ResidentUdpChainAdmission,
    ) -> Self {
        Self { raw, chain }
    }

    pub(super) fn disposition(self) -> ResidentUdpExecutionDisposition {
        if self.policy_closed_by_chain() {
            ResidentUdpExecutionDisposition::PolicyClosed
        } else {
            self.raw.disposition()
        }
    }

    pub(super) fn executor_label(self) -> &'static str {
        if self.policy_closed_by_chain() && !self.raw.policy_closed() {
            CHAIN_POLICY_CLOSED_EXECUTOR
        } else {
            self.raw.executor_label()
        }
    }

    pub(super) fn packet_semantics(self) -> UdpPacketSemantics {
        if self.policy_closed_by_chain() && !self.raw.policy_closed() {
            UdpPacketSemantics::ProtocolClosed
        } else {
            self.raw.packet_semantics()
        }
    }

    pub(super) fn policy_closed(self) -> bool {
        self.raw.policy_closed() || self.policy_closed_by_chain()
    }

    pub(super) fn unsupported_reason(self) -> Option<&'static str> {
        self.raw
            .unsupported_reason()
            .or_else(|| self.chain.unsupported_reason())
    }

    pub(super) fn component_status(self) -> &'static str {
        if self.raw.policy_closed() {
            self.raw.component_status()
        } else {
            self.chain.status()
        }
    }

    pub(super) fn negative_path_ready(self) -> bool {
        self.raw.negative_path_ready() || self.policy_closed_by_chain()
    }

    pub(super) const fn source_contract(self) -> ResidentUdpSourceContract {
        if self.policy_closed_by_chain() {
            ResidentUdpSourceContract::policy_closed()
        } else {
            self.raw.source_contract()
        }
    }

    pub(super) fn transient_exchange_compatible(self) -> bool {
        !self.policy_closed()
    }

    const fn policy_closed_by_chain(self) -> bool {
        matches!(self.chain, ResidentUdpChainAdmission::Unsupported(_))
    }
}
