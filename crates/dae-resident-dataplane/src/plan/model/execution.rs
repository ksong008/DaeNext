use super::*;
use dae_runtime_control::OwnerGeneration;

const UNMATERIALIZED_RESIDENT_PLAN_GENERATION: OwnerGeneration = OwnerGeneration::new(0);

mod protocol;
mod semantics;
mod tcp;
mod udp;

pub(crate) use protocol::{
    ResidentProtocolShape, ResidentTcpProbeDispatch, ResidentTcpRuntimeDispatch,
};
pub(crate) use semantics::UdpPacketSemantics;
pub(crate) use tcp::ResidentTcpCarrierOwnership;
pub(crate) use udp::{
    RESIDENT_UDP_CLEANUP_OWNER, RESIDENT_UDP_CLEANUP_POLICY, ResidentStreamPacketTransport,
    ResidentUdpExecutionAgreement, ResidentUdpExecutionDisposition, ResidentUdpExecutorFactory,
    ResidentUdpPolicyClosedReason, ResidentUdpSourceContract, ResidentUdpWireIdentityContract,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentExecutionPlan {
    pub(crate) protocol: ResidentProtocolShape,
    pub(crate) security: ResidentSecurityUnderlayPlan,
    pub(crate) wrapper: ResidentStreamWrapperPlan,
    pub(crate) udp: ResidentUdpExecutorFactory,
    pub(crate) runtime_generation: OwnerGeneration,
}

impl ResidentExecutionPlan {
    pub(crate) const fn plan_generation() -> OwnerGeneration {
        UNMATERIALIZED_RESIDENT_PLAN_GENERATION
    }

    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        let wrapper = ResidentStreamWrapperPlan::from_proxy(proxy);
        let security = ResidentSecurityUnderlayPlan::from_proxy(proxy, wrapper);
        let protocol = ResidentProtocolShape::from_proxy(proxy);
        let udp = ResidentUdpExecutorFactory::from_proxy(proxy, wrapper, security);
        Self {
            protocol,
            security,
            wrapper,
            udp,
            runtime_generation: Self::plan_generation(),
        }
    }

    pub(super) fn with_runtime_generation(mut self, generation: OwnerGeneration) -> Self {
        self.runtime_generation = generation;
        self
    }

    pub(crate) const fn runtime_generation(self) -> OwnerGeneration {
        self.runtime_generation
    }

    pub(crate) fn executor_contract(self) -> ResidentProtocolExecutorContract {
        ResidentProtocolExecutorContract {
            tcp_executor: self.protocol.tcp_executor_label(self.wrapper),
            udp_executor: self.udp.executor_label(),
            packet_semantics: self.udp.packet_semantics().as_str(),
            udp_policy_closed: self.udp.policy_closed(),
        }
    }

    pub(crate) const fn tcp_carrier_ownership(self) -> ResidentTcpCarrierOwnership {
        ResidentTcpCarrierOwnership::from_execution(self.protocol, self.wrapper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialized_execution_plan_stays_compact() {
        assert!(std::mem::size_of::<ResidentExecutionPlan>() <= 16);
        assert!(std::mem::size_of::<Option<ResidentExecutionPlan>>() <= 16);
    }
}
