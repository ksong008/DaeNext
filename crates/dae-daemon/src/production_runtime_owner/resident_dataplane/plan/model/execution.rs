use super::*;
use dae_runtime_control::OwnerGeneration;

const UNMATERIALIZED_RESIDENT_PLAN_GENERATION: OwnerGeneration = OwnerGeneration::new(0);

mod protocol;
mod semantics;
mod udp;

pub(in crate::production_runtime_owner::resident_dataplane) use protocol::{
    ResidentProtocolShape, ResidentTcpProbeDispatch, ResidentTcpRuntimeDispatch,
};
pub(in crate::production_runtime_owner::resident_dataplane) use semantics::UdpPacketSemantics;
pub(in crate::production_runtime_owner::resident_dataplane) use udp::{
    RESIDENT_UDP_CLEANUP_OWNER, RESIDENT_UDP_CLEANUP_POLICY, ResidentStreamPacketTransport,
    ResidentUdpExecutionAgreement, ResidentUdpExecutionDisposition, ResidentUdpExecutorFactory,
    ResidentUdpPolicyClosedReason, ResidentUdpSourceContract, ResidentUdpWireIdentityContract,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentExecutionPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) protocol: ResidentProtocolShape,
    pub(in crate::production_runtime_owner::resident_dataplane) security:
        ResidentSecurityUnderlayPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) wrapper: ResidentStreamWrapperPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) udp: ResidentUdpExecutorFactory,
    pub(in crate::production_runtime_owner::resident_dataplane) runtime_generation: OwnerGeneration,
}

impl ResidentExecutionPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) const fn plan_generation()
    -> OwnerGeneration {
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

    pub(in crate::production_runtime_owner::resident_dataplane) const fn runtime_generation(
        self,
    ) -> OwnerGeneration {
        self.runtime_generation
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executor_contract(
        self,
    ) -> ResidentProtocolExecutorContract {
        ResidentProtocolExecutorContract {
            tcp_executor: self.protocol.tcp_executor_label(self.wrapper),
            udp_executor: self.udp.executor_label(),
            packet_semantics: self.udp.packet_semantics().as_str(),
            udp_policy_closed: self.udp.policy_closed(),
        }
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
