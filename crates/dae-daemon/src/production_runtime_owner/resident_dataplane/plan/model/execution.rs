use super::*;

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
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentExecutionPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) protocol: ResidentProtocolShape,
    pub(in crate::production_runtime_owner::resident_dataplane) security:
        ResidentSecurityUnderlayPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) wrapper: ResidentStreamWrapperPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) udp: ResidentUdpExecutorFactory,
}

impl ResidentExecutionPlan {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        let security = ResidentSecurityUnderlayPlan::from_proxy(proxy);
        let wrapper = ResidentStreamWrapperPlan::from_proxy(proxy);
        let protocol = ResidentProtocolShape::from_proxy(proxy);
        let udp = ResidentUdpExecutorFactory::from_proxy(proxy, wrapper, security);
        Self {
            protocol,
            security,
            wrapper,
            udp,
        }
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
        assert!(std::mem::size_of::<ResidentExecutionPlan>() <= 8);
        assert!(std::mem::size_of::<Option<ResidentExecutionPlan>>() <= 8);
    }
}
