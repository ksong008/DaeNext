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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentManualProbeDispatch {
    Tcp,
    Udp,
    PolicyClosed,
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn manual_probe_dispatch(
        self,
    ) -> ResidentManualProbeDispatch {
        match self.protocol {
            ResidentProtocolShape::ConnectUdpH2 | ResidentProtocolShape::ConnectUdpH3 => {
                if self.udp.policy_closed() {
                    ResidentManualProbeDispatch::PolicyClosed
                } else {
                    ResidentManualProbeDispatch::Udp
                }
            }
            _ => ResidentManualProbeDispatch::Tcp,
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

    #[test]
    fn connect_udp_manual_probe_follows_udp_admission_independently() {
        let h2 = ResidentExecutionPlan {
            protocol: ResidentProtocolShape::ConnectUdpH2,
            security: ResidentSecurityUnderlayPlan::StandardTls,
            wrapper: ResidentStreamWrapperPlan::ConnectUdpH2,
            udp: ResidentUdpExecutorFactory::ConnectUdpH2,
        };
        assert_eq!(h2.manual_probe_dispatch(), ResidentManualProbeDispatch::Udp);

        let h3 = ResidentExecutionPlan {
            protocol: ResidentProtocolShape::ConnectUdpH3,
            security: ResidentSecurityUnderlayPlan::QuicTls,
            wrapper: ResidentStreamWrapperPlan::ConnectUdpH3,
            udp: ResidentUdpExecutorFactory::ConnectUdpH3,
        };
        assert_eq!(h3.manual_probe_dispatch(), ResidentManualProbeDispatch::Udp);
    }
}
