use super::*;

fn materialized_runtime_ownership(
    execution: plan::ResidentExecutionPlan,
) -> dae_outbound::RuntimeOwnershipProfile {
    use dae_outbound::{
        CALLER_SCOPED_QUIC_OWNERSHIP, CONFIGURED_HTTP_OWNERSHIP, FLOW_STREAM_ASSOCIATION_OWNERSHIP,
        FLOW_STREAM_PACKET_OWNERSHIP, FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        GENERATION_CONNECT_UDP_OWNERSHIP,
    };
    use plan::{ResidentProtocolShape as Protocol, ResidentStreamWrapperPlan as Wrapper};

    match execution.protocol {
        Protocol::ConnectUdpH2 | Protocol::ConnectUdpH3 => GENERATION_CONNECT_UDP_OWNERSHIP,
        Protocol::Hysteria2 | Protocol::Tuic | Protocol::Juicity => CALLER_SCOPED_QUIC_OWNERSHIP,
        Protocol::Socks5 => FLOW_STREAM_ASSOCIATION_OWNERSHIP,
        _ if matches!(execution.wrapper, Wrapper::Xhttp(_)) => CONFIGURED_HTTP_OWNERSHIP,
        _ if execution.udp.policy_closed() => FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        _ => FLOW_STREAM_PACKET_OWNERSHIP,
    }
}

pub(super) fn materialized_runtime_ownership_value(proxy: &plan::ResidentProxyPlan) -> Value {
    let profile = materialized_runtime_ownership(proxy.execution_plan());
    profile.to_materialized_value(&format!("runtime:{}", proxy.graph_link_hash))
}

pub(super) fn source_and_materialized_ownership_agree(
    row: &SourceShapeRegistryRow,
    proxy: &plan::ResidentProxyPlan,
) -> bool {
    let materialized = materialized_runtime_ownership(proxy.execution_plan());
    row.runtime_ownership
        .accepts_materialized(materialized.model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_outbound::{
        CALLER_SCOPED_QUIC_OWNERSHIP, CONFIGURED_HTTP_OWNERSHIP, GENERATION_CONNECT_UDP_OWNERSHIP,
        RuntimeOwnershipModel,
    };
    use plan::{
        ResidentExecutionPlan, ResidentProtocolShape as Protocol, ResidentSecurityUnderlayPlan,
        ResidentStreamWrapperPlan as Wrapper, ResidentUdpExecutorFactory as Udp,
        ResidentXhttpHttpVersion,
    };

    fn execution(protocol: Protocol, wrapper: Wrapper, udp: Udp) -> ResidentExecutionPlan {
        ResidentExecutionPlan {
            protocol,
            security: ResidentSecurityUnderlayPlan::None,
            wrapper,
            udp,
        }
    }

    #[test]
    fn quic_execution_exposes_caller_scoped_physical_transport() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::Hysteria2,
            Wrapper::QuicStream,
            Udp::Hysteria2Datagram,
        ));

        assert_eq!(ownership, CALLER_SCOPED_QUIC_OWNERSHIP);
        assert_eq!(
            ownership.model,
            RuntimeOwnershipModel::CallerScopedQuicTransport
        );
    }

    #[test]
    fn connect_udp_execution_uses_the_generation_transport_contract() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::ConnectUdpH3,
            Wrapper::ConnectUdpH3,
            Udp::ConnectUdpH3,
        ));

        assert_eq!(ownership, GENERATION_CONNECT_UDP_OWNERSHIP);
    }

    #[test]
    fn xhttp_wrapper_selects_its_configured_http_transport_contract() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::VlessStandard,
            Wrapper::Xhttp(ResidentXhttpHttpVersion::H2),
            Udp::VlessStandard(plan::ResidentStreamPacketTransport::XhttpH2),
        ));

        assert_eq!(ownership, CONFIGURED_HTTP_OWNERSHIP);
    }
}
