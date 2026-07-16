use super::*;

#[path = "ownership/mapper.rs"]
mod mapper;
use self::mapper::materialized_runtime_ownership;

pub(super) fn materialized_runtime_ownership_value(proxy: &plan::ResidentProxyPlan) -> Value {
    let profile = materialized_runtime_ownership(proxy.execution_plan());
    let redacted_identity = format!("runtime:{}", proxy.graph_link_hash);
    if profile.model == dae_outbound::RuntimeOwnershipModel::MaterializedShapeRejected {
        profile.to_materialization_rejected_value(&redacted_identity)
    } else {
        profile.to_materialized_value(&redacted_identity)
    }
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
#[path = "ownership/real_plan_tests.rs"]
mod real_plan_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use dae_outbound::{
        CALLER_SCOPED_HYSTERIA2_OWNERSHIP, CALLER_SCOPED_JUICITY_OWNERSHIP,
        CALLER_SCOPED_TUIC_OWNERSHIP, CONFIGURED_HTTP_OWNERSHIP, GENERATION_CONNECT_UDP_OWNERSHIP,
        LogicalLeaseKind, MATERIALIZED_SHAPE_REJECTED_OWNERSHIP, PhysicalCarrierKind,
        RuntimeOwnershipModel, RuntimeRouteAdmission,
    };
    use plan::{
        ResidentExecutionPlan, ResidentProtocolShape as Protocol,
        ResidentSecurityUnderlayPlan as Security, ResidentStreamPacketTransport as Stream,
        ResidentStreamWrapperPlan as Wrapper, ResidentUdpExecutorFactory as Udp,
        ResidentUdpPolicyClosedReason as Closed, ResidentXhttpHttpVersion,
    };

    fn execution(
        protocol: Protocol,
        security: Security,
        wrapper: Wrapper,
        udp: Udp,
    ) -> ResidentExecutionPlan {
        ResidentExecutionPlan {
            protocol,
            security,
            wrapper,
            udp,
            runtime_generation: ResidentExecutionPlan::plan_generation(),
        }
    }

    #[test]
    fn quic_execution_exposes_caller_scoped_physical_transport() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::Hysteria2,
            Security::QuicTls,
            Wrapper::QuicStream,
            Udp::Hysteria2Datagram,
        ));

        assert_eq!(ownership, CALLER_SCOPED_HYSTERIA2_OWNERSHIP);
        assert_eq!(
            ownership.model,
            RuntimeOwnershipModel::CallerScopedHysteria2Transport
        );
    }

    #[test]
    fn connect_udp_execution_uses_the_generation_transport_contract() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::ConnectUdpH3,
            Security::QuicTls,
            Wrapper::ConnectUdpH3,
            Udp::ConnectUdpH3,
        ));

        assert_eq!(ownership, GENERATION_CONNECT_UDP_OWNERSHIP);
    }

    #[test]
    fn quic_packet_leases_remain_protocol_specific() {
        let tuic = materialized_runtime_ownership(execution(
            Protocol::Tuic,
            Security::QuicTls,
            Wrapper::QuicStream,
            Udp::TuicPacket,
        ));
        let juicity = materialized_runtime_ownership(execution(
            Protocol::Juicity,
            Security::QuicTls,
            Wrapper::QuicStream,
            Udp::JuicityStreamPacket,
        ));

        assert_eq!(tuic, CALLER_SCOPED_TUIC_OWNERSHIP);
        assert_eq!(
            tuic.data_udp.logical_lease,
            LogicalLeaseKind::TuicAssociation
        );
        assert_eq!(juicity, CALLER_SCOPED_JUICITY_OWNERSHIP);
        assert_eq!(
            juicity.data_udp.logical_lease,
            LogicalLeaseKind::JuicityPacketStream
        );
    }

    #[test]
    fn xhttp_wrapper_selects_its_configured_http_transport_contract() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::VlessStandard,
            Security::StandardTls,
            Wrapper::Xhttp(ResidentXhttpHttpVersion::H2),
            Udp::VlessStandard(plan::ResidentStreamPacketTransport::XhttpH2),
        ));

        assert_eq!(ownership, CONFIGURED_HTTP_OWNERSHIP);
    }

    #[test]
    fn incompatible_typed_dimensions_map_to_materialization_rejected_contract() {
        let incompatible = [
            execution(
                Protocol::Hysteria2,
                Security::StandardTls,
                Wrapper::QuicStream,
                Udp::Hysteria2Datagram,
            ),
            execution(
                Protocol::Hysteria2,
                Security::QuicTls,
                Wrapper::Xhttp(ResidentXhttpHttpVersion::H2),
                Udp::Hysteria2Datagram,
            ),
            execution(
                Protocol::Hysteria2,
                Security::QuicTls,
                Wrapper::QuicStream,
                Udp::TuicPacket,
            ),
            execution(
                Protocol::Tuic,
                Security::QuicTls,
                Wrapper::QuicStream,
                Udp::Hysteria2Datagram,
            ),
            execution(
                Protocol::VlessStandard,
                Security::StandardTls,
                Wrapper::Xhttp(ResidentXhttpHttpVersion::H2),
                Udp::VlessStandard(plan::ResidentStreamPacketTransport::XhttpH3),
            ),
            execution(
                Protocol::VlessStandard,
                Security::RealityRustls,
                Wrapper::Xhttp(ResidentXhttpHttpVersion::H3),
                Udp::VlessStandard(Stream::XhttpH3),
            ),
            execution(
                Protocol::VlessStandard,
                Security::None,
                Wrapper::WebSocket,
                Udp::VlessStandard(Stream::WebSocketPlain),
            ),
            execution(
                Protocol::VlessStandard,
                Security::None,
                Wrapper::HttpUpgrade,
                Udp::VlessStandard(Stream::HttpUpgradePlain),
            ),
            execution(
                Protocol::VlessStandard,
                Security::RealityRustls,
                Wrapper::H2,
                Udp::VlessStandard(Stream::H2Tls),
            ),
            execution(
                Protocol::VmessAead,
                Security::None,
                Wrapper::H2,
                Udp::PolicyClosed(Closed::VmessH2),
            ),
        ];

        for execution in incompatible {
            let ownership = materialized_runtime_ownership(execution);
            assert_eq!(ownership, MATERIALIZED_SHAPE_REJECTED_OWNERSHIP);
            assert_eq!(
                ownership.data_tcp.admission,
                RuntimeRouteAdmission::FailClosed
            );
            assert_eq!(
                ownership.data_tcp.physical_carrier,
                PhysicalCarrierKind::None
            );
            assert_eq!(
                ownership.data_udp.admission,
                RuntimeRouteAdmission::FailClosed
            );
        }
    }
}
