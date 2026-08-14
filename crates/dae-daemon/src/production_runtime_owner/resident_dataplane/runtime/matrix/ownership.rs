use super::*;

#[path = "ownership/mapper.rs"]
mod mapper;
use self::mapper::{materialized_execution_shape, materialized_runtime_ownership};

pub(super) fn materialized_source_execution_shape(
    proxy: &plan::ResidentProxyPlan,
) -> dae_outbound::MaterializedExecutionShape {
    materialized_execution_shape(proxy.execution_plan())
}

pub(super) fn materialized_runtime_ownership_value(proxy: &plan::ResidentProxyPlan) -> Value {
    let profile = effective_materialized_runtime_ownership(proxy);
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
    let materialized = effective_materialized_runtime_ownership(proxy);
    row.runtime_ownership
        .accepts_materialized(materialized.model)
}

pub(super) fn effective_materialized_runtime_ownership(
    proxy: &plan::ResidentProxyPlan,
) -> dae_outbound::RuntimeOwnershipProfile {
    let raw = materialized_runtime_ownership(proxy.execution_plan());
    if raw.model == dae_outbound::RuntimeOwnershipModel::MaterializedShapeRejected {
        return raw;
    }

    match plan::resident_udp_chain_admission(proxy) {
        plan::ResidentUdpChainAdmission::NotChained => raw,
        plan::ResidentUdpChainAdmission::ParentStream
            if raw.model == dae_outbound::RuntimeOwnershipModel::FlowStreamAndPacketSession =>
        {
            raw
        }
        plan::ResidentUdpChainAdmission::ParentStream => {
            dae_outbound::MATERIALIZED_SHAPE_REJECTED_OWNERSHIP
        }
        plan::ResidentUdpChainAdmission::Unsupported(_) => {
            dae_outbound::FLOW_STREAM_POLICY_CLOSED_OWNERSHIP
        }
    }
}

#[cfg(test)]
#[path = "ownership/real_plan_tests.rs"]
mod real_plan_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use dae_outbound::{
        GENERATION_OWNED_HYSTERIA2_OWNERSHIP, GENERATION_OWNED_JUICITY_OWNERSHIP,
        GENERATION_OWNED_MEEK_OWNERSHIP, GENERATION_OWNED_TUIC_OWNERSHIP,
        GENERATION_OWNED_VLESS_MUX_OWNERSHIP, GENERATION_OWNED_XHTTP_OWNERSHIP, LogicalLeaseKind,
        MATERIALIZED_SHAPE_REJECTED_OWNERSHIP, PhysicalCarrierKind, RuntimeLifecycleOwner,
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
    fn shared_quic_execution_exposes_generation_owned_physical_transport() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::Hysteria2,
            Security::QuicTls,
            Wrapper::QuicStream,
            Udp::Hysteria2Datagram,
        ));

        assert_eq!(ownership, GENERATION_OWNED_HYSTERIA2_OWNERSHIP);
        assert_eq!(
            ownership.model,
            RuntimeOwnershipModel::GenerationOwnedHysteria2Transport
        );
        assert_eq!(
            ownership.data_tcp.lifecycle_owner,
            RuntimeLifecycleOwner::GenerationRuntime
        );
    }

    #[test]
    fn meek_execution_exposes_generation_owned_http1_transport() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::VlessStandard,
            Security::StandardTls,
            Wrapper::Meek,
            Udp::PolicyClosed(Closed::VlessMeek),
        ));

        assert_eq!(ownership, GENERATION_OWNED_MEEK_OWNERSHIP);
        assert_eq!(
            ownership.model,
            RuntimeOwnershipModel::GenerationOwnedMeekTransport
        );
        assert_eq!(
            ownership.data_tcp.lifecycle_owner,
            RuntimeLifecycleOwner::GenerationRuntime
        );
        assert_eq!(
            ownership.data_udp.admission,
            RuntimeRouteAdmission::FailClosed
        );
    }

    #[test]
    fn vless_mux_execution_exposes_generation_owned_multiplexed_transport() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::VlessMux,
            Security::StandardTls,
            Wrapper::Mux,
            Udp::PolicyClosed(Closed::VlessMux),
        ));

        assert_eq!(ownership, GENERATION_OWNED_VLESS_MUX_OWNERSHIP);
        assert_eq!(
            ownership.model,
            RuntimeOwnershipModel::GenerationOwnedVlessMuxTransport
        );
        assert_eq!(
            ownership.data_tcp.physical_carrier,
            PhysicalCarrierKind::MultiplexedStreamConnection
        );
        assert_eq!(
            ownership.data_tcp.logical_lease,
            LogicalLeaseKind::MultiplexedByteStream
        );
        assert_eq!(
            ownership.data_udp.admission,
            RuntimeRouteAdmission::FailClosed
        );
    }

    #[test]
    fn quic_packet_leases_remain_protocol_specific() {
        let tuic = materialized_runtime_ownership(execution(
            Protocol::Tuic,
            Security::QuicTls,
            Wrapper::QuicStream,
            Udp::TuicPacket(dae_outbound::tuic::TuicUdpRelayMode::Native),
        ));
        let juicity = materialized_runtime_ownership(execution(
            Protocol::Juicity,
            Security::QuicTls,
            Wrapper::QuicStream,
            Udp::JuicityStreamPacket,
        ));

        assert_eq!(tuic, GENERATION_OWNED_TUIC_OWNERSHIP);
        assert_eq!(
            tuic.data_udp.logical_lease,
            LogicalLeaseKind::TuicAssociation
        );
        assert_eq!(juicity, GENERATION_OWNED_JUICITY_OWNERSHIP);
        assert_eq!(
            juicity.data_udp.logical_lease,
            LogicalLeaseKind::JuicityPacketStream
        );
    }

    #[test]
    fn xhttp_wrapper_selects_its_generation_transport_contract() {
        let ownership = materialized_runtime_ownership(execution(
            Protocol::VlessStandard,
            Security::StandardTls,
            Wrapper::Xhttp(ResidentXhttpHttpVersion::H2),
            Udp::VlessStandard(plan::ResidentStreamPacketTransport::XhttpH2),
        ));

        assert_eq!(ownership, GENERATION_OWNED_XHTTP_OWNERSHIP);
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
                Udp::TuicPacket(dae_outbound::tuic::TuicUdpRelayMode::Native),
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
