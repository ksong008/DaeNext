use super::super::*;
use super::*;

const HYSTERIA2_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationOwnedHysteria2Transport];
const TUIC_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationOwnedTuicTransport];
const JUICITY_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationOwnedJuicityTransport];
const QUIC_FAMILY_MODELS: &[RuntimeOwnershipModel] = &[
    RuntimeOwnershipModel::GenerationOwnedHysteria2Transport,
    RuntimeOwnershipModel::GenerationOwnedTuicTransport,
    RuntimeOwnershipModel::GenerationOwnedJuicityTransport,
];

pub const GENERATION_OWNED_HYSTERIA2_OWNERSHIP: RuntimeOwnershipProfile = generation_quic_profile(
    RuntimeOwnershipModel::GenerationOwnedHysteria2Transport,
    HYSTERIA2_MODELS,
    LogicalLeaseKind::Hysteria2Session,
);

pub const GENERATION_OWNED_TUIC_OWNERSHIP: RuntimeOwnershipProfile = generation_quic_profile(
    RuntimeOwnershipModel::GenerationOwnedTuicTransport,
    TUIC_MODELS,
    LogicalLeaseKind::TuicAssociation,
);

pub const GENERATION_OWNED_JUICITY_OWNERSHIP: RuntimeOwnershipProfile = generation_quic_profile(
    RuntimeOwnershipModel::GenerationOwnedJuicityTransport,
    JUICITY_MODELS,
    LogicalLeaseKind::JuicityPacketStream,
);

pub const QUIC_FAMILY_MATERIALIZED_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::MaterializedProtocolTransport,
    allowed_materialized_models: QUIC_FAMILY_MODELS,
    disposition: RuntimeOwnershipDisposition::Implemented,
    data_tcp: generation_quic_route(RuntimeCallerClass::DataTcp, LogicalLeaseKind::QuicStream),
    data_udp: generation_quic_route(
        RuntimeCallerClass::DataUdp,
        LogicalLeaseKind::MaterializedQuicLease,
    ),
    health_tcp: generation_quic_route(RuntimeCallerClass::HealthTcp, LogicalLeaseKind::QuicStream),
    health_dns: generation_quic_route(
        RuntimeCallerClass::HealthDns,
        LogicalLeaseKind::MaterializedQuicLease,
    ),
    manual: generation_quic_route(
        RuntimeCallerClass::ManualProbe,
        LogicalLeaseKind::QuicStream,
    ),
    configured_dns: generation_quic_route(
        RuntimeCallerClass::ConfiguredDns,
        LogicalLeaseKind::MaterializedQuicLease,
    ),
    forced_managed_dns: generation_quic_route(
        RuntimeCallerClass::ForcedManagedDns,
        LogicalLeaseKind::MaterializedQuicLease,
    ),
};

const fn generation_quic_profile(
    model: RuntimeOwnershipModel,
    allowed_materialized_models: &'static [RuntimeOwnershipModel],
    packet_lease: LogicalLeaseKind,
) -> RuntimeOwnershipProfile {
    RuntimeOwnershipProfile {
        model,
        allowed_materialized_models,
        disposition: RuntimeOwnershipDisposition::Implemented,
        data_tcp: generation_quic_route(RuntimeCallerClass::DataTcp, LogicalLeaseKind::QuicStream),
        data_udp: generation_quic_route(RuntimeCallerClass::DataUdp, packet_lease),
        health_tcp: generation_quic_route(
            RuntimeCallerClass::HealthTcp,
            LogicalLeaseKind::QuicStream,
        ),
        health_dns: generation_quic_route(RuntimeCallerClass::HealthDns, packet_lease),
        manual: generation_quic_route(
            RuntimeCallerClass::ManualProbe,
            LogicalLeaseKind::QuicStream,
        ),
        configured_dns: generation_quic_route(RuntimeCallerClass::ConfiguredDns, packet_lease),
        forced_managed_dns: generation_quic_route(
            RuntimeCallerClass::ForcedManagedDns,
            packet_lease,
        ),
    }
}

const fn generation_quic_route(
    caller: RuntimeCallerClass,
    logical_lease: LogicalLeaseKind,
) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::QuicEndpointAndConnection,
        logical_lease,
        RuntimeLifecycleOwner::GenerationRuntime,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        RuntimeBudgetContract::PhysicalOwnerCountAndChargedBytes,
    )
}
