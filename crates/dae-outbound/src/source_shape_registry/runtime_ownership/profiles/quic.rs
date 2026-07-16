use super::super::*;
use super::*;

const HYSTERIA2_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::CallerScopedHysteria2Transport];
const TUIC_MODELS: &[RuntimeOwnershipModel] = &[RuntimeOwnershipModel::CallerScopedTuicTransport];
const JUICITY_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::CallerScopedJuicityTransport];
const QUIC_FAMILY_MODELS: &[RuntimeOwnershipModel] = &[
    RuntimeOwnershipModel::CallerScopedHysteria2Transport,
    RuntimeOwnershipModel::CallerScopedTuicTransport,
    RuntimeOwnershipModel::CallerScopedJuicityTransport,
];

pub const CALLER_SCOPED_HYSTERIA2_OWNERSHIP: RuntimeOwnershipProfile = quic_profile(
    RuntimeOwnershipModel::CallerScopedHysteria2Transport,
    HYSTERIA2_MODELS,
    LogicalLeaseKind::Hysteria2Session,
);

pub const CALLER_SCOPED_TUIC_OWNERSHIP: RuntimeOwnershipProfile = quic_profile(
    RuntimeOwnershipModel::CallerScopedTuicTransport,
    TUIC_MODELS,
    LogicalLeaseKind::TuicAssociation,
);

pub const CALLER_SCOPED_JUICITY_OWNERSHIP: RuntimeOwnershipProfile = quic_profile(
    RuntimeOwnershipModel::CallerScopedJuicityTransport,
    JUICITY_MODELS,
    LogicalLeaseKind::JuicityPacketStream,
);

pub const QUIC_FAMILY_MATERIALIZED_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::MaterializedProtocolTransport,
    allowed_materialized_models: QUIC_FAMILY_MODELS,
    disposition: RuntimeOwnershipDisposition::Blocked,
    data_tcp: quic_route(
        RuntimeCallerClass::DataTcp,
        LogicalLeaseKind::QuicStream,
        RuntimeLifecycleOwner::Flow,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    ),
    data_udp: quic_route(
        RuntimeCallerClass::DataUdp,
        LogicalLeaseKind::MaterializedQuicLease,
        RuntimeLifecycleOwner::UdpSessionManager,
        PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
    ),
    health_tcp: quic_route(
        RuntimeCallerClass::HealthTcp,
        LogicalLeaseKind::QuicStream,
        RuntimeLifecycleOwner::HealthAttempt,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    ),
    health_dns: quic_route(
        RuntimeCallerClass::HealthDns,
        LogicalLeaseKind::MaterializedQuicLease,
        RuntimeLifecycleOwner::HealthAttempt,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    ),
    manual: quic_route(
        RuntimeCallerClass::ManualProbe,
        LogicalLeaseKind::QuicStream,
        RuntimeLifecycleOwner::ManualProbeJob,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    ),
    configured_dns: quic_route(
        RuntimeCallerClass::ConfiguredDns,
        LogicalLeaseKind::MaterializedQuicLease,
        RuntimeLifecycleOwner::ConfiguredDnsForwarder,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
    ),
    forced_managed_dns: quic_route(
        RuntimeCallerClass::ForcedManagedDns,
        LogicalLeaseKind::MaterializedQuicLease,
        RuntimeLifecycleOwner::UdpSessionManager,
        PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
    ),
};

const fn quic_profile(
    model: RuntimeOwnershipModel,
    allowed_materialized_models: &'static [RuntimeOwnershipModel],
    packet_lease: LogicalLeaseKind,
) -> RuntimeOwnershipProfile {
    RuntimeOwnershipProfile {
        model,
        allowed_materialized_models,
        disposition: RuntimeOwnershipDisposition::Blocked,
        data_tcp: quic_route(
            RuntimeCallerClass::DataTcp,
            LogicalLeaseKind::QuicStream,
            RuntimeLifecycleOwner::Flow,
            PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
        ),
        data_udp: quic_route(
            RuntimeCallerClass::DataUdp,
            packet_lease,
            RuntimeLifecycleOwner::UdpSessionManager,
            PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
        ),
        health_tcp: quic_route(
            RuntimeCallerClass::HealthTcp,
            LogicalLeaseKind::QuicStream,
            RuntimeLifecycleOwner::HealthAttempt,
            PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
        ),
        health_dns: quic_route(
            RuntimeCallerClass::HealthDns,
            packet_lease,
            RuntimeLifecycleOwner::HealthAttempt,
            PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
        ),
        manual: quic_route(
            RuntimeCallerClass::ManualProbe,
            LogicalLeaseKind::QuicStream,
            RuntimeLifecycleOwner::ManualProbeJob,
            PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
        ),
        configured_dns: quic_route(
            RuntimeCallerClass::ConfiguredDns,
            packet_lease,
            RuntimeLifecycleOwner::ConfiguredDnsForwarder,
            PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        ),
        forced_managed_dns: quic_route(
            RuntimeCallerClass::ForcedManagedDns,
            packet_lease,
            RuntimeLifecycleOwner::UdpSessionManager,
            PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
        ),
    }
}

const fn quic_route(
    caller: RuntimeCallerClass,
    logical_lease: LogicalLeaseKind,
    lifecycle_owner: RuntimeLifecycleOwner,
    key_contract: PhysicalOwnerKeyContract,
) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::QuicEndpointAndConnection,
        logical_lease,
        lifecycle_owner,
        key_contract,
        RuntimeBudgetContract::PhysicalOwnerCountAndChargedBytesMissing,
    )
}
