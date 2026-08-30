use super::super::*;
use super::*;

const CONNECT_UDP_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationConnectUdpTransport];
const CONFIGURED_HTTP_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::ConfiguredHttpTransport];
const GENERATION_MEEK_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationOwnedMeekTransport];
const GENERATION_XHTTP_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationOwnedXhttpTransport];

pub const GENERATION_CONNECT_UDP_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::GenerationConnectUdpTransport,
    allowed_materialized_models: CONNECT_UDP_MODELS,
    disposition: RuntimeOwnershipDisposition::Implemented,
    data_tcp: not_applicable_route(RuntimeCallerClass::DataTcp),
    data_udp: connect_udp_route(RuntimeCallerClass::DataUdp),
    health_tcp: closed_route(RuntimeCallerClass::HealthTcp),
    health_dns: connect_udp_route(RuntimeCallerClass::HealthDns),
    manual: connect_udp_route(RuntimeCallerClass::ManualProbe),
    configured_dns: connect_udp_route(RuntimeCallerClass::ConfiguredDns),
    forced_managed_dns: connect_udp_route(RuntimeCallerClass::ForcedManagedDns),
};

pub const CONFIGURED_HTTP_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::ConfiguredHttpTransport,
    allowed_materialized_models: CONFIGURED_HTTP_MODELS,
    disposition: RuntimeOwnershipDisposition::Blocked,
    data_tcp: configured_http_route(
        RuntimeCallerClass::DataTcp,
        RuntimeLifecycleOwner::GenerationOrCaller,
        PhysicalOwnerKeyContract::ConfiguredPoolOrFlowGraphAndTransport,
    ),
    data_udp: configured_http_route(
        RuntimeCallerClass::DataUdp,
        RuntimeLifecycleOwner::GenerationOrCaller,
        PhysicalOwnerKeyContract::ConfiguredPoolOrFlowGraphAndTransport,
    ),
    health_tcp: configured_http_route(
        RuntimeCallerClass::HealthTcp,
        RuntimeLifecycleOwner::HealthAttempt,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    ),
    health_dns: configured_http_route(
        RuntimeCallerClass::HealthDns,
        RuntimeLifecycleOwner::HealthAttempt,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    ),
    manual: configured_http_route(
        RuntimeCallerClass::ManualProbe,
        RuntimeLifecycleOwner::ManualProbeJob,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    ),
    configured_dns: configured_http_route(
        RuntimeCallerClass::ConfiguredDns,
        RuntimeLifecycleOwner::ConfiguredDnsForwarder,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
    ),
    forced_managed_dns: configured_http_route(
        RuntimeCallerClass::ForcedManagedDns,
        RuntimeLifecycleOwner::UdpSessionManager,
        PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
    ),
};

pub const GENERATION_OWNED_MEEK_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::GenerationOwnedMeekTransport,
    allowed_materialized_models: GENERATION_MEEK_MODELS,
    disposition: RuntimeOwnershipDisposition::Implemented,
    data_tcp: generation_meek_route(RuntimeCallerClass::DataTcp),
    data_udp: closed_route(RuntimeCallerClass::DataUdp),
    health_tcp: generation_meek_route(RuntimeCallerClass::HealthTcp),
    health_dns: closed_route(RuntimeCallerClass::HealthDns),
    manual: generation_meek_route(RuntimeCallerClass::ManualProbe),
    configured_dns: closed_route(RuntimeCallerClass::ConfiguredDns),
    forced_managed_dns: closed_route(RuntimeCallerClass::ForcedManagedDns),
};

pub const GENERATION_OWNED_XHTTP_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::GenerationOwnedXhttpTransport,
    allowed_materialized_models: GENERATION_XHTTP_MODELS,
    disposition: RuntimeOwnershipDisposition::Implemented,
    data_tcp: generation_xhttp_stream_route(RuntimeCallerClass::DataTcp),
    data_udp: generation_xhttp_packet_route(RuntimeCallerClass::DataUdp),
    health_tcp: generation_xhttp_stream_route(RuntimeCallerClass::HealthTcp),
    health_dns: generation_xhttp_packet_route(RuntimeCallerClass::HealthDns),
    manual: generation_xhttp_stream_route(RuntimeCallerClass::ManualProbe),
    configured_dns: generation_xhttp_packet_route(RuntimeCallerClass::ConfiguredDns),
    forced_managed_dns: generation_xhttp_packet_route(RuntimeCallerClass::ForcedManagedDns),
};

const fn connect_udp_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::ConnectUdpHttpConnection,
        LogicalLeaseKind::ConnectUdpContext,
        RuntimeLifecycleOwner::GenerationRuntime,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        RuntimeBudgetContract::PoolCountAndChargedBytes,
    )
}

const fn configured_http_route(
    caller: RuntimeCallerClass,
    lifecycle_owner: RuntimeLifecycleOwner,
    key_contract: PhysicalOwnerKeyContract,
) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::ConfiguredHttpConnection,
        LogicalLeaseKind::HttpStreamOrExchange,
        lifecycle_owner,
        key_contract,
        RuntimeBudgetContract::ConfiguredConnectionCountWithChargedBytesMissing,
    )
}

const fn generation_meek_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::ConfiguredHttpConnection,
        LogicalLeaseKind::HttpStreamOrExchange,
        RuntimeLifecycleOwner::GenerationRuntime,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        RuntimeBudgetContract::PhysicalConnectionCountAndBoundedExchangeBytes,
    )
}

const fn generation_xhttp_stream_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::ConfiguredHttpConnection,
        LogicalLeaseKind::HttpStreamOrExchange,
        RuntimeLifecycleOwner::GenerationRuntime,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        RuntimeBudgetContract::PhysicalConnectionLogicalStreamAndBufferBytes,
    )
}

const fn generation_xhttp_packet_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::ConfiguredHttpConnection,
        LogicalLeaseKind::PacketSession,
        RuntimeLifecycleOwner::GenerationRuntime,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        RuntimeBudgetContract::PhysicalConnectionLogicalStreamAndBufferBytes,
    )
}
