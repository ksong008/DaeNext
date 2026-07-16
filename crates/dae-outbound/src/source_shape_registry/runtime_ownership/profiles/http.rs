use super::super::*;
use super::*;

const CONNECT_UDP_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationConnectUdpTransport];
const CONFIGURED_HTTP_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::ConfiguredHttpTransport];

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
