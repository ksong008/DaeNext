use super::super::*;
use super::*;

const FLOW_STREAM_PACKET_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::FlowStreamAndPacketSession];
const FLOW_STREAM_CLOSED_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed];
const FLOW_STREAM_ASSOCIATION_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::FlowStreamAndAssociation];
const GENERATION_VLESS_MUX_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::GenerationOwnedVlessMuxTransport];

pub const FLOW_STREAM_PACKET_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::FlowStreamAndPacketSession,
    allowed_materialized_models: FLOW_STREAM_PACKET_MODELS,
    disposition: RuntimeOwnershipDisposition::IntentionallyPerFlow,
    data_tcp: TCP_FLOW_ROUTE,
    data_udp: UDP_PACKET_ROUTE,
    health_tcp: HEALTH_TCP_STREAM_ROUTE,
    health_dns: HEALTH_DNS_PACKET_ROUTE,
    manual: MANUAL_STREAM_ROUTE,
    configured_dns: CONFIGURED_DNS_PACKET_ROUTE,
    forced_managed_dns: FORCED_MANAGED_DNS_PACKET_ROUTE,
};

pub const FLOW_STREAM_POLICY_CLOSED_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed,
    allowed_materialized_models: FLOW_STREAM_CLOSED_MODELS,
    disposition: RuntimeOwnershipDisposition::IntentionallyPerFlow,
    data_tcp: TCP_FLOW_ROUTE,
    data_udp: closed_route(RuntimeCallerClass::DataUdp),
    health_tcp: HEALTH_TCP_STREAM_ROUTE,
    health_dns: closed_route(RuntimeCallerClass::HealthDns),
    manual: MANUAL_STREAM_ROUTE,
    configured_dns: closed_route(RuntimeCallerClass::ConfiguredDns),
    forced_managed_dns: closed_route(RuntimeCallerClass::ForcedManagedDns),
};

pub const FLOW_STREAM_ASSOCIATION_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::FlowStreamAndAssociation,
    allowed_materialized_models: FLOW_STREAM_ASSOCIATION_MODELS,
    disposition: RuntimeOwnershipDisposition::IntentionallyPerFlow,
    data_tcp: TCP_FLOW_ROUTE,
    data_udp: association_route(
        RuntimeCallerClass::DataUdp,
        RuntimeLifecycleOwner::UdpSessionManager,
        PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
        RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
    ),
    health_tcp: HEALTH_TCP_STREAM_ROUTE,
    health_dns: association_route(
        RuntimeCallerClass::HealthDns,
        RuntimeLifecycleOwner::HealthAttempt,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
        RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
    ),
    manual: MANUAL_STREAM_ROUTE,
    configured_dns: association_route(
        RuntimeCallerClass::ConfiguredDns,
        RuntimeLifecycleOwner::ConfiguredDnsForwarder,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        RuntimeBudgetContract::ConfiguredDnsActorCountAndPayloadBytes,
    ),
    forced_managed_dns: association_route(
        RuntimeCallerClass::ForcedManagedDns,
        RuntimeLifecycleOwner::UdpSessionManager,
        PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
        RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
    ),
};

pub const GENERATION_OWNED_VLESS_MUX_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::GenerationOwnedVlessMuxTransport,
    allowed_materialized_models: GENERATION_VLESS_MUX_MODELS,
    disposition: RuntimeOwnershipDisposition::Implemented,
    data_tcp: generation_vless_mux_route(RuntimeCallerClass::DataTcp),
    data_udp: closed_route(RuntimeCallerClass::DataUdp),
    health_tcp: generation_vless_mux_route(RuntimeCallerClass::HealthTcp),
    health_dns: closed_route(RuntimeCallerClass::HealthDns),
    manual: generation_vless_mux_route(RuntimeCallerClass::ManualProbe),
    configured_dns: closed_route(RuntimeCallerClass::ConfiguredDns),
    forced_managed_dns: closed_route(RuntimeCallerClass::ForcedManagedDns),
};

const fn generation_vless_mux_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::MultiplexedStreamConnection,
        LogicalLeaseKind::MultiplexedByteStream,
        RuntimeLifecycleOwner::GenerationRuntime,
        PhysicalOwnerKeyContract::GenerationGraphAndTransport,
        RuntimeBudgetContract::PhysicalConnectionLogicalStreamAndBufferBytes,
    )
}

const fn association_route(
    caller: RuntimeCallerClass,
    lifecycle_owner: RuntimeLifecycleOwner,
    key_contract: PhysicalOwnerKeyContract,
    budget_contract: RuntimeBudgetContract,
) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::SocksAssociation,
        LogicalLeaseKind::PacketAssociation,
        lifecycle_owner,
        key_contract,
        budget_contract,
    )
}
