use super::*;

const fn admitted_route(
    caller: RuntimeCallerClass,
    physical_carrier: PhysicalCarrierKind,
    logical_lease: LogicalLeaseKind,
    lifecycle_owner: RuntimeLifecycleOwner,
    key_contract: PhysicalOwnerKeyContract,
    budget_contract: RuntimeBudgetContract,
) -> RuntimeOwnerRoute {
    RuntimeOwnerRoute {
        caller,
        admission: RuntimeRouteAdmission::Admitted,
        physical_carrier,
        logical_lease,
        lifecycle_owner,
        key_contract,
        budget_contract,
    }
}

const fn closed_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    RuntimeOwnerRoute {
        caller,
        admission: RuntimeRouteAdmission::FailClosed,
        physical_carrier: PhysicalCarrierKind::None,
        logical_lease: LogicalLeaseKind::None,
        lifecycle_owner: RuntimeLifecycleOwner::SourceAdmission,
        key_contract: PhysicalOwnerKeyContract::None,
        budget_contract: RuntimeBudgetContract::NotApplicable,
    }
}

const NOT_APPLICABLE_ROUTE: RuntimeOwnerRoute = RuntimeOwnerRoute {
    caller: RuntimeCallerClass::None,
    admission: RuntimeRouteAdmission::NotApplicable,
    physical_carrier: PhysicalCarrierKind::None,
    logical_lease: LogicalLeaseKind::None,
    lifecycle_owner: RuntimeLifecycleOwner::SourceAdmission,
    key_contract: PhysicalOwnerKeyContract::None,
    budget_contract: RuntimeBudgetContract::NotApplicable,
};

const TCP_FLOW_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::TcpFlow,
    PhysicalCarrierKind::PerFlowStream,
    LogicalLeaseKind::ByteStream,
    RuntimeLifecycleOwner::Flow,
    PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    RuntimeBudgetContract::FlowConcurrency,
);
const UDP_PACKET_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::UdpFlow,
    PhysicalCarrierKind::StreamOrDatagramTransport,
    LogicalLeaseKind::PacketSession,
    RuntimeLifecycleOwner::UdpSessionManager,
    PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
    RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
);
const HEALTH_STREAM_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::HealthCheck,
    PhysicalCarrierKind::PerFlowStream,
    LogicalLeaseKind::ByteStream,
    RuntimeLifecycleOwner::HealthAttempt,
    PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    RuntimeBudgetContract::FlowConcurrency,
);
const MANUAL_STREAM_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::ManualProbe,
    PhysicalCarrierKind::PerFlowStream,
    LogicalLeaseKind::ByteStream,
    RuntimeLifecycleOwner::ManualProbeJob,
    PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    RuntimeBudgetContract::FlowConcurrency,
);
const DNS_PACKET_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::ProxyDns,
    PhysicalCarrierKind::StreamOrDatagramTransport,
    LogicalLeaseKind::PacketSession,
    RuntimeLifecycleOwner::DnsRequest,
    PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
    RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
);

pub const FLOW_STREAM_PACKET_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::FlowStreamAndPacketSession,
    disposition: RuntimeOwnershipDisposition::IntentionallyPerFlow,
    tcp: TCP_FLOW_ROUTE,
    udp: UDP_PACKET_ROUTE,
    health: HEALTH_STREAM_ROUTE,
    manual: MANUAL_STREAM_ROUTE,
    dns: DNS_PACKET_ROUTE,
};

pub const FLOW_STREAM_POLICY_CLOSED_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed,
    disposition: RuntimeOwnershipDisposition::IntentionallyPerFlow,
    tcp: TCP_FLOW_ROUTE,
    udp: closed_route(RuntimeCallerClass::UdpFlow),
    health: HEALTH_STREAM_ROUTE,
    manual: MANUAL_STREAM_ROUTE,
    dns: closed_route(RuntimeCallerClass::ProxyDns),
};

pub const FLOW_STREAM_ASSOCIATION_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::FlowStreamAndAssociation,
    disposition: RuntimeOwnershipDisposition::IntentionallyPerFlow,
    tcp: TCP_FLOW_ROUTE,
    udp: admitted_route(
        RuntimeCallerClass::UdpFlow,
        PhysicalCarrierKind::SocksAssociation,
        LogicalLeaseKind::PacketAssociation,
        RuntimeLifecycleOwner::UdpSessionManager,
        PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
        RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
    ),
    health: HEALTH_STREAM_ROUTE,
    manual: MANUAL_STREAM_ROUTE,
    dns: admitted_route(
        RuntimeCallerClass::ProxyDns,
        PhysicalCarrierKind::SocksAssociation,
        LogicalLeaseKind::PacketAssociation,
        RuntimeLifecycleOwner::DnsRequest,
        PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
        RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
    ),
};

const fn quic_route(
    caller: RuntimeCallerClass,
    logical_lease: LogicalLeaseKind,
    lifecycle_owner: RuntimeLifecycleOwner,
) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::QuicEndpointAndConnection,
        logical_lease,
        lifecycle_owner,
        PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
        RuntimeBudgetContract::PhysicalOwnerCountAndChargedBytesMissing,
    )
}

pub const CALLER_SCOPED_QUIC_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::CallerScopedQuicTransport,
    disposition: RuntimeOwnershipDisposition::Implemented,
    tcp: quic_route(
        RuntimeCallerClass::TcpFlow,
        LogicalLeaseKind::QuicStream,
        RuntimeLifecycleOwner::Flow,
    ),
    udp: quic_route(
        RuntimeCallerClass::UdpFlow,
        LogicalLeaseKind::QuicPacketSession,
        RuntimeLifecycleOwner::UdpSessionManager,
    ),
    health: quic_route(
        RuntimeCallerClass::HealthCheck,
        LogicalLeaseKind::QuicStream,
        RuntimeLifecycleOwner::HealthAttempt,
    ),
    manual: quic_route(
        RuntimeCallerClass::ManualProbe,
        LogicalLeaseKind::QuicStream,
        RuntimeLifecycleOwner::ManualProbeJob,
    ),
    dns: quic_route(
        RuntimeCallerClass::ProxyDns,
        LogicalLeaseKind::QuicPacketSession,
        RuntimeLifecycleOwner::DnsRequest,
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

pub const GENERATION_CONNECT_UDP_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::GenerationConnectUdpTransport,
    disposition: RuntimeOwnershipDisposition::Implemented,
    tcp: NOT_APPLICABLE_ROUTE,
    udp: connect_udp_route(RuntimeCallerClass::UdpFlow),
    health: connect_udp_route(RuntimeCallerClass::HealthCheck),
    manual: connect_udp_route(RuntimeCallerClass::ManualProbe),
    dns: connect_udp_route(RuntimeCallerClass::ProxyDns),
};

const fn configured_http_route(
    caller: RuntimeCallerClass,
    lifecycle_owner: RuntimeLifecycleOwner,
) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::ConfiguredHttpConnection,
        LogicalLeaseKind::HttpStreamOrExchange,
        lifecycle_owner,
        PhysicalOwnerKeyContract::ConfiguredPoolOrFlowGraphAndTransport,
        RuntimeBudgetContract::ConfiguredConnectionCountWithChargedBytesMissing,
    )
}

pub const CONFIGURED_HTTP_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::ConfiguredHttpTransport,
    disposition: RuntimeOwnershipDisposition::Implemented,
    tcp: configured_http_route(
        RuntimeCallerClass::TcpFlow,
        RuntimeLifecycleOwner::GenerationOrCaller,
    ),
    udp: configured_http_route(
        RuntimeCallerClass::UdpFlow,
        RuntimeLifecycleOwner::GenerationOrCaller,
    ),
    health: configured_http_route(
        RuntimeCallerClass::HealthCheck,
        RuntimeLifecycleOwner::HealthAttempt,
    ),
    manual: configured_http_route(
        RuntimeCallerClass::ManualProbe,
        RuntimeLifecycleOwner::ManualProbeJob,
    ),
    dns: configured_http_route(
        RuntimeCallerClass::ProxyDns,
        RuntimeLifecycleOwner::DnsRequest,
    ),
};

const fn resolved_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::MaterializedTransport,
        LogicalLeaseKind::MaterializedLease,
        RuntimeLifecycleOwner::ResolvedAtMaterialization,
        PhysicalOwnerKeyContract::ResolvedAtMaterialization,
        RuntimeBudgetContract::ResolvedAtMaterialization,
    )
}

pub const MATERIALIZED_PROTOCOL_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::MaterializedProtocolTransport,
    disposition: RuntimeOwnershipDisposition::Implemented,
    tcp: resolved_route(RuntimeCallerClass::TcpFlow),
    udp: resolved_route(RuntimeCallerClass::UdpFlow),
    health: resolved_route(RuntimeCallerClass::HealthCheck),
    manual: resolved_route(RuntimeCallerClass::ManualProbe),
    dns: resolved_route(RuntimeCallerClass::ProxyDns),
};

const fn rejected_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    RuntimeOwnerRoute {
        caller,
        admission: RuntimeRouteAdmission::FailClosed,
        physical_carrier: PhysicalCarrierKind::External,
        logical_lease: LogicalLeaseKind::None,
        lifecycle_owner: RuntimeLifecycleOwner::SourceAdmission,
        key_contract: PhysicalOwnerKeyContract::None,
        budget_contract: RuntimeBudgetContract::NotApplicable,
    }
}

pub const SOURCE_REJECTED_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::SourceAdmissionRejected,
    disposition: RuntimeOwnershipDisposition::FailClosed,
    tcp: rejected_route(RuntimeCallerClass::TcpFlow),
    udp: rejected_route(RuntimeCallerClass::UdpFlow),
    health: rejected_route(RuntimeCallerClass::HealthCheck),
    manual: rejected_route(RuntimeCallerClass::ManualProbe),
    dns: rejected_route(RuntimeCallerClass::ProxyDns),
};
