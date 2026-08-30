use super::super::*;

pub(super) const fn admitted_route(
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

pub(super) const fn closed_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
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

pub(super) const fn not_applicable_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    RuntimeOwnerRoute {
        caller,
        admission: RuntimeRouteAdmission::NotApplicable,
        physical_carrier: PhysicalCarrierKind::None,
        logical_lease: LogicalLeaseKind::None,
        lifecycle_owner: RuntimeLifecycleOwner::SourceAdmission,
        key_contract: PhysicalOwnerKeyContract::None,
        budget_contract: RuntimeBudgetContract::NotApplicable,
    }
}

pub(super) const TCP_FLOW_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::DataTcp,
    PhysicalCarrierKind::PerFlowStream,
    LogicalLeaseKind::ByteStream,
    RuntimeLifecycleOwner::Flow,
    PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    RuntimeBudgetContract::FlowConcurrency,
);

pub(super) const UDP_PACKET_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::DataUdp,
    PhysicalCarrierKind::StreamOrDatagramTransport,
    LogicalLeaseKind::PacketSession,
    RuntimeLifecycleOwner::UdpSessionManager,
    PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
    RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
);

pub(super) const HEALTH_TCP_STREAM_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::HealthTcp,
    PhysicalCarrierKind::PerFlowStream,
    LogicalLeaseKind::ByteStream,
    RuntimeLifecycleOwner::HealthAttempt,
    PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    RuntimeBudgetContract::FlowConcurrency,
);

pub(super) const HEALTH_DNS_PACKET_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::HealthDns,
    PhysicalCarrierKind::StreamOrDatagramTransport,
    LogicalLeaseKind::PacketSession,
    RuntimeLifecycleOwner::HealthAttempt,
    PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
);

pub(super) const MANUAL_STREAM_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::ManualProbe,
    PhysicalCarrierKind::PerFlowStream,
    LogicalLeaseKind::ByteStream,
    RuntimeLifecycleOwner::ManualProbeJob,
    PhysicalOwnerKeyContract::FlowGraphTargetAndTransport,
    RuntimeBudgetContract::FlowConcurrency,
);

pub(super) const CONFIGURED_DNS_PACKET_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::ConfiguredDns,
    PhysicalCarrierKind::StreamOrDatagramTransport,
    LogicalLeaseKind::PacketSession,
    RuntimeLifecycleOwner::ConfiguredDnsForwarder,
    PhysicalOwnerKeyContract::GenerationGraphAndTransport,
    RuntimeBudgetContract::ConfiguredDnsActorCountAndPayloadBytes,
);

pub(super) const FORCED_MANAGED_DNS_PACKET_ROUTE: RuntimeOwnerRoute = admitted_route(
    RuntimeCallerClass::ForcedManagedDns,
    PhysicalCarrierKind::StreamOrDatagramTransport,
    LogicalLeaseKind::PacketSession,
    RuntimeLifecycleOwner::UdpSessionManager,
    PhysicalOwnerKeyContract::UdpSessionGraphTargetAndTransport,
    RuntimeBudgetContract::UdpSessionCountAndPayloadBytes,
);

pub(super) const fn materialized_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    admitted_route(
        caller,
        PhysicalCarrierKind::MaterializedTransport,
        LogicalLeaseKind::MaterializedLease,
        RuntimeLifecycleOwner::ResolvedAtMaterialization,
        PhysicalOwnerKeyContract::ResolvedAtMaterialization,
        RuntimeBudgetContract::ResolvedAtMaterialization,
    )
}
