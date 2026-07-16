use super::super::*;
use super::*;

const MATERIALIZED_STREAM_SECURITY_MODELS: &[RuntimeOwnershipModel] = &[
    RuntimeOwnershipModel::FlowStreamAndPacketSession,
    RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed,
    RuntimeOwnershipModel::ConfiguredHttpTransport,
];

const MATERIALIZED_CHAIN_MODELS: &[RuntimeOwnershipModel] = &[
    RuntimeOwnershipModel::FlowStreamAndPacketSession,
    RuntimeOwnershipModel::FlowStreamWithPacketPolicyClosed,
    RuntimeOwnershipModel::FlowStreamAndAssociation,
];

const SOURCE_REJECTED_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::SourceAdmissionRejected];
const MATERIALIZED_SHAPE_REJECTED_MODELS: &[RuntimeOwnershipModel] =
    &[RuntimeOwnershipModel::MaterializedShapeRejected];

pub const MATERIALIZED_STREAM_SECURITY_OWNERSHIP: RuntimeOwnershipProfile =
    materialized_profile(MATERIALIZED_STREAM_SECURITY_MODELS);

pub const MATERIALIZED_CHAIN_OWNERSHIP: RuntimeOwnershipProfile =
    materialized_profile(MATERIALIZED_CHAIN_MODELS);

pub const MATERIALIZED_SHAPE_REJECTED_OWNERSHIP: RuntimeOwnershipProfile =
    RuntimeOwnershipProfile {
        model: RuntimeOwnershipModel::MaterializedShapeRejected,
        allowed_materialized_models: MATERIALIZED_SHAPE_REJECTED_MODELS,
        disposition: RuntimeOwnershipDisposition::FailClosed,
        data_tcp: materialization_rejected_route(RuntimeCallerClass::DataTcp),
        data_udp: materialization_rejected_route(RuntimeCallerClass::DataUdp),
        health_tcp: materialization_rejected_route(RuntimeCallerClass::HealthTcp),
        health_dns: materialization_rejected_route(RuntimeCallerClass::HealthDns),
        manual: materialization_rejected_route(RuntimeCallerClass::ManualProbe),
        configured_dns: materialization_rejected_route(RuntimeCallerClass::ConfiguredDns),
        forced_managed_dns: materialization_rejected_route(RuntimeCallerClass::ForcedManagedDns),
    };

pub const SOURCE_REJECTED_OWNERSHIP: RuntimeOwnershipProfile = RuntimeOwnershipProfile {
    model: RuntimeOwnershipModel::SourceAdmissionRejected,
    allowed_materialized_models: SOURCE_REJECTED_MODELS,
    disposition: RuntimeOwnershipDisposition::FailClosed,
    data_tcp: rejected_route(RuntimeCallerClass::DataTcp),
    data_udp: rejected_route(RuntimeCallerClass::DataUdp),
    health_tcp: rejected_route(RuntimeCallerClass::HealthTcp),
    health_dns: rejected_route(RuntimeCallerClass::HealthDns),
    manual: rejected_route(RuntimeCallerClass::ManualProbe),
    configured_dns: rejected_route(RuntimeCallerClass::ConfiguredDns),
    forced_managed_dns: rejected_route(RuntimeCallerClass::ForcedManagedDns),
};

const fn materialized_profile(
    allowed_materialized_models: &'static [RuntimeOwnershipModel],
) -> RuntimeOwnershipProfile {
    RuntimeOwnershipProfile {
        model: RuntimeOwnershipModel::MaterializedProtocolTransport,
        allowed_materialized_models,
        disposition: RuntimeOwnershipDisposition::Blocked,
        data_tcp: materialized_route(RuntimeCallerClass::DataTcp),
        data_udp: materialized_route(RuntimeCallerClass::DataUdp),
        health_tcp: materialized_route(RuntimeCallerClass::HealthTcp),
        health_dns: materialized_route(RuntimeCallerClass::HealthDns),
        manual: materialized_route(RuntimeCallerClass::ManualProbe),
        configured_dns: materialized_route(RuntimeCallerClass::ConfiguredDns),
        forced_managed_dns: materialized_route(RuntimeCallerClass::ForcedManagedDns),
    }
}

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

const fn materialization_rejected_route(caller: RuntimeCallerClass) -> RuntimeOwnerRoute {
    RuntimeOwnerRoute {
        caller,
        admission: RuntimeRouteAdmission::FailClosed,
        physical_carrier: PhysicalCarrierKind::None,
        logical_lease: LogicalLeaseKind::None,
        lifecycle_owner: RuntimeLifecycleOwner::ResolvedAtMaterialization,
        key_contract: PhysicalOwnerKeyContract::None,
        budget_contract: RuntimeBudgetContract::NotApplicable,
    }
}
