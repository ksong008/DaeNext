pub mod connectivity_owned;
pub mod domain_routing;
#[cfg(feature = "ffi-compat")]
pub mod ffi;
pub mod reload;
pub mod routing_native;
pub mod routing_owned;
pub mod runtime_deps;
pub mod runtime_state;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlApiReportStatus {
    Pass,
    Fail,
}

impl ControlApiReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlApiTypedReport {
    pub schema: &'static str,
    pub status: ControlApiReportStatus,
    pub runtime_overview_available: bool,
    pub reload_core_state_available: bool,
    pub domain_routing_owner_available: bool,
    pub runtime_dependency_plan_available: bool,
    pub stage_report_schema: bool,
}

impl ControlApiTypedReport {
    pub fn formal_runtime_control_api() -> Self {
        Self {
            schema: "control-api-typed-report",
            status: ControlApiReportStatus::Pass,
            runtime_overview_available: true,
            reload_core_state_available: true,
            domain_routing_owner_available: true,
            runtime_dependency_plan_available: true,
            stage_report_schema: false,
        }
    }
}

pub use connectivity_owned::{
    ConnectivityMapReplay, ConnectivityOwnerApplyReport, ConnectivityOwnerUpdate,
    ConnectivityStateEntry, ConnectivityStateUpdate, OutboundConnectivityMapOwner,
    OutboundConnectivityOwner, OutboundConnectivityState,
};
pub use domain_routing::{
    DomainRoutingDnsEvent, DomainRoutingIpKey, DomainRoutingMapReplay, DomainRoutingOwner,
    DomainRoutingOwnerSnapshot, DomainRoutingOwnerUpdate, DomainRoutingReloadClearPlan,
    DomainRoutingStateEntry, DomainRoutingSyncPlan, DomainRoutingTracker, DomainRoutingView,
    IpRoutingView, format_ip_key, ip_to_key, parse_ip_key,
};
pub use reload::{CoreFlip, ReloadCoreState, ReloadDnsCachePlan};
pub use routing_native::{
    BPF_F_NO_PREALLOC, DEFAULT_LPM_MAX_ENTRIES, LpmMapTemplate, MAX_LPM_ARRAY_ENTRIES,
    RoutingNativeBuildPlan, RoutingNativeFallback, RoutingNativeMatch, RoutingNativePlanError,
    RoutingNativeRule, build_routing_native_plan, ip_prefix_to_bpf_lpm_key,
};
pub use routing_owned::{
    RoutingMapOwner, RoutingMapOwnerApplyReport, RoutingRuleOwner, RoutingRuleOwnerApplyReport,
    RoutingRuleState,
};
pub use runtime_deps::{EnvironmentGate, RuntimeDependencyPlan};
pub use runtime_state::{ControlPlaneDefaultAdmission, RuntimeStateReport};
