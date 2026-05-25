pub mod domain_routing;
pub mod reload;
pub mod runtime_deps;

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
            schema: "control-api-typed-report-v1",
            status: ControlApiReportStatus::Pass,
            runtime_overview_available: true,
            reload_core_state_available: true,
            domain_routing_owner_available: true,
            runtime_dependency_plan_available: true,
            stage_report_schema: false,
        }
    }
}

pub use domain_routing::{
    DomainRoutingOwnerSnapshot, DomainRoutingTracker, DomainRoutingView, IpRoutingView,
};
pub use reload::{CoreFlip, ReloadCoreState};
pub use runtime_deps::{EnvironmentGate, RuntimeDependencyPlan};
