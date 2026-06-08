use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSurface {
    PublicApi,
    Core,
    Protocol,
    Dataplane,
    Transport,
    TestSupport,
    Admission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundDependencyBoundary {
    CoreRuntime,
    FormalTransport,
    TestSupport,
    BenchmarkOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSplitDecision {
    KeepInCrate,
    ExtractLater,
    MoveToTestSupport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOwnerSurface {
    ProductDaemon,
    FormalTransport,
    Dataplane,
    LoopbackTestSupport,
    AdmissionHelper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOwnership {
    OwnedByDaemonRuntime,
    InjectedByCaller,
    MayCreateLocalRuntime,
    DependencyOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundModuleContract {
    pub module: &'static str,
    pub surface: OutboundSurface,
    pub split_decision: OutboundSplitDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundDependencyContract {
    pub crate_name: &'static str,
    pub boundary: OutboundDependencyBoundary,
    pub default_runtime_required: bool,
    pub feature_candidate: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeOwnershipContract {
    pub path: &'static str,
    pub surface: RuntimeOwnerSurface,
    pub ownership: RuntimeOwnership,
    pub default_product_path: bool,
    pub local_runtime_allowed: bool,
}

pub fn public_api_contract() -> &'static [OutboundModuleContract] {
    &PUBLIC_API_CONTRACT
}

pub fn module_boundary_contract() -> &'static [OutboundModuleContract] {
    &MODULE_BOUNDARY_CONTRACT
}

pub fn dependency_boundary_contract() -> &'static [OutboundDependencyContract] {
    &DEPENDENCY_BOUNDARY_CONTRACT
}

pub fn crate_split_decision() -> OutboundSplitDecision {
    OutboundSplitDecision::KeepInCrate
}

pub fn runtime_ownership_contract() -> &'static [RuntimeOwnershipContract] {
    &RUNTIME_OWNERSHIP_CONTRACT
}
