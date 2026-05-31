#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeStateReport {
    pub schema_version: u32,
    pub rust_owned_runtime: bool,
    pub reload_state_available: bool,
    pub backend_state_available: bool,
    pub routing_owner_available: bool,
    pub domain_owner_available: bool,
    pub connectivity_owner_available: bool,
    pub active_handoff_available: bool,
    pub api_compatible: bool,
}

impl RuntimeStateReport {
    pub const SCHEMA_VERSION: u32 = 1;

    pub const fn new() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            rust_owned_runtime: false,
            reload_state_available: false,
            backend_state_available: false,
            routing_owner_available: false,
            domain_owner_available: false,
            connectivity_owner_available: false,
            active_handoff_available: false,
            api_compatible: true,
        }
    }

    pub const fn rust_owned_control_plane() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            rust_owned_runtime: true,
            reload_state_available: true,
            backend_state_available: true,
            routing_owner_available: true,
            domain_owner_available: true,
            connectivity_owner_available: true,
            active_handoff_available: true,
            api_compatible: true,
        }
    }

    pub fn ready_for_default_control_plane(self) -> bool {
        self.rust_owned_runtime
            && self.reload_state_available
            && self.backend_state_available
            && self.routing_owner_available
            && self.domain_owner_available
            && self.connectivity_owner_available
            && self.active_handoff_available
            && self.api_compatible
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneDefaultAdmission {
    pub runtime: RuntimeStateReport,
    pub benchmark_passed: bool,
    pub unit_passed: bool,
    pub integration_passed: bool,
    pub reload_passed: bool,
    pub host_write_passed: bool,
    pub cleanup_passed: bool,
    pub rollback_passed: bool,
    pub c_tproxy_oracle_retained: bool,
}

impl ControlPlaneDefaultAdmission {
    pub fn admitted(self) -> bool {
        self.runtime.ready_for_default_control_plane()
            && self.benchmark_passed
            && self.unit_passed
            && self.integration_passed
            && self.reload_passed
            && self.host_write_passed
            && self.cleanup_passed
            && self.rollback_passed
            && self.c_tproxy_oracle_retained
    }
}
