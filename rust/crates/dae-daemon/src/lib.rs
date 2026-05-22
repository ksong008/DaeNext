pub mod control_plane;
pub mod identity;
pub mod lifecycle;
pub mod preflight;
pub mod runner;
pub mod version;

#[cfg(test)]
mod tests;

pub use control_plane::{
    ControlPlaneOwnerPaths, default_stage151_root, run_stage151_control_plane_owner_preflight,
    stage151_control_plane_owner_preflight_report,
};
pub use identity::{
    DAEMON_CRATE_NAME, DEFAULT_DAEMON_MANIFEST, GO_DEFAULT_IDENTITY, OPTIN_BINARY_NAME,
    daemon_identity,
};
pub use lifecycle::{
    LifecyclePaths, default_stage150_root, run_stage150_lifecycle_smoke,
    stage150_lifecycle_smoke_report,
};
pub use preflight::stage149_identity_preflight_report;
pub use runner::{DaemonOutput, run_with_args_and_version};
pub use version::version_from_env;
