pub mod identity;
pub mod preflight;
pub mod runner;
pub mod version;

#[cfg(test)]
mod tests;

pub use identity::{
    DAEMON_CRATE_NAME, DEFAULT_DAEMON_MANIFEST, GO_DEFAULT_IDENTITY, OPTIN_BINARY_NAME,
    daemon_identity,
};
pub use preflight::stage149_identity_preflight_report;
pub use runner::{DaemonOutput, run_with_args_and_version};
pub use version::version_from_env;
