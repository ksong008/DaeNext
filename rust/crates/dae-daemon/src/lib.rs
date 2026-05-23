pub mod control_plane;
pub mod control_plane_entrypoint;
pub mod default_run;
pub mod default_run_identity;
pub mod identity;
pub mod lifecycle;
pub mod listener_ebpf_preflight;
pub mod matched_default_benchmark;
pub mod preflight;
pub mod product_chain_recertification;
pub mod production_dataplane_harness;
pub mod production_runtime_owner;
pub mod reload_owner_benchmark;
pub mod reload_owner_handoff;
pub mod run_entrypoint;
pub mod runner;
pub mod signal;
pub mod version;

#[cfg(test)]
mod matched_default_benchmark_tests;
#[cfg(test)]
mod tests;

pub use control_plane::{
    ControlPlaneOwnerPaths, default_stage151_root, run_stage151_control_plane_owner_preflight,
    stage151_control_plane_owner_preflight_report,
};
pub use control_plane_entrypoint::{
    default_stage157_root, stage157_control_plane_entrypoint_admission_report,
};
pub use default_run::{RunOptions, default_run_root, run_default_optin_report};
pub use default_run_identity::{
    Stage156DefaultRunIdentityOptions, default_stage156_root,
    stage156_default_run_identity_admission_report,
};
pub use identity::{
    DAEMON_CRATE_NAME, DEFAULT_DAEMON_MANIFEST, GO_DEFAULT_IDENTITY, OPTIN_BINARY_NAME,
    daemon_identity,
};
pub use lifecycle::{
    LifecyclePaths, default_stage150_root, run_stage150_lifecycle_smoke,
    stage150_lifecycle_smoke_report,
};
pub use listener_ebpf_preflight::{
    default_stage160_root, stage160_listener_ebpf_preflight_harness_report,
};
pub use matched_default_benchmark::{
    MatchedDefaultBenchmarkOptions, matched_default_benchmark_report,
};
pub use preflight::stage149_identity_preflight_report;
pub use product_chain_recertification::{
    ProductChainAdmissionEvidence, ProductChainRecertificationOptions,
    product_chain_recertification_report,
};
pub use production_dataplane_harness::{
    ProductionDataplaneHarnessOptions, production_dataplane_harness_report,
};
pub use production_runtime_owner::{
    ProductionRuntimeOwnerOptions, production_runtime_owner_report,
};
pub use reload_owner_benchmark::{default_stage167_root, stage167_reload_owner_benchmark_report};
pub use reload_owner_handoff::{
    ReloadOwnerHandoffPaths, default_stage165_root, stage165_reload_owner_handoff_smoke_report,
};
pub use run_entrypoint::{default_stage153_root, stage153_run_entrypoint_preflight_report};
pub use runner::{DaemonOutput, run_with_args_and_version};
pub use signal::{default_stage152_root, stage152_signal_control_plane_smoke_report};
pub use version::version_from_env;
