pub mod bpf_loader;
pub mod config_validate;
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
pub mod rust_native_control_plane;
pub mod service_contract;
pub mod signal;
pub mod version;

#[cfg(test)]
mod matched_default_benchmark_tests;
#[cfg(test)]
mod tests;

pub use control_plane::{
    ControlPlaneOwnerPaths, control_plane_owner_preflight_report,
    default_control_plane_owner_preflight_root, run_control_plane_owner_preflight,
};
pub use control_plane_entrypoint::{
    control_plane_entrypoint_admission_report, default_control_plane_entrypoint_admission_root,
};
pub use default_run::{
    RunOptions, default_run_root, product_chain_admission_from_run_report, run_default_optin_report,
};
pub use default_run_identity::{
    DefaultRunIdentityAdmissionOptions, default_run_identity_admission_report,
    default_run_identity_admission_root,
};
pub use identity::{
    DAEMON_CRATE_NAME, DEFAULT_DAEMON_MANIFEST, GO_DEFAULT_IDENTITY, OPTIN_BINARY_NAME,
    daemon_identity,
};
pub use lifecycle::{
    LifecyclePaths, default_lifecycle_smoke_root, lifecycle_smoke_report, run_lifecycle_smoke,
};
pub use listener_ebpf_preflight::{
    default_listener_ebpf_preflight_root, listener_ebpf_preflight_report,
};
pub use matched_default_benchmark::{
    MatchedDefaultBenchmarkOptions, matched_default_benchmark_report,
};
pub use preflight::identity_preflight_report;
pub use product_chain_recertification::{
    ProductChainAdmissionEvidence, ProductChainRecertificationOptions,
    product_chain_recertification_report,
};
pub use production_dataplane_harness::{
    ProductionDataplaneHarnessOptions, production_dataplane_harness_report,
};
pub use production_runtime_owner::{
    ProductionRuntimeOwnerOptions, daemon_runtime_native_owner_summary_json,
    datapath_outbound_ebpf_deep_area_summary_json, production_runtime_owner_report,
};
pub use reload_owner_benchmark::{
    default_reload_owner_benchmark_root, reload_owner_benchmark_report,
};
pub use reload_owner_handoff::{
    ReloadOwnerHandoffPaths, default_reload_owner_handoff_root, reload_owner_handoff_smoke_report,
};
pub use run_entrypoint::{default_run_entrypoint_preflight_root, run_entrypoint_preflight_report};
pub use runner::{DaemonOutput, run_with_args_and_version};
pub use rust_native_control_plane::{
    default_rust_native_control_plane_admission_root, rust_native_control_plane_admission_report,
};
pub use service_contract::{
    ABORT_FILE_PATH, PID_FILE_PATH, PROGRESS_FILE_PATH, ReloadOptions, ResidentRunOptions,
    reload_resident_service, run_resident_service, service_contract_capabilities,
};
pub use signal::{default_signal_control_plane_smoke_root, signal_control_plane_smoke_report};
pub use version::version_from_env;
