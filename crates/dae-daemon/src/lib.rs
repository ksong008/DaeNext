pub mod allocator;
pub mod bpf_loader;
pub mod config_validate;
pub mod control_plane;
pub mod control_plane_entrypoint;
pub mod daed_product;
mod final_native_evidence;
pub mod identity;
pub mod lifecycle;
pub mod listener_ebpf_preflight;
pub mod preflight;
pub mod product_run;
pub mod product_run_identity;
pub mod production_dataplane_harness;
pub mod production_runtime_owner;
pub mod reload_owner_benchmark;
pub mod reload_owner_handoff;
pub mod run_entrypoint;
pub mod runner;
pub mod service_contract;
pub mod signal;
pub mod version;

#[cfg(test)]
mod tests;

pub use control_plane::{
    ControlPlaneOwnerPaths, control_plane_owner_preflight_report,
    default_control_plane_owner_preflight_root, run_control_plane_owner_preflight,
};
pub use control_plane_entrypoint::{
    control_plane_entrypoint_admission_report, default_control_plane_entrypoint_admission_root,
};
pub use daed_product::{DaedProductOutput, run_daed_product_with_args_and_version};
pub use identity::{DAEMON_CRATE_NAME, DAEMON_MANIFEST, PRODUCT_BINARY_NAME, daemon_identity};
pub use lifecycle::{
    LifecyclePaths, default_lifecycle_smoke_root, lifecycle_smoke_report, run_lifecycle_smoke,
};
pub use listener_ebpf_preflight::{
    default_listener_ebpf_preflight_root, listener_ebpf_preflight_report,
};
pub use preflight::identity_preflight_report;
pub use product_run::{RunOptions, product_run_root, run_product_run_report};
pub use product_run_identity::{
    ProductRunIdentityAdmissionOptions, product_run_identity_admission_report,
    product_run_identity_admission_root,
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
pub use run_entrypoint::{product_run_entrypoint_preflight_root, run_entrypoint_preflight_report};
pub use runner::{DaemonOutput, run_with_args_and_version};
pub use service_contract::{
    ABORT_FILE_PATH, PID_FILE_PATH, PROGRESS_FILE_PATH, ReloadOptions, ResidentRunOptions,
    reload_resident_service, run_resident_service, service_contract_capabilities,
};
pub use signal::{default_signal_control_plane_smoke_root, signal_control_plane_smoke_report};
pub use version::version_from_env;
