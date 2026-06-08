use serde_json::{Value, json};

use crate::{
    DefaultRunIdentityAdmissionOptions, RunOptions, control_plane_entrypoint_admission_report,
    control_plane_owner_preflight_report, daemon_identity, default_run_identity_admission_report,
    identity_preflight_report, lifecycle_smoke_report, listener_ebpf_preflight_report,
    run_default_optin_report, run_entrypoint_preflight_report, run_with_args_and_version,
    rust_native_control_plane_admission_report, signal_control_plane_smoke_report,
};

include!("tests/contract_scans.rs");
include!("tests/identity_runner.rs");
include!("tests/run_command_basic.rs");
include!("tests/bounded_run.rs");
include!("tests/product_chain_runner.rs");
include!("tests/lifecycle_control.rs");
include!("tests/listener_preflight.rs");
