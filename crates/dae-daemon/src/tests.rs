use serde_json::Value;

use crate::{
    ProductRunIdentityAdmissionOptions, RunOptions, control_plane_entrypoint_admission_report,
    control_plane_owner_preflight_report, daemon_identity, identity_preflight_report,
    lifecycle_smoke_report, listener_ebpf_preflight_report, product_run_identity_admission_report,
    run_entrypoint_preflight_report, run_product_run_report, run_with_args_and_version,
    signal_control_plane_smoke_report,
};

mod bounded_run;
mod contract_scans;
mod identity_runner;
mod lifecycle_control;
mod listener_preflight;
mod run_command_basic;
