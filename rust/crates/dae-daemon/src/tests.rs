use serde_json::{Value, json};

use crate::{
    DefaultRunIdentityAdmissionOptions, RunOptions, control_plane_entrypoint_admission_report,
    control_plane_owner_preflight_report, daemon_identity, default_run_identity_admission_report,
    identity_preflight_report, lifecycle_smoke_report, listener_ebpf_preflight_report,
    run_default_optin_report, run_entrypoint_preflight_report, run_with_args_and_version,
    rust_native_control_plane_admission_report, signal_control_plane_smoke_report,
};

mod contract_scans;
use self::contract_scans::*;
mod identity_runner;
use self::identity_runner::*;
mod run_command_basic;
use self::run_command_basic::*;
mod bounded_run;
use self::bounded_run::*;
mod product_chain_runner;
use self::product_chain_runner::*;
mod lifecycle_control;
use self::lifecycle_control::*;
mod listener_preflight;
use self::listener_preflight::*;
