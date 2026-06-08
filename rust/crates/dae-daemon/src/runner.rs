use crate::bpf_loader::run_bpf_loader_command;
use crate::config_validate::validate_config_file;
use crate::identity::daemon_identity;
use crate::lifecycle::{default_lifecycle_smoke_root, lifecycle_smoke_report};
use crate::preflight::identity_preflight_report;
use crate::production_runtime_owner::{NetnsLinkMode, parse_netns_link_mode};
use crate::{
    DefaultRunIdentityAdmissionOptions, default_run_identity_admission_report,
    default_run_identity_admission_root,
};
use crate::{
    ReloadOptions, ResidentRunOptions, reload_resident_service, run_resident_service,
    service_contract_capabilities,
};
use crate::{
    RunOptions, default_run_root, product_chain_admission_from_run_report, run_default_optin_report,
};
use crate::{
    control_plane_entrypoint_admission_report, default_control_plane_entrypoint_admission_root,
};
use crate::{control_plane_owner_preflight_report, default_control_plane_owner_preflight_root};
use crate::{default_listener_ebpf_preflight_root, listener_ebpf_preflight_report};
use crate::{default_reload_owner_benchmark_root, reload_owner_benchmark_report};
use crate::{default_reload_owner_handoff_root, reload_owner_handoff_smoke_report};
use crate::{default_run_entrypoint_preflight_root, run_entrypoint_preflight_report};
use crate::{
    default_rust_native_control_plane_admission_root, rust_native_control_plane_admission_report,
};
use crate::{default_signal_control_plane_smoke_root, signal_control_plane_smoke_report};
use dae_ebpf_support::AttachBackend;
use std::path::PathBuf;
use std::time::Duration;

mod output;
pub use self::output::*;
mod command_router;
pub use self::command_router::*;
mod basic_commands;
use self::basic_commands::*;
mod default_optin;
use self::default_optin::*;
mod aux_commands;
use self::aux_commands::*;
