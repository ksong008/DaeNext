use crate::bpf_loader::run_bpf_loader_command;
use crate::config_validate::validate_config_file;
use crate::identity::daemon_identity;
use crate::lifecycle::{default_lifecycle_smoke_root, lifecycle_smoke_report};
use crate::preflight::identity_preflight_report;
use crate::production_runtime_owner::{NetnsLinkMode, parse_netns_link_mode};
use crate::{
    ProductRunIdentityAdmissionOptions, product_run_identity_admission_report,
    product_run_identity_admission_root,
};
use crate::{
    ReloadOptions, ResidentRunOptions, reload_resident_service, run_resident_service,
    service_contract_capabilities,
};
use crate::{RunOptions, product_run_root, run_product_run_report};
use crate::{
    control_plane_entrypoint_admission_report, default_control_plane_entrypoint_admission_root,
};
use crate::{control_plane_owner_preflight_report, default_control_plane_owner_preflight_root};
use crate::{default_listener_ebpf_preflight_root, listener_ebpf_preflight_report};
use crate::{default_reload_owner_benchmark_root, reload_owner_benchmark_report};
use crate::{default_reload_owner_handoff_root, reload_owner_handoff_smoke_report};
use crate::{default_signal_control_plane_smoke_root, signal_control_plane_smoke_report};
use crate::{product_run_entrypoint_preflight_root, run_entrypoint_preflight_report};
use dae_ebpf_support::AttachBackend;
use std::path::PathBuf;
use std::time::Duration;

mod output;
pub use self::output::*;
mod command_router;
pub use self::command_router::*;
mod basic_commands;
use self::basic_commands::*;
mod product_run;
use self::product_run::*;
mod aux_commands;
use self::aux_commands::*;
