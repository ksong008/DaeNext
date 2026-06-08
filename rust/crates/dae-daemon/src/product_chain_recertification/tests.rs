use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

mod baseline;
mod control_plane_owner;
mod datapath_core;
mod default_switch;
mod dependency_boundary;
mod go_free_product_chain;
mod local_validation;
mod native_owned_entry_gates;
mod outbound_fingerprint_underlay;
mod outbound_production_matrix;
mod readiness_host_write;
mod release_default_switch;
mod repo_status;
mod resident_runtime_platform;
mod run_command_replacement;
mod runtime_control_contract;

mod fixtures;
use self::fixtures::*;
