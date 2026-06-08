use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

mod control_plane_owner;
mod daed2_rehearsal;
mod datapath_core;
mod dependency_boundary;
mod go_free_product_chain;
mod host_write_freeze;
mod host_write_safety;
mod local_validation;
mod native_owned_entry_gates;
mod outbound_fingerprint_underlay;
mod outbound_production_matrix;
mod product_layout;
mod readiness;
mod release_default_switch;
mod repo_inspection;
mod resident_runtime_platform;
mod rollback_model;
mod run_command_replacement;
mod runtime_control_contract;
mod service_contract;
mod support;
mod topology;
mod typed_report;

use control_plane_owner::control_plane_owner_gate_json;
use daed2_rehearsal::{
    attach_daed2_product_chain_switch_rehearsal,
    materialize_daed2_product_chain_switch_rehearsal_report,
};
use datapath_core::datapath_core_gate_json;
use dependency_boundary::go_mod_dependency_boundary_json;
use go_free_product_chain::{
    attach_go_free_product_chain_gate_from_report, default_product_package_scan_json,
    go_free_product_chain_gate_json,
};
use host_write_freeze::{
    attach_production_host_write_plan_freeze, materialize_production_host_write_plan_freeze_report,
};
use host_write_safety::{
    production_run_command_apply_plan_blockers, production_run_command_execution_blockers,
};
use local_validation::{
    attach_local_validation_fresh_install_plan, materialize_local_validation_fresh_install_plan,
};
use native_owned_entry_gates::native_owned_entry_gates_json;
use outbound_fingerprint_underlay::outbound_fingerprint_underlay_gate_json;
use outbound_production_matrix::outbound_production_matrix_gate_json;
use readiness::{
    attach_production_replacement_readiness, materialize_production_replacement_readiness_report,
};
use release_default_switch::{
    attach_release_default_switch_gate_from_report, release_default_switch_gate_json,
};
use repo_inspection::{expected_product_chain_branch, repo_status_json};
use resident_runtime_platform::resident_runtime_platform_gate_json;
use run_command_replacement::{
    attach_production_run_command_replacement_artifacts,
    materialize_production_run_command_replacement_artifacts,
    production_run_command_replacement_plan_json,
};
use runtime_control_contract::runtime_control_api_source_contract_json;
use service_contract::{candidate_service_contract_report, service_contract_json};
use support::{ensure_safe_run_root, path_string};
use topology::product_chain_topology;
#[cfg(test)]
use topology::{ProductChainTopology, ProductChainTopologyKind};
use typed_report::{
    ProductChainTypedReportSummary, remaining_blockers, runtime_control_api_clean_baseline_json,
    value_string_array,
};

#[path = "product_chain_recertification_root/options.rs"]
mod options;
pub use self::options::*;
#[path = "product_chain_recertification_root/report_entry.rs"]
mod report_entry;
pub use self::report_entry::*;
#[path = "product_chain_recertification_root/evidence.rs"]
mod evidence;
use self::evidence::*;
#[path = "product_chain_recertification_root/report_value.rs"]
mod report_value;
use self::report_value::*;
#[path = "product_chain_recertification_root/gate_helpers.rs"]
mod gate_helpers;
use self::gate_helpers::*;

#[cfg(test)]
mod tests;
