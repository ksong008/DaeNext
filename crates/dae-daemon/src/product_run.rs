use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use dae_core_types::reload::RELOAD_DONE;
use serde_json::{Value, json};

use crate::{
    ProductionDataplaneHarnessOptions, ProductionRuntimeOwnerOptions,
    config_validate::load_config_file,
    listener_ebpf_preflight_report, production_dataplane_harness_report,
    production_runtime_owner_report, reload_owner_handoff_smoke_report,
    service_contract::{RESIDENT_DATAPLANE_ENV, resident_dataplane_admission_ready_from_env},
};

mod options;
pub use self::options::*;
mod run_report;
pub use self::run_report::*;
mod safety_paths;
use self::safety_paths::*;
mod live_matrix;
use self::live_matrix::*;
#[cfg(test)]
mod tests;
