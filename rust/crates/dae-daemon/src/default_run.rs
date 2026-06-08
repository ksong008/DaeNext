use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use dae_core_types::reload::RELOAD_DONE;
use serde_json::{Value, json};

use crate::{
    MatchedDefaultBenchmarkOptions, ProductChainAdmissionEvidence,
    ProductChainRecertificationOptions, ProductionDataplaneHarnessOptions,
    ProductionRuntimeOwnerOptions, listener_ebpf_preflight_report,
    matched_default_benchmark_report, product_chain_recertification_report,
    production_dataplane_harness_report, production_runtime_owner_report,
    reload_owner_handoff_smoke_report,
    service_contract::{RESIDENT_DATAPLANE_ENV, resident_dataplane_default_switch_ready_from_env},
};

mod options;
pub use self::options::*;
mod run_report;
pub use self::run_report::*;
mod safety_paths;
use self::safety_paths::*;
mod live_matrix;
use self::live_matrix::*;
mod admission;
pub use self::admission::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
