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

include!("default_run/options.rs");
include!("default_run/run_report.rs");
include!("default_run/safety_paths.rs");
include!("default_run/live_matrix.rs");
include!("default_run/admission.rs");
include!("default_run/tests.rs");
