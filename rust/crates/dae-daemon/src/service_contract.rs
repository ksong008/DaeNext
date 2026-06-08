use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use dae_config::Config;
use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR, RELOAD_PROCESSING, RELOAD_SEND};
use serde_json::{Value, json};

use crate::config_validate::load_config_file;
use crate::production_runtime_owner::{
    ResidentProductionRuntime, start_resident_production_runtime,
};

include!("service_contract/types.rs");
include!("service_contract/base_capabilities.rs");
include!("service_contract/datapath_capabilities.rs");
include!("service_contract/outbound_fingerprint.rs");
include!("service_contract/outbound_matrix.rs");
include!("service_contract/source_shapes.rs");
include!("service_contract/resident_live_adapter.rs");
include!("service_contract/release_product.rs");
include!("service_contract/resident_service.rs");
include!("service_contract/tests.rs");
