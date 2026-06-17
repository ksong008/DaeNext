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
    ResidentProductionRuntime, configured_lan_ifaces, configured_wan_ifaces,
    start_resident_production_runtime, validate_resident_runtime_interfaces,
};

mod types;
pub use self::types::*;
mod base_capabilities;
pub use self::base_capabilities::*;
mod datapath_capabilities;
use self::datapath_capabilities::*;
mod outbound_fingerprint;
use self::outbound_fingerprint::*;
mod outbound_matrix;
use self::outbound_matrix::*;
mod source_shapes;
use self::source_shapes::*;
mod resident_live_adapter;
use self::resident_live_adapter::*;
mod resident_service;
pub use self::resident_service::*;
#[cfg(test)]
mod tests;
