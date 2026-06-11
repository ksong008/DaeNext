use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{fs, io};

use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR};
use serde_json::{Value, json};

#[path = "service_contract/production_capabilities.rs"]
mod production_capabilities;
use self::production_capabilities::*;
#[path = "service_contract/resident_service.rs"]
mod resident_service;
#[path = "service_contract/runtime_state_evidence.rs"]
mod runtime_state_evidence;
