use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{fs, io};

use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR};
use serde_json::{Value, json};

include!("service_contract/candidate_capabilities.rs");
include!("service_contract/go_free_evidence.rs");
include!("service_contract/resident_service.rs");
