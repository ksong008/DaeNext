use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{fs, io};

use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR};
use serde_json::{Value, json};

#[path = "service_contract/candidate_capabilities.rs"]
mod candidate_capabilities;
use self::candidate_capabilities::*;
#[path = "service_contract/go_free_evidence.rs"]
mod go_free_evidence;
use self::go_free_evidence::*;
#[path = "service_contract/resident_service.rs"]
mod resident_service;
use self::resident_service::*;
