use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use super::path_string;

include!("service_contract/service_file.rs");
include!("service_contract/candidate_report.rs");
include!("service_contract/control_plane.rs");
include!("service_contract/datapath_core.rs");
include!("service_contract/extended_contracts.rs");
include!("service_contract/command.rs");
