use std::mem::{align_of, offset_of, size_of};
use std::path::PathBuf;

use serde_json::Value;

use crate::*;

include!("tests/abi_maps.rs");
include!("tests/aya_smoke.rs");
include!("tests/tc_attach.rs");
include!("tests/connectivity_routing.rs");
include!("tests/param.rs");
include!("tests/helpers.rs");
