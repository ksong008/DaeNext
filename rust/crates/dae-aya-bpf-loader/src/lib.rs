use std::io::{self, BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use serde_json::{Value, json};

#[cfg(feature = "native-ebpf")]
const EMBEDDED_NATIVE_AYA_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dae-native-bpf_bpfel.o"));

include!("lib/options.rs");
include!("lib/command_router.rs");
include!("lib/contracts.rs");
include!("lib/attach_commands.rs");
include!("lib/misc_commands.rs");
include!("lib/trace_contract.rs");
include!("lib/connectivity_map.rs");
include!("lib/routing_maps.rs");
include!("lib/trace_loader.rs");
include!("lib/load_pin.rs");
include!("lib/parsers.rs");
include!("lib/fd_handoff.rs");
include!("lib/tests.rs");
