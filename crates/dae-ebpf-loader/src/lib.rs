use std::io::{self, BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use serde_json::{Value, json};

#[cfg(feature = "native-ebpf")]
#[repr(C, align(8))]
struct AlignedNativeAyaObject<const N: usize>([u8; N]);

#[cfg(feature = "native-ebpf")]
static EMBEDDED_NATIVE_AYA_OBJECT: AlignedNativeAyaObject<
    { include_bytes!(concat!(env!("OUT_DIR"), "/dae-native-bpf_bpfel.o")).len() },
> = AlignedNativeAyaObject(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/dae-native-bpf_bpfel.o"
)));

#[cfg(feature = "native-ebpf")]
pub fn embedded_native_aya_object() -> &'static [u8] {
    &EMBEDDED_NATIVE_AYA_OBJECT.0
}

#[path = "lib/options.rs"]
mod options;
pub use self::options::*;
#[path = "lib/command_router.rs"]
mod command_router;
pub use self::command_router::*;
#[path = "lib/contracts.rs"]
mod contracts;
use self::contracts::*;
#[path = "lib/attach_commands.rs"]
mod attach_commands;
use self::attach_commands::*;
#[path = "lib/misc_commands.rs"]
mod misc_commands;
use self::misc_commands::*;
#[path = "lib/trace_contract.rs"]
mod trace_contract;
use self::trace_contract::*;
#[path = "lib/connectivity_map.rs"]
mod connectivity_map;
pub use self::connectivity_map::*;
#[path = "lib/routing_maps.rs"]
mod routing_maps;
pub use self::routing_maps::*;
#[path = "lib/trace_loader.rs"]
mod trace_loader;
use self::trace_loader::*;
#[path = "lib/load_pin.rs"]
mod load_pin;
use self::load_pin::*;
#[path = "lib/parsers.rs"]
mod parsers;
use self::parsers::*;
#[path = "lib/fd_handoff.rs"]
mod fd_handoff;
use self::fd_handoff::*;
#[path = "lib/tests.rs"]
#[cfg(test)]
mod tests;
