use serde_json::Value;

use crate::*;
use dae_core_types::OutboundIndex;
use dae_ebpf_support::{BpfMatchSet, ConnectivityEvent, ConnectivityKey, RoutingMapEntry};
use dae_routing::IpPrefix;

include!("tests/domain_routing.rs");
include!("tests/reload_control.rs");
include!("tests/outbound_connectivity.rs");
include!("tests/routing_owner.rs");
include!("tests/helpers.rs");
