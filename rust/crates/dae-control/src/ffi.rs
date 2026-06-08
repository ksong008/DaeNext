use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use dae_ebpf_support::{
    BpfDomainRouting, BpfLpmKey, BpfMatchSet, ConnectivityEvent, ConnectivityKey,
    DomainRoutingMapEntry, LpmMapBuildSpec, LpmMapEntry, RoutingMapEntry,
    apply_domain_routing_map_by_id, apply_routing_maps_with_lpm_build_by_id,
};

use crate::{
    DomainRoutingDnsEvent, DomainRoutingIpKey, DomainRoutingOwner, DomainRoutingOwnerSnapshot,
    OutboundConnectivityMapOwner, ReloadDnsCachePlan, RoutingMapOwner, RoutingNativeBuildPlan,
    RuntimeStateReport,
};

mod types;
pub use self::types::*;
mod error;
pub use self::error::*;
mod runtime_state;
use self::runtime_state::*;
mod routing_maps;
use self::routing_maps::*;
mod owner_lifecycle;
use self::owner_lifecycle::*;
mod domain_routing;
use self::domain_routing::*;
mod connectivity;
use self::connectivity::*;
mod raw_inputs;
use self::raw_inputs::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
