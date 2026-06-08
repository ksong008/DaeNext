use std::fs;
use std::hint::black_box;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use dae_control::domain_routing::DomainRoutingOwnerApplyReport;
use dae_control::{
    ControlPlaneDefaultAdmission, DomainRoutingDnsEvent, DomainRoutingOwner, LpmMapTemplate,
    ReloadDnsCachePlan, RoutingNativeFallback, RoutingNativeMatch, RoutingNativeRule,
    RoutingRuleOwner, RoutingRuleOwnerApplyReport, RoutingRuleState, RuntimeStateReport, ip_to_key,
};
use dae_core_types::OutboundIndex;
use dae_dns::{
    DnsCacheStore, build_response_cache_plan_from_packet,
    restore_cached_response_for_packet_question,
};
use dae_ebpf_support::{ConnectivityEvent, ConnectivityKey};
use dae_routing::IpPrefix;
use dae_routing::{Query, RoutingMatcher};
use serde_json::{Value, json};

mod model;
use self::model::*;
mod report;
pub use self::report::*;
mod flow;
use self::flow::*;
mod dns_domain;
use self::dns_domain::*;
mod routing_connectivity;
use self::routing_connectivity::*;
mod datapath_contract;
use self::datapath_contract::*;
mod benchmark;
use self::benchmark::*;
mod safety;
use self::safety::*;
