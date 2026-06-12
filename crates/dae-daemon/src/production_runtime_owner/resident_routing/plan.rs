use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
};

use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_core_types::OutboundIndex;
use dae_ebpf_support::MAX_MATCH_SET_LEN;
use dae_routing::{
    DomainKey, IpPrefix as RoutingIpPrefix, RoutingMatchKind, RoutingMatchSet,
    RoutingSharedDomainSet, RoutingSharedLpmSet, SharedIpPrefixSet,
};
use serde_json::{Value, json};

use super::geodata::{
    GeodataResolutionReport, GeodataResolver, load_geoip_params, load_geosite_params,
};
use super::types::{IpPrefix, MatchSetBytes, OutboundSpec, ResidentDomainSet, ResidentRoutingPlan};
use super::{
    IP_VERSION_4, IP_VERSION_6, L4_TCP, L4_UDP, MATCH_TYPE_DOMAIN_SET, MATCH_TYPE_DSCP,
    MATCH_TYPE_FALLBACK, MATCH_TYPE_IP_SET, MATCH_TYPE_IP_VERSION, MATCH_TYPE_L4_PROTO,
    MATCH_TYPE_MAC, MATCH_TYPE_PORT, MATCH_TYPE_PROCESS_NAME, MATCH_TYPE_SOURCE_IP_SET,
    MATCH_TYPE_SOURCE_PORT,
};

mod build;
pub(super) use self::build::*;
mod optimize;
use self::optimize::*;
mod typed_matcher;
pub(super) use self::typed_matcher::*;
mod compile;
use self::compile::*;
mod outbound;
use self::outbound::*;
mod function_helpers;
use self::function_helpers::*;
mod parsers;
use self::parsers::*;
