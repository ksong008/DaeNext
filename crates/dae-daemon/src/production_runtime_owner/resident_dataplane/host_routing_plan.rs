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
    DomainKey, IpPrefix, RoutingMatchKind, RoutingMatchSet, RoutingSharedDomainSet,
    RoutingSharedLpmSet, SharedIpPrefixSet,
};
use serde_json::{Value, json};

use super::geodata::{
    GeodataResolutionReport, GeodataResolver, load_geoip_params, load_geosite_params,
};

const MATCH_TYPE_DOMAIN_SET: u8 = 0;
const MATCH_TYPE_IP_SET: u8 = 1;
const MATCH_TYPE_SOURCE_IP_SET: u8 = 2;
const MATCH_TYPE_PORT: u8 = 3;
const MATCH_TYPE_SOURCE_PORT: u8 = 4;
const MATCH_TYPE_L4_PROTO: u8 = 5;
const MATCH_TYPE_IP_VERSION: u8 = 6;
const MATCH_TYPE_MAC: u8 = 7;
const MATCH_TYPE_PROCESS_NAME: u8 = 8;
const MATCH_TYPE_DSCP: u8 = 9;
const MATCH_TYPE_FALLBACK: u8 = 10;
const L4_TCP: u8 = 1;
const L4_UDP: u8 = 2;
const IP_VERSION_4: u8 = 1;
const IP_VERSION_6: u8 = 2;

mod build;
pub(crate) use self::build::*;
mod optimize;
use self::optimize::*;
mod typed_matcher;
pub(crate) use self::typed_matcher::*;
mod compile;
use self::compile::*;
mod outbound;
use self::outbound::*;
mod function_helpers;
use self::function_helpers::*;
mod parsers;
use self::parsers::*;
mod types;
use self::types::OutboundSpec;
pub(crate) use self::types::{MatchSetBytes, ResidentDomainSet, ResidentRoutingPlan};

#[allow(dead_code)]
pub(crate) fn build_resident_userspace_routing_matcher(
    config: &Config,
) -> Result<dae_routing::RoutingMatcher, String> {
    let geodata = GeodataResolver::new(Vec::<PathBuf>::new());
    build_resident_userspace_routing_matcher_with_geodata(config, &geodata)
}

pub(crate) fn build_resident_userspace_routing_matcher_with_geodata(
    config: &Config,
    geodata: &GeodataResolver,
) -> Result<dae_routing::RoutingMatcher, String> {
    let plan = build_routing_plan_with_geodata_resolver(config, geodata)?;
    let (domain_sets, lpm_sets, matches) = userspace_matcher_typed_sets(&plan)?;
    dae_routing::RoutingMatcher::from_shared_typed_sets(domain_sets, lpm_sets, matches)
        .map_err(|error| format!("build resident userspace routing matcher: {error}"))
}
