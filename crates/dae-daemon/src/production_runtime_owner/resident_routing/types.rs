use std::net::IpAddr;
use std::sync::Arc;

use dae_routing::SharedDomainSet;
use serde_json::Value;

use super::geodata::GeodataResolutionReport;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentRoutingPlan {
    pub(super) matches: Vec<MatchSetBytes>,
    pub(super) lpm_sets: Vec<SharedResidentIpPrefixSet>,
    pub(super) domain_sets: Vec<ResidentDomainSet>,
    pub(super) geodata_report: GeodataResolutionReport,
    pub(super) skipped_rules: Vec<Value>,
}

pub(super) type SharedResidentIpPrefixSet = Arc<[IpPrefix]>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MatchSetBytes {
    pub(super) bytes: [u8; 24],
    pub(super) kind: &'static str,
    pub(super) outbound: u8,
    pub(super) mark: u32,
    pub(super) must: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OutboundSpec {
    pub(super) id: u8,
    pub(super) mark: u32,
    pub(super) must: bool,
    pub(super) name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IpPrefix {
    pub(super) addr: IpAddr,
    pub(super) bits: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentDomainSet {
    pub(super) rule_index: usize,
    pub(super) values: SharedDomainSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OutboundConnectivityEntry {
    pub(super) outbound: u8,
    pub(super) l4proto: u8,
    pub(super) ipversion: u8,
}
