use dae_routing::SharedDomainSet;
use serde_json::Value;

use super::super::geodata::{GeodataResolutionReport, SharedResidentIpPrefixSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentRoutingPlan {
    pub(crate) matches: Vec<MatchSetBytes>,
    pub(crate) lpm_sets: Vec<SharedResidentIpPrefixSet>,
    pub(crate) domain_sets: Vec<ResidentDomainSet>,
    pub(crate) geodata_report: GeodataResolutionReport,
    pub(crate) skipped_rules: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MatchSetBytes {
    pub(crate) bytes: [u8; 24],
    pub(crate) kind: &'static str,
    pub(crate) outbound: u8,
    pub(crate) mark: u32,
    pub(crate) must: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundSpec {
    pub(crate) id: u8,
    pub(crate) mark: u32,
    pub(crate) must: bool,
    pub(crate) name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentDomainSet {
    pub(crate) rule_index: usize,
    pub(crate) values: SharedDomainSet,
}
