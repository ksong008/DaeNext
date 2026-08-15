use dae_routing::SharedDomainSet;
use serde_json::Value;

use super::super::geodata::{GeodataResolutionReport, SharedResidentIpPrefixSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentRoutingPlan {
    pub matches: Vec<MatchSetBytes>,
    pub lpm_sets: Vec<SharedResidentIpPrefixSet>,
    pub domain_sets: Vec<ResidentDomainSet>,
    pub geodata_report: GeodataResolutionReport,
    pub skipped_rules: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchSetBytes {
    pub bytes: [u8; 24],
    pub kind: &'static str,
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundSpec {
    pub(crate) id: u8,
    pub(crate) mark: u32,
    pub(crate) must: bool,
    pub(crate) name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentDomainSet {
    pub rule_index: usize,
    pub values: SharedDomainSet,
}
