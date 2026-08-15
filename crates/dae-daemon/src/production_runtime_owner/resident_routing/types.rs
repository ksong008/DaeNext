#[cfg(test)]
pub(super) use super::super::resident_dataplane::facade::ResidentDomainSet;
pub(super) use super::super::resident_dataplane::facade::{MatchSetBytes, ResidentRoutingPlan};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OutboundConnectivityEntry {
    pub(super) outbound: u8,
    pub(super) l4proto: u8,
    pub(super) ipversion: u8,
}
