use super::*;
pub type DomainRoutingIpKey = [u32; 4];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingOwnerSnapshot {
    pub bitmap: [u32; 32],
    pub ips: Vec<DomainRoutingIpKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRoutingDnsEvent<'a> {
    pub owner_key: &'a str,
    pub bitmap: [u32; 32],
    pub ips: Vec<DomainRoutingIpKey>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct IpState {
    pub(super) owners: HashMap<String, [u32; 32]>,
    pub(super) merged: [u32; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingTracker {
    pub(super) owners: HashMap<String, DomainRoutingOwnerSnapshot>,
    pub(super) ips: HashMap<DomainRoutingIpKey, IpState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRoutingStateEntry {
    pub key: DomainRoutingIpKey,
    pub bitmap: [u32; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingSyncPlan {
    pub updates: Vec<DomainRoutingStateEntry>,
    pub deletes: Vec<DomainRoutingIpKey>,
    pub owner_count: usize,
    pub ip_count: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingOwner {
    pub(super) map_id: Option<u32>,
    pub(super) tracker: DomainRoutingTracker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRoutingOwnerUpdate {
    pub map_id: Option<u32>,
    pub plan: DomainRoutingSyncPlan,
    pub flush: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingOwnerApplyReport {
    pub map_id: u32,
    pub map_id_changed: bool,
    pub skipped: bool,
    pub entries_updated: usize,
    pub entries_deleted: usize,
    pub owner_count: usize,
    pub ip_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRoutingMapReplay {
    pub map_id: u32,
    pub changed: bool,
    pub entries: Vec<DomainRoutingStateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRoutingReloadClearPlan {
    pub map_id: u32,
    pub map_id_changed: bool,
    pub deletes: Vec<DomainRoutingIpKey>,
    pub owner_count: usize,
    pub ip_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRoutingView {
    pub step: String,
    pub owners: Vec<String>,
    pub ips: Vec<IpRoutingView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpRoutingView {
    pub ip: String,
    pub owners: Vec<String>,
    pub merged: Vec<u32>,
    pub present: bool,
}
