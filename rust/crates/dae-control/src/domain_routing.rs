use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type DomainRoutingIpKey = [u32; 4];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingOwnerSnapshot {
    pub bitmap: [u32; 32],
    pub ips: Vec<DomainRoutingIpKey>,
}

impl DomainRoutingOwnerSnapshot {
    pub fn new(bitmap_words: &[u32], ips: &[&str]) -> Self {
        let mut bitmap = [0; 32];
        for (index, word) in bitmap_words.iter().copied().enumerate().take(32) {
            bitmap[index] = word;
        }
        Self {
            bitmap,
            ips: normalize_ip_keys(ips.iter().filter_map(|ip| parse_ip_key(ip))),
        }
    }

    pub fn from_keys(bitmap_words: &[u32], ips: &[DomainRoutingIpKey]) -> Self {
        let mut bitmap = [0; 32];
        for (index, word) in bitmap_words.iter().copied().enumerate().take(32) {
            bitmap[index] = word;
        }
        Self {
            bitmap,
            ips: normalize_ip_keys(ips.iter().copied()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() || self.bitmap.iter().all(|word| *word == 0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct IpState {
    owners: HashMap<String, [u32; 32]>,
    merged: [u32; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingTracker {
    owners: HashMap<String, DomainRoutingOwnerSnapshot>,
    ips: HashMap<DomainRoutingIpKey, IpState>,
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
    map_id: Option<u32>,
    tracker: DomainRoutingTracker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRoutingOwnerUpdate {
    pub map_id: Option<u32>,
    pub plan: DomainRoutingSyncPlan,
    pub flush: bool,
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

impl DomainRoutingTracker {
    pub fn sync_owner(&mut self, owner_key: &str, snapshot: DomainRoutingOwnerSnapshot) {
        let _ = self.apply_owner_update(owner_key, snapshot);
    }

    pub fn plan_owner_update(
        &self,
        owner_key: &str,
        snapshot: &DomainRoutingOwnerSnapshot,
    ) -> DomainRoutingSyncPlan {
        if owner_key.is_empty() {
            return DomainRoutingSyncPlan {
                owner_count: self.owners.len(),
                ip_count: self.ips.len(),
                ..DomainRoutingSyncPlan::default()
            };
        }

        let old_snapshot = self.owners.get(owner_key);
        let mut affected =
            Vec::with_capacity(old_snapshot.map_or(0, |old| old.ips.len()) + snapshot.ips.len());
        if let Some(old) = old_snapshot {
            affected.extend_from_slice(&old.ips);
        }
        affected.extend_from_slice(&snapshot.ips);
        affected.sort_unstable();
        affected.dedup();

        let mut updates = Vec::new();
        let mut deletes = Vec::new();
        for ip in affected {
            let (bitmap, present) = self.desired_bitmap_for_key(&ip, owner_key, snapshot);
            let current = self.ips.get(&ip);
            match (present, current) {
                (false, Some(_)) => deletes.push(ip),
                (true, None) => updates.push(DomainRoutingStateEntry { key: ip, bitmap }),
                (true, Some(state)) if state.merged != bitmap => {
                    updates.push(DomainRoutingStateEntry { key: ip, bitmap });
                }
                _ => {}
            }
        }

        DomainRoutingSyncPlan {
            updates,
            deletes,
            owner_count: self.owners.len(),
            ip_count: self.ips.len(),
        }
    }

    pub fn apply_owner_update(
        &mut self,
        owner_key: &str,
        snapshot: DomainRoutingOwnerSnapshot,
    ) -> DomainRoutingSyncPlan {
        self.apply_owner_update_ref(owner_key, &snapshot)
    }

    pub fn apply_owner_update_ref(
        &mut self,
        owner_key: &str,
        snapshot: &DomainRoutingOwnerSnapshot,
    ) -> DomainRoutingSyncPlan {
        let mut plan = self.plan_owner_update(owner_key, snapshot);
        if owner_key.is_empty() {
            return plan;
        }
        self.apply_owner_snapshot_ref(owner_key, snapshot);
        plan.owner_count = self.owners.len();
        plan.ip_count = self.ips.len();
        plan
    }

    pub fn entries(&self) -> Vec<DomainRoutingStateEntry> {
        let mut entries = self
            .ips
            .iter()
            .map(|(key, state)| DomainRoutingStateEntry {
                key: *key,
                bitmap: state.merged,
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.key);
        entries
    }

    pub fn owner_count(&self) -> usize {
        self.owners.len()
    }

    pub fn ip_count(&self) -> usize {
        self.ips.len()
    }

    fn desired_bitmap_for_key(
        &self,
        key: &DomainRoutingIpKey,
        owner_key: &str,
        snapshot: &DomainRoutingOwnerSnapshot,
    ) -> ([u32; 32], bool) {
        let mut bitmap = [0; 32];
        let mut present = false;
        if let Some(state) = self.ips.get(key) {
            for (existing_owner_key, existing_bitmap) in &state.owners {
                if existing_owner_key == owner_key {
                    continue;
                }
                or_bitmap(&mut bitmap, existing_bitmap);
                present = true;
            }
        }
        if !snapshot.is_empty() && snapshot.ips.contains(key) {
            or_bitmap(&mut bitmap, &snapshot.bitmap);
            present = true;
        }
        (bitmap, present)
    }

    fn apply_owner_snapshot_ref(&mut self, owner_key: &str, snapshot: &DomainRoutingOwnerSnapshot) {
        if let Some(old) = self.owners.remove(owner_key) {
            for ip in old.ips {
                let Some(state) = self.ips.get_mut(&ip) else {
                    continue;
                };
                state.owners.remove(owner_key);
                if state.owners.is_empty() {
                    self.ips.remove(&ip);
                } else {
                    state.merged = merge_owner_bitmaps(&state.owners);
                }
            }
        }

        if snapshot.is_empty() {
            return;
        }

        self.owners.insert(owner_key.to_owned(), snapshot.clone());
        for ip in &snapshot.ips {
            let ip = *ip;
            let state = self.ips.entry(ip).or_default();
            state.owners.insert(owner_key.to_owned(), snapshot.bitmap);
            state.merged = merge_owner_bitmaps(&state.owners);
        }
    }

    pub fn view(&self, step: impl Into<String>) -> DomainRoutingView {
        let mut owners = self.owners.keys().cloned().collect::<Vec<_>>();
        owners.sort();
        let mut ips = self
            .ips
            .iter()
            .map(|(key, state)| {
                let mut owners = state.owners.keys().cloned().collect::<Vec<_>>();
                owners.sort();
                IpRoutingView {
                    ip: format_ip_key(key),
                    owners,
                    merged: trimmed_bitmap(&state.merged),
                    present: true,
                }
            })
            .collect::<Vec<_>>();
        ips.sort_by(|left, right| left.ip.cmp(&right.ip));
        DomainRoutingView {
            step: step.into(),
            owners,
            ips,
        }
    }
}

impl DomainRoutingOwner {
    pub fn map_id(&self) -> Option<u32> {
        self.map_id
    }

    pub fn tracker(&self) -> &DomainRoutingTracker {
        &self.tracker
    }

    pub fn install_map(&mut self, map_id: u32) -> DomainRoutingMapReplay {
        let changed = self.map_id != Some(map_id);
        self.map_id = Some(map_id);
        DomainRoutingMapReplay {
            map_id,
            changed,
            entries: if changed {
                self.tracker.entries()
            } else {
                Vec::new()
            },
        }
    }

    pub fn prepare_reload_map(
        &mut self,
        map_id: u32,
        existing_keys: impl IntoIterator<Item = DomainRoutingIpKey>,
    ) -> DomainRoutingReloadClearPlan {
        let map_id_changed = self.map_id != Some(map_id);
        self.map_id = Some(map_id);
        self.tracker = DomainRoutingTracker::default();
        let deletes = normalize_ip_keys(existing_keys);
        DomainRoutingReloadClearPlan {
            map_id,
            map_id_changed,
            deletes,
            owner_count: self.tracker.owner_count(),
            ip_count: self.tracker.ip_count(),
        }
    }

    pub fn apply_owner_snapshot(
        &mut self,
        owner_key: &str,
        snapshot: DomainRoutingOwnerSnapshot,
    ) -> DomainRoutingOwnerUpdate {
        self.apply_owner_snapshot_ref(owner_key, &snapshot)
    }

    pub fn apply_owner_snapshot_ref(
        &mut self,
        owner_key: &str,
        snapshot: &DomainRoutingOwnerSnapshot,
    ) -> DomainRoutingOwnerUpdate {
        let plan = self.tracker.apply_owner_update_ref(owner_key, snapshot);
        DomainRoutingOwnerUpdate {
            map_id: self.map_id,
            flush: self.map_id.is_some() && (!plan.updates.is_empty() || !plan.deletes.is_empty()),
            plan,
        }
    }
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

fn merge_owner_bitmaps(owners: &HashMap<String, [u32; 32]>) -> [u32; 32] {
    let mut merged = [0; 32];
    for bitmap in owners.values() {
        or_bitmap(&mut merged, bitmap);
    }
    merged
}

fn or_bitmap(dst: &mut [u32; 32], src: &[u32; 32]) {
    for (dst, src) in dst.iter_mut().zip(src.iter()) {
        *dst |= *src;
    }
}

fn normalize_ip_keys(
    keys: impl IntoIterator<Item = DomainRoutingIpKey>,
) -> Vec<DomainRoutingIpKey> {
    let mut keys = keys.into_iter().collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    keys
}

pub fn parse_ip_key(ip: &str) -> Option<DomainRoutingIpKey> {
    let ip = ip.parse::<IpAddr>().ok()?;
    Some(ip_to_key(ip))
}

pub fn ip_to_key(ip: IpAddr) -> DomainRoutingIpKey {
    let octets = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    [
        u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]),
        u32::from_ne_bytes([octets[4], octets[5], octets[6], octets[7]]),
        u32::from_ne_bytes([octets[8], octets[9], octets[10], octets[11]]),
        u32::from_ne_bytes([octets[12], octets[13], octets[14], octets[15]]),
    ]
}

pub fn format_ip_key(key: &DomainRoutingIpKey) -> String {
    let mut octets = [0_u8; 16];
    for (index, word) in key.iter().enumerate() {
        octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    if octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
        return Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]).to_string();
    }
    Ipv6Addr::from(octets).to_string()
}

fn trimmed_bitmap(bitmap: &[u32; 32]) -> Vec<u32> {
    let mut end = bitmap.len();
    while end > 0 && bitmap[end - 1] == 0 {
        end -= 1;
    }
    bitmap[..end].to_vec()
}
