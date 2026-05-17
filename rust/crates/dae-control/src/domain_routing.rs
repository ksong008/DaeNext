use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingOwnerSnapshot {
    pub bitmap: [u32; 32],
    pub ips: BTreeSet<String>,
}

impl DomainRoutingOwnerSnapshot {
    pub fn new(bitmap_words: &[u32], ips: &[&str]) -> Self {
        let mut bitmap = [0; 32];
        for (index, word) in bitmap_words.iter().copied().enumerate().take(32) {
            bitmap[index] = word;
        }
        Self {
            bitmap,
            ips: ips.iter().map(|ip| (*ip).to_owned()).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() || self.bitmap.iter().all(|word| *word == 0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct IpState {
    owners: BTreeMap<String, [u32; 32]>,
    merged: [u32; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingTracker {
    owners: BTreeMap<String, DomainRoutingOwnerSnapshot>,
    ips: BTreeMap<String, IpState>,
}

impl DomainRoutingTracker {
    pub fn sync_owner(&mut self, owner_key: &str, snapshot: DomainRoutingOwnerSnapshot) {
        if owner_key.is_empty() {
            return;
        }
        self.apply_owner_snapshot(owner_key, snapshot);
    }

    fn apply_owner_snapshot(&mut self, owner_key: &str, snapshot: DomainRoutingOwnerSnapshot) {
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
        for ip in snapshot.ips {
            let state = self.ips.entry(ip).or_default();
            state.owners.insert(owner_key.to_owned(), snapshot.bitmap);
            state.merged = merge_owner_bitmaps(&state.owners);
        }
    }

    pub fn view(&self, step: impl Into<String>) -> DomainRoutingView {
        DomainRoutingView {
            step: step.into(),
            owners: self.owners.keys().cloned().collect(),
            ips: self
                .ips
                .iter()
                .map(|(ip, state)| IpRoutingView {
                    ip: ip.clone(),
                    owners: state.owners.keys().cloned().collect(),
                    merged: trimmed_bitmap(&state.merged),
                    present: true,
                })
                .collect(),
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

fn merge_owner_bitmaps(owners: &BTreeMap<String, [u32; 32]>) -> [u32; 32] {
    let mut merged = [0; 32];
    for bitmap in owners.values() {
        for (dst, src) in merged.iter_mut().zip(bitmap.iter()) {
            *dst |= *src;
        }
    }
    merged
}

fn trimmed_bitmap(bitmap: &[u32; 32]) -> Vec<u32> {
    let mut end = bitmap.len();
    while end > 0 && bitmap[end - 1] == 0 {
        end -= 1;
    }
    bitmap[..end].to_vec()
}
