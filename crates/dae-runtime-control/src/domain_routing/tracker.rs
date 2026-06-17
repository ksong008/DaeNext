use super::*;
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
        if old_snapshot == Some(snapshot) {
            return DomainRoutingSyncPlan {
                owner_count: self.owners.len(),
                ip_count: self.ips.len(),
                ..DomainRoutingSyncPlan::default()
            };
        }

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
        let mut plan = self.plan_owner_update(owner_key, &snapshot);
        if owner_key.is_empty() {
            return plan;
        }
        self.apply_owner_snapshot_owned(owner_key, snapshot);
        plan.owner_count = self.owners.len();
        plan.ip_count = self.ips.len();
        plan
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

    pub(super) fn desired_bitmap_for_key(
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

    pub(super) fn apply_owner_snapshot_ref(
        &mut self,
        owner_key: &str,
        snapshot: &DomainRoutingOwnerSnapshot,
    ) {
        self.remove_owner(owner_key);

        if snapshot.is_empty() {
            return;
        }

        self.owners.insert(owner_key.to_owned(), snapshot.clone());
        self.apply_owner_ip_state(owner_key, &snapshot.ips, snapshot.bitmap);
    }

    pub(super) fn apply_owner_snapshot_owned(
        &mut self,
        owner_key: &str,
        snapshot: DomainRoutingOwnerSnapshot,
    ) {
        self.remove_owner(owner_key);

        if snapshot.is_empty() {
            return;
        }

        self.apply_owner_ip_state(owner_key, &snapshot.ips, snapshot.bitmap);
        self.owners.insert(owner_key.to_owned(), snapshot);
    }

    pub(super) fn apply_owner_snapshot_incremental(
        &mut self,
        owner_key: &str,
        snapshot: DomainRoutingOwnerSnapshot,
        plan: &DomainRoutingSyncPlan,
    ) {
        let snapshot_empty = snapshot.is_empty();
        let mut remove_empty_ips = Vec::new();

        for key in &plan.deletes {
            let Some(state) = self.ips.get_mut(key) else {
                continue;
            };
            state.owners.remove(owner_key);
            if state.owners.is_empty() {
                remove_empty_ips.push(*key);
            } else {
                state.merged = merge_owner_bitmaps(&state.owners);
            }
        }

        for entry in &plan.updates {
            if !snapshot_empty && snapshot.ips.contains(&entry.key) {
                let state = self.ips.entry(entry.key).or_default();
                state.owners.insert(owner_key.to_owned(), snapshot.bitmap);
                state.merged = entry.bitmap;
                continue;
            }

            let Some(state) = self.ips.get_mut(&entry.key) else {
                continue;
            };
            state.owners.remove(owner_key);
            if state.owners.is_empty() {
                remove_empty_ips.push(entry.key);
            } else {
                state.merged = entry.bitmap;
            }
        }

        for key in remove_empty_ips {
            self.ips.remove(&key);
        }

        if snapshot_empty {
            self.owners.remove(owner_key);
        } else {
            self.owners.insert(owner_key.to_owned(), snapshot);
        }
    }

    pub(super) fn remove_owner(&mut self, owner_key: &str) {
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
    }

    pub(super) fn apply_owner_ip_state(
        &mut self,
        owner_key: &str,
        ips: &[DomainRoutingIpKey],
        bitmap: [u32; 32],
    ) {
        for ip in ips {
            let ip = *ip;
            let state = self.ips.entry(ip).or_default();
            state.owners.insert(owner_key.to_owned(), bitmap);
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
