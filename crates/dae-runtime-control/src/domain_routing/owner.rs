use super::*;
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

    pub fn apply_owner_snapshot_by_id(
        &mut self,
        map_id: u32,
        owner_key: &str,
        snapshot: DomainRoutingOwnerSnapshot,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        self.apply_owner_snapshot_with(map_id, owner_key, snapshot, |map_id, updates, deletes| {
            apply_domain_routing_state_entries_by_id(map_id, updates, deletes)
        })
    }

    pub fn apply_dns_event_by_id(
        &mut self,
        map_id: u32,
        event: DomainRoutingDnsEvent<'_>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        self.apply_dns_event_with(map_id, event, |map_id, updates, deletes| {
            apply_domain_routing_state_entries_by_id(map_id, updates, deletes)
        })
    }

    pub fn apply_dns_events_by_id<'event>(
        &mut self,
        map_id: u32,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        self.apply_dns_events_with(map_id, events, |map_id, updates, deletes| {
            apply_domain_routing_state_entries_by_id(map_id, updates, deletes)
        })
    }

    pub fn apply_dns_events_with<'event>(
        &mut self,
        map_id: u32,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
        apply: impl FnOnce(u32, &[DomainRoutingStateEntry], &[DomainRoutingIpKey]) -> io::Result<()>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        // Coalesce owner replacements before staging only the affected IPs.
        // Neither the local tracker nor its map id changes until BPF succeeds.
        let mut replacements = HashMap::new();
        for event in events {
            if event.owner_key.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain routing owner key is empty",
                ));
            }
            replacements.insert(event.owner_key, event.into_snapshot());
        }
        replacements.retain(|key, snapshot| match self.tracker.owners.get(*key) {
            Some(old) => old != snapshot,
            None => !snapshot.is_empty(),
        });
        let owner_snapshot_changed = !replacements.is_empty();
        let mut affected = Vec::new();
        for (key, snapshot) in &replacements {
            if let Some(old) = self.tracker.owners.get(*key) {
                affected.extend_from_slice(&old.ips);
            }
            affected.extend_from_slice(&snapshot.ips);
        }
        affected.sort_unstable();
        affected.dedup();
        let affected_keys = affected.len();
        let mut staged = affected
            .iter()
            .map(|ip| (*ip, self.tracker.ips.get(ip).cloned().unwrap_or_default()))
            .collect::<HashMap<_, _>>();
        for (key, snapshot) in &replacements {
            if let Some(old) = self.tracker.owners.get(*key) {
                for ip in &old.ips {
                    staged
                        .get_mut(ip)
                        .expect("old IP is staged")
                        .owners
                        .remove(*key);
                }
            }
            if !snapshot.is_empty() {
                for ip in &snapshot.ips {
                    staged
                        .get_mut(ip)
                        .expect("new IP is staged")
                        .owners
                        .insert((*key).to_owned(), snapshot.bitmap);
                }
            }
        }
        let mut updates = Vec::new();
        let mut deletes = Vec::new();
        for ip in &affected {
            let next = staged.get_mut(ip).expect("affected IP is staged");
            next.merged = merge_owner_bitmaps(&next.owners);
            match (self.tracker.ips.get(ip), next.owners.is_empty()) {
                (Some(_), true) => deletes.push(*ip),
                (None, false) => updates.push(DomainRoutingStateEntry {
                    key: *ip,
                    bitmap: next.merged,
                }),
                (Some(old), false) if old.merged != next.merged => {
                    updates.push(DomainRoutingStateEntry {
                        key: *ip,
                        bitmap: next.merged,
                    })
                }
                _ => {}
            }
        }
        let map_id_changed = self.map_id != Some(map_id);
        if map_id_changed {
            // A new map needs a one-time replay, including untouched IPs.
            updates = self
                .tracker
                .ips
                .iter()
                .filter(|(ip, _)| !staged.contains_key(*ip))
                .map(|(ip, state)| DomainRoutingStateEntry {
                    key: *ip,
                    bitmap: state.merged,
                })
                .chain(
                    staged
                        .iter()
                        .filter(|(_, state)| !state.owners.is_empty())
                        .map(|(ip, state)| DomainRoutingStateEntry {
                            key: *ip,
                            bitmap: state.merged,
                        }),
                )
                .collect();
            updates.sort_by_key(|entry| entry.key);
            deletes.clear();
        }
        let skipped = updates.is_empty() && deletes.is_empty();
        if !skipped {
            apply(map_id, &updates, &deletes)?;
        }
        for (key, snapshot) in replacements {
            if snapshot.is_empty() {
                self.tracker.owners.remove(key);
            } else {
                self.tracker.owners.insert(key.to_owned(), snapshot);
            }
        }
        for (ip, state) in staged {
            if state.owners.is_empty() {
                self.tracker.ips.remove(&ip);
            } else {
                self.tracker.ips.insert(ip, state);
            }
        }
        self.map_id = Some(map_id);
        Ok(DomainRoutingOwnerApplyReport {
            map_id,
            map_id_changed,
            skipped,
            owner_snapshot_changed,
            affected_keys,
            entries_updated: updates.len(),
            entries_deleted: deletes.len(),
            owner_count: self.tracker.owner_count(),
            ip_count: self.tracker.ip_count(),
        })
    }

    pub fn apply_dns_event_with(
        &mut self,
        map_id: u32,
        event: DomainRoutingDnsEvent<'_>,
        apply: impl FnOnce(u32, &[DomainRoutingStateEntry], &[DomainRoutingIpKey]) -> io::Result<()>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        let DomainRoutingDnsEvent {
            owner_key,
            bitmap,
            ips,
        } = event;
        self.apply_owner_snapshot_with(
            map_id,
            owner_key,
            DomainRoutingOwnerSnapshot { bitmap, ips },
            apply,
        )
    }

    pub fn apply_owner_snapshot_with(
        &mut self,
        map_id: u32,
        owner_key: &str,
        snapshot: DomainRoutingOwnerSnapshot,
        apply: impl FnOnce(u32, &[DomainRoutingStateEntry], &[DomainRoutingIpKey]) -> io::Result<()>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        self.apply_dns_events_with(
            map_id,
            [DomainRoutingDnsEvent {
                owner_key,
                bitmap: snapshot.bitmap,
                ips: snapshot.ips,
            }],
            apply,
        )
    }

    pub fn prepare_reload_map_by_id(
        &mut self,
        map_id: u32,
        existing_keys: impl IntoIterator<Item = DomainRoutingIpKey>,
    ) -> io::Result<DomainRoutingReloadClearPlan> {
        self.prepare_reload_map_with(map_id, existing_keys, |map_id, deletes| {
            apply_domain_routing_state_entries_by_id(map_id, &[], deletes)
        })
    }

    pub fn prepare_reload_map_with(
        &mut self,
        map_id: u32,
        existing_keys: impl IntoIterator<Item = DomainRoutingIpKey>,
        apply: impl FnOnce(u32, &[DomainRoutingIpKey]) -> io::Result<()>,
    ) -> io::Result<DomainRoutingReloadClearPlan> {
        let deletes = normalize_ip_keys(existing_keys);
        if !deletes.is_empty() {
            apply(map_id, &deletes)?;
        }
        let map_id_changed = self.map_id != Some(map_id);
        self.map_id = Some(map_id);
        self.tracker = DomainRoutingTracker::default();
        Ok(DomainRoutingReloadClearPlan {
            map_id,
            map_id_changed,
            deletes,
            owner_count: self.tracker.owner_count(),
            ip_count: self.tracker.ip_count(),
        })
    }
}
