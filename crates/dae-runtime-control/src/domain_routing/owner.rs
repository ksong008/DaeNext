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
            apply_domain_routing_entries(map_id, updates, deletes)
        })
    }

    pub fn apply_dns_event_by_id(
        &mut self,
        map_id: u32,
        event: DomainRoutingDnsEvent<'_>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        self.apply_dns_event_with(map_id, event, |map_id, updates, deletes| {
            apply_domain_routing_entries(map_id, updates, deletes)
        })
    }

    pub fn apply_dns_events_by_id<'event>(
        &mut self,
        map_id: u32,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        self.apply_dns_events_with(map_id, events, |map_id, updates, deletes| {
            apply_domain_routing_entries(map_id, updates, deletes)
        })
    }

    pub fn apply_dns_events_with<'event>(
        &mut self,
        map_id: u32,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
        apply: impl FnOnce(u32, &[DomainRoutingStateEntry], &[DomainRoutingIpKey]) -> io::Result<()>,
    ) -> io::Result<DomainRoutingOwnerApplyReport> {
        let mut next = self.tracker.clone();
        for event in events {
            if event.owner_key.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain routing owner key is empty",
                ));
            }
            next.apply_owner_snapshot_owned(event.owner_key, event.into_snapshot());
        }

        let map_id_changed = self.map_id != Some(map_id);
        let plan = if map_id_changed {
            DomainRoutingSyncPlan {
                updates: next.entries(),
                deletes: Vec::new(),
                owner_count: next.owner_count(),
                ip_count: next.ip_count(),
            }
        } else {
            self.tracker.plan_transition(&next)
        };
        if plan.updates.is_empty() && plan.deletes.is_empty() {
            self.map_id = Some(map_id);
            self.tracker = next;
            return Ok(DomainRoutingOwnerApplyReport {
                map_id,
                map_id_changed,
                skipped: true,
                entries_updated: 0,
                entries_deleted: 0,
                owner_count: self.tracker.owner_count(),
                ip_count: self.tracker.ip_count(),
            });
        }

        apply(map_id, &plan.updates, &plan.deletes)?;
        let report = DomainRoutingOwnerApplyReport {
            map_id,
            map_id_changed,
            skipped: false,
            entries_updated: plan.updates.len(),
            entries_deleted: plan.deletes.len(),
            owner_count: next.owner_count(),
            ip_count: next.ip_count(),
        };
        self.map_id = Some(map_id);
        self.tracker = next;
        Ok(report)
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
        if owner_key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "domain routing owner key is empty",
            ));
        }
        let map_id_changed = self.map_id != Some(map_id);
        if map_id_changed {
            let mut next = self.tracker.clone();
            next.apply_owner_update_ref(owner_key, &snapshot);
            let entries = next.entries();
            if !entries.is_empty() {
                apply(map_id, &entries, &[])?;
            }
            self.map_id = Some(map_id);
            self.tracker = next;
            return Ok(DomainRoutingOwnerApplyReport {
                map_id,
                map_id_changed: true,
                skipped: entries.is_empty(),
                entries_updated: entries.len(),
                entries_deleted: 0,
                owner_count: self.tracker.owner_count(),
                ip_count: self.tracker.ip_count(),
            });
        }

        let plan = self.tracker.plan_owner_update(owner_key, &snapshot);
        if plan.updates.is_empty() && plan.deletes.is_empty() {
            self.tracker.apply_owner_snapshot_owned(owner_key, snapshot);
            return Ok(DomainRoutingOwnerApplyReport {
                map_id,
                map_id_changed: false,
                skipped: true,
                entries_updated: 0,
                entries_deleted: 0,
                owner_count: self.tracker.owner_count(),
                ip_count: self.tracker.ip_count(),
            });
        }
        apply(map_id, &plan.updates, &plan.deletes)?;
        let entries_updated = plan.updates.len();
        let entries_deleted = plan.deletes.len();
        self.tracker
            .apply_owner_snapshot_incremental(owner_key, snapshot, &plan);
        Ok(DomainRoutingOwnerApplyReport {
            map_id,
            map_id_changed: false,
            skipped: false,
            entries_updated,
            entries_deleted,
            owner_count: self.tracker.owner_count(),
            ip_count: self.tracker.ip_count(),
        })
    }

    pub fn prepare_reload_map_by_id(
        &mut self,
        map_id: u32,
        existing_keys: impl IntoIterator<Item = DomainRoutingIpKey>,
    ) -> io::Result<DomainRoutingReloadClearPlan> {
        self.prepare_reload_map_with(map_id, existing_keys, |map_id, deletes| {
            apply_domain_routing_entries(map_id, &[], deletes)
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
