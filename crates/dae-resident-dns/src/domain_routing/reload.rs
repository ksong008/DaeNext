use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResidentDnsDomainRoutingReloadSnapshot {
    accepted_responses: Vec<(DnsCacheKey, Arc<DnsCacheEntry>)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResidentDnsDomainRoutingRestoreReport {
    pub accepted_response_entries: usize,
    pub sniffed_domain_entries: usize,
    pub skipped_expired_entries: usize,
    pub skipped_unmatched_entries: usize,
}

impl ResidentDnsDomainRoutingReloadSnapshot {
    pub fn entry_count(&self) -> usize {
        self.accepted_responses.len()
    }
}

impl ResidentDnsDomainRouting {
    pub fn snapshot_for_reload(&self) -> Result<ResidentDnsDomainRoutingReloadSnapshot, String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.sweep_expired_locked(now_unix, &mut state)?;
        let accepted_responses = state.cache.snapshot_live_entries_shared(now_unix);
        Ok(ResidentDnsDomainRoutingReloadSnapshot { accepted_responses })
    }

    pub fn restore_reload_snapshot(
        &self,
        snapshot: &ResidentDnsDomainRoutingReloadSnapshot,
    ) -> Result<ResidentDnsDomainRoutingRestoreReport, String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.sweep_expired_locked(now_unix, &mut state)?;
        let mut report = ResidentDnsDomainRoutingRestoreReport::default();
        for (key, entry) in &snapshot.accepted_responses {
            if entry.cache_expires_at() <= now_unix {
                report.skipped_expired_entries += 1;
                continue;
            }
            let Some(plan) = build_resident_dns_domain_routing_update_plan_from_entry(
                &self.routing_matcher,
                &mut state.domain_bitmap,
                key,
                entry,
            )?
            else {
                report.skipped_unmatched_entries += 1;
                continue;
            };
            self.apply_event(
                &mut state.owner,
                DomainRoutingDnsEvent::from_keys(
                    &plan.entry.route_owner_key,
                    &plan.entry.domain_bitmap,
                    plan.ips.iter().copied(),
                ),
            )
            .map_err(|err| format!("restore resident DNS response domain routing owner: {err}"))?;
            state
                .cache
                .insert_without_route_owner_key(now_unix, plan.key, plan.entry);
            report.accepted_response_entries += 1;
        }
        drop(state);
        self.maintenance.notify_deadline_changed();
        Ok(report)
    }
}

pub(super) fn build_resident_dns_domain_routing_update_plan_from_entry(
    routing_matcher: &RoutingMatcher,
    domain_bitmap: &mut Vec<u32>,
    key: &DnsCacheKey,
    entry: &DnsCacheEntry,
) -> Result<Option<ResidentDnsDomainRoutingUpdatePlan>, String> {
    if entry.ips.is_empty() {
        return Ok(None);
    }
    let bitmap = routing_matcher
        .domain_bitmap_for_domain_into(&key.qname, domain_bitmap)
        .map_err(|err| format!("match resident DNS reload domain routing bitmap: {err}"))?;
    if bitmap.iter().all(|word| *word == 0) {
        return Ok(None);
    }
    let ips = entry.ips.iter().copied().map(ip_to_key).collect::<Vec<_>>();
    let mut entry = entry.clone();
    if entry.route_owner_key.is_empty() {
        entry.route_owner_key = key.to_string();
    }
    entry.domain_bitmap.clear();
    entry.domain_bitmap.extend_from_slice(bitmap);
    Ok(Some(ResidentDnsDomainRoutingUpdatePlan {
        key: key.clone(),
        entry,
        ips,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_snapshot_skips_entries_that_expired_while_reloading() {
        let matcher = RoutingMatcher::from_typed_sets(Vec::new(), Vec::new(), Vec::new()).unwrap();
        let mut domain_routing = ResidentDnsDomainRouting::new(1, matcher);
        domain_routing.test_apply_map = Some(apply_resident_domain_routing_event_in_memory);
        let now_unix = unix_now();
        let key = DnsCacheKey::new("expired.example", 1, 1);
        let mut entry = DnsCacheEntry::new(now_unix, now_unix);
        entry.route_owner_key = key.to_string();
        entry.ips.push("192.0.2.40".parse().unwrap());
        let snapshot = ResidentDnsDomainRoutingReloadSnapshot {
            accepted_responses: vec![(key, Arc::new(entry))],
        };

        let report = domain_routing.restore_reload_snapshot(&snapshot).unwrap();
        assert_eq!(report.skipped_expired_entries, 1);
        assert_eq!(report.accepted_response_entries, 0);
        assert_eq!(report.sniffed_domain_entries, 0);
        let state = domain_routing.state.lock().unwrap();
        assert!(state.cache.is_empty());
        assert_eq!(state.owner.tracker().owner_count(), 0);
    }
}
