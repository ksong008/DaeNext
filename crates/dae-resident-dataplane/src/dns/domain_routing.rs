use std::io;
use std::sync::{Arc, Mutex};

use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore, DnsPacketView, DnsResponseCachePlan};
use dae_routing::RoutingMatcher;
#[cfg(test)]
use dae_runtime_control::DomainRoutingStateEntry;
use dae_runtime_control::{
    DomainRoutingDnsEvent, DomainRoutingIpKey, DomainRoutingOwner, DomainRoutingTracker,
    apply_domain_routing_state_entries_by_id, ip_to_key,
};

use super::unix_now;

mod maintenance;
mod reload;
#[cfg(test)]
mod tests;
pub(crate) use self::maintenance::ResidentDnsDomainRoutingMaintenanceHandle;
#[cfg(test)]
pub(super) use self::reload::build_resident_dns_domain_routing_update_plan_from_entry;
pub(super) use self::reload::{
    ResidentDnsDomainRoutingReloadSnapshot, ResidentDnsDomainRoutingRestoreReport,
};

#[cfg(test)]
type ResidentDomainRoutingMapApply =
    fn(u32, &[DomainRoutingStateEntry], &[DomainRoutingIpKey]) -> io::Result<()>;

#[derive(Debug)]
pub(crate) struct ResidentDnsDomainRouting {
    map_id: u32,
    generation: u64,
    fence: Arc<ResidentDomainRoutingGenerationFence>,
    routing_matcher: RoutingMatcher,
    state: Mutex<ResidentDnsDomainRoutingState>,
    maintenance: maintenance::ResidentDnsDomainRoutingMaintenanceSignal,
    #[cfg(test)]
    test_apply_map: Option<ResidentDomainRoutingMapApply>,
}

#[derive(Debug, Default)]
pub(crate) struct ResidentDomainRoutingGenerationFence {
    state: Mutex<ResidentDomainRoutingGenerationFenceState>,
}

#[derive(Debug, Default)]
struct ResidentDomainRoutingGenerationFenceState {
    active_generation: Option<u64>,
    map_id: Option<u32>,
    tracker: DomainRoutingTracker,
}

#[derive(Debug)]
struct ResidentDnsDomainRoutingState {
    owner: DomainRoutingOwner,
    cache: DnsCacheStore,
    domain_bitmap: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentDnsDomainRoutingUpdatePlan {
    pub(super) key: DnsCacheKey,
    pub(super) entry: DnsCacheEntry,
    pub(super) ips: Vec<DomainRoutingIpKey>,
}

impl ResidentDnsDomainRouting {
    #[cfg(test)]
    pub(crate) fn new(map_id: u32, routing_matcher: RoutingMatcher) -> Self {
        let fence = Arc::new(ResidentDomainRoutingGenerationFence {
            state: Mutex::new(ResidentDomainRoutingGenerationFenceState {
                active_generation: Some(0),
                map_id: Some(map_id),
                tracker: DomainRoutingTracker::default(),
            }),
        });
        Self::new_for_generation(map_id, 0, routing_matcher, fence)
    }

    pub(crate) fn new_for_generation(
        map_id: u32,
        generation: u64,
        routing_matcher: RoutingMatcher,
        fence: Arc<ResidentDomainRoutingGenerationFence>,
    ) -> Self {
        Self {
            map_id,
            generation,
            fence,
            routing_matcher,
            state: Mutex::new(ResidentDnsDomainRoutingState {
                owner: DomainRoutingOwner::default(),
                cache: DnsCacheStore::default(),
                domain_bitmap: Vec::new(),
            }),
            maintenance: maintenance::ResidentDnsDomainRoutingMaintenanceSignal::default(),
            #[cfg(test)]
            test_apply_map: None,
        }
    }

    pub(super) fn record_accepted_response(
        &self,
        cache_plan: &DnsResponseCachePlan,
    ) -> Result<(), String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.sweep_expired_locked(now_unix, &mut state)?;
        let Some(plan) = build_resident_dns_domain_routing_update_plan(
            &self.routing_matcher,
            &mut state.domain_bitmap,
            cache_plan,
        )?
        else {
            return Ok(());
        };
        let capacity_eviction = state
            .cache
            .capacity_eviction_key_for_insert(&plan.key)
            .map(|key| {
                let entry = state.cache.remove_capacity_eviction(&key).ok_or_else(|| {
                    "resident DNS domain routing capacity eviction disappeared".to_owned()
                })?;
                Ok::<_, String>((key, entry))
            })
            .transpose()?;
        let apply_result = if let Some((_, evicted)) = capacity_eviction.as_ref() {
            let mut events = Vec::with_capacity(2);
            if !evicted.route_owner_key.is_empty() {
                events.push(DomainRoutingDnsEvent::remove(&evicted.route_owner_key));
            }
            events.push(DomainRoutingDnsEvent::from_keys(
                &plan.entry.route_owner_key,
                &plan.entry.domain_bitmap,
                plan.ips.iter().copied(),
            ));
            self.apply_events(&mut state.owner, events)
        } else {
            self.apply_event(
                &mut state.owner,
                DomainRoutingDnsEvent::from_keys(
                    &plan.entry.route_owner_key,
                    &plan.entry.domain_bitmap,
                    plan.ips.iter().copied(),
                ),
            )
        };
        if let Err(err) = apply_result {
            if let Some((key, entry)) = capacity_eviction {
                state.cache.restore_capacity_eviction(key, entry);
            }
            return Err(format!("apply resident DNS domain routing response: {err}"));
        }
        state
            .cache
            .insert_without_route_owner_key(now_unix, plan.key, plan.entry);
        drop(state);
        self.maintenance.notify_deadline_changed();
        Ok(())
    }

    pub(super) fn remove_request(&self, request: &DnsPacketView<'_>) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        let Some((removed_key, removed)) = state
            .cache
            .remove_packet_question_entry(
                &request
                    .questions()
                    .next()
                    .ok_or_else(|| "DNS request has no question".to_owned())?,
            )
            .map_err(|err| format!("remove resident DNS domain routing cache entry: {err}"))?
        else {
            return Ok(());
        };
        if !removed.route_owner_key.is_empty()
            && let Err(err) = self.apply_event(
                &mut state.owner,
                DomainRoutingDnsEvent::remove(&removed.route_owner_key),
            )
        {
            state.cache.restore_removed_entry(removed_key, removed);
            return Err(format!("remove resident DNS domain routing owner: {err}"));
        }
        drop(state);
        self.maintenance.notify_deadline_changed();
        Ok(())
    }

    fn sweep_expired_locked(
        &self,
        now_unix: i64,
        state: &mut ResidentDnsDomainRoutingState,
    ) -> Result<(), String> {
        let mut expired_entries = state.cache.sweep_entries(now_unix).into_iter();
        while let Some((key, expired)) = expired_entries.next() {
            if expired.route_owner_key.is_empty() {
                continue;
            }
            if let Err(err) = self.apply_event(
                &mut state.owner,
                DomainRoutingDnsEvent::remove(&expired.route_owner_key),
            ) {
                state
                    .cache
                    .restore_swept_entries(std::iter::once((key, expired)).chain(expired_entries));
                return Err(format!(
                    "remove expired resident DNS domain routing owner: {err}"
                ));
            }
        }
        Ok(())
    }

    fn apply_event(
        &self,
        owner: &mut DomainRoutingOwner,
        event: DomainRoutingDnsEvent<'_>,
    ) -> io::Result<()> {
        #[cfg(test)]
        if let Some(apply_map) = self.test_apply_map {
            return self.fence.apply_event_with(
                self.generation,
                self.map_id,
                owner,
                event,
                apply_map,
            );
        }
        self.fence.apply_event_with(
            self.generation,
            self.map_id,
            owner,
            event,
            apply_domain_routing_state_entries_by_id,
        )
    }

    fn apply_events<'event>(
        &self,
        owner: &mut DomainRoutingOwner,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
    ) -> io::Result<()> {
        #[cfg(test)]
        if let Some(apply_map) = self.test_apply_map {
            return self.fence.apply_events_with(
                self.generation,
                self.map_id,
                owner,
                events,
                apply_map,
            );
        }
        self.fence.apply_events_with(
            self.generation,
            self.map_id,
            owner,
            events,
            apply_domain_routing_state_entries_by_id,
        )
    }

    pub(crate) fn activate_generation(&self) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.fence
            .activate_with(
                self.generation,
                self.map_id,
                &state.owner,
                apply_domain_routing_state_entries_by_id,
            )
            .map_err(|error| format!("activate resident DNS domain routing generation: {error}"))
    }
}

impl ResidentDomainRoutingGenerationFence {
    fn apply_event_with(
        &self,
        generation: u64,
        map_id: u32,
        owner: &mut DomainRoutingOwner,
        event: DomainRoutingDnsEvent<'_>,
        apply: impl FnOnce(
            u32,
            &[dae_runtime_control::DomainRoutingStateEntry],
            &[DomainRoutingIpKey],
        ) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut state = self.lock()?;
        let active = state.active_generation == Some(generation) && state.map_id == Some(map_id);
        let report = if active {
            owner.apply_dns_event_with(map_id, event, apply)?
        } else {
            owner.apply_dns_event_with(map_id, event, |_, _, _| Ok(()))?
        };
        if active {
            state.tracker = owner.tracker().clone();
        }
        let _ = report;
        Ok(())
    }

    fn apply_events_with<'event>(
        &self,
        generation: u64,
        map_id: u32,
        owner: &mut DomainRoutingOwner,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
        apply: impl FnOnce(
            u32,
            &[dae_runtime_control::DomainRoutingStateEntry],
            &[DomainRoutingIpKey],
        ) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut state = self.lock()?;
        let active = state.active_generation == Some(generation) && state.map_id == Some(map_id);
        if active {
            owner.apply_dns_events_with(map_id, events, apply)?;
            state.tracker = owner.tracker().clone();
        } else {
            owner.apply_dns_events_with(map_id, events, |_, _, _| Ok(()))?;
        }
        Ok(())
    }

    fn activate_with(
        &self,
        generation: u64,
        map_id: u32,
        owner: &DomainRoutingOwner,
        apply: impl FnOnce(
            u32,
            &[dae_runtime_control::DomainRoutingStateEntry],
            &[DomainRoutingIpKey],
        ) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.active_generation == Some(generation) && state.map_id == Some(map_id) {
            return Ok(());
        }
        let desired = owner.tracker();
        let plan = if state.map_id == Some(map_id) {
            state.tracker.plan_transition(desired)
        } else {
            dae_runtime_control::DomainRoutingSyncPlan {
                updates: desired.entries(),
                deletes: Vec::new(),
                owner_count: desired.owner_count(),
                ip_count: desired.ip_count(),
            }
        };
        if !plan.updates.is_empty() || !plan.deletes.is_empty() {
            apply(map_id, &plan.updates, &plan.deletes)?;
        }
        state.active_generation = Some(generation);
        state.map_id = Some(map_id);
        state.tracker = desired.clone();
        Ok(())
    }

    fn lock(
        &self,
    ) -> io::Result<std::sync::MutexGuard<'_, ResidentDomainRoutingGenerationFenceState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("resident domain routing generation fence poisoned"))
    }
}

#[cfg(test)]
fn apply_resident_domain_routing_event_in_memory(
    _: u32,
    _: &[DomainRoutingStateEntry],
    _: &[DomainRoutingIpKey],
) -> io::Result<()> {
    Ok(())
}

pub(super) fn build_resident_dns_domain_routing_update_plan(
    routing_matcher: &RoutingMatcher,
    domain_bitmap: &mut Vec<u32>,
    cache_plan: &DnsResponseCachePlan,
) -> Result<Option<ResidentDnsDomainRoutingUpdatePlan>, String> {
    if cache_plan.entry.ips.is_empty() {
        return Ok(None);
    }
    let bitmap = routing_matcher
        .domain_bitmap_for_domain_into(&cache_plan.key.qname, domain_bitmap)
        .map_err(|err| format!("match resident DNS response domain routing bitmap: {err}"))?;
    if bitmap.iter().all(|word| *word == 0) {
        return Ok(None);
    }
    let ips = cache_plan
        .entry
        .ips
        .iter()
        .copied()
        .map(ip_to_key)
        .collect::<Vec<_>>();
    let mut entry = cache_plan.entry.clone();
    entry.domain_bitmap.clear();
    entry.domain_bitmap.extend_from_slice(bitmap);
    Ok(Some(ResidentDnsDomainRoutingUpdatePlan {
        key: cache_plan.key.clone(),
        entry,
        ips,
    }))
}
