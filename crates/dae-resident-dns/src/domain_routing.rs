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

use dae_resident_core::{
    GenerationFence, GenerationGate, GenerationToken, ResidentDnsResourceProfile,
};
#[cfg(test)]
use dae_resident_core::{LogicalGenerationId, PhysicalRuntimeId};

use super::unix_now;

mod maintenance;
mod reload;
#[cfg(test)]
mod tests;
pub use self::maintenance::ResidentDnsDomainRoutingMaintenanceHandle;
#[cfg(test)]
use self::reload::build_resident_dns_domain_routing_update_plan_from_entry;
pub use self::reload::{
    ResidentDnsDomainRoutingReloadSnapshot, ResidentDnsDomainRoutingRestoreReport,
};

#[cfg(test)]
type ResidentDomainRoutingMapApply =
    fn(u32, &[DomainRoutingStateEntry], &[DomainRoutingIpKey]) -> io::Result<()>;

#[derive(Debug)]
pub struct ResidentDnsDomainRouting {
    map_id: u32,
    generation: GenerationToken,
    fence: Arc<ResidentDomainRoutingMapOwner>,
    routing_matcher: RoutingMatcher,
    mutation: Mutex<()>,
    state: Mutex<ResidentDnsDomainRoutingState>,
    maintenance: maintenance::ResidentDnsDomainRoutingMaintenanceSignal,
    #[cfg(test)]
    test_apply_map: Option<ResidentDomainRoutingMapApply>,
}

#[derive(Debug, Default)]
struct ResidentDomainRoutingMapState {
    map_id: Option<u32>,
    tracker: DomainRoutingTracker,
}

#[derive(Debug)]
pub struct ResidentDomainRoutingMapOwner {
    inner: GenerationFence<ResidentDomainRoutingMapState>,
}

impl Default for ResidentDomainRoutingMapOwner {
    fn default() -> Self {
        Self::with_gate(Arc::new(GenerationGate::default()))
    }
}

impl ResidentDomainRoutingMapOwner {
    pub fn with_gate(gate: Arc<GenerationGate>) -> Self {
        Self {
            inner: gate.resource(ResidentDomainRoutingMapState::default()),
        }
    }

    pub fn gate(&self) -> &Arc<GenerationGate> {
        self.inner.gate()
    }
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
        let generation =
            GenerationToken::new(PhysicalRuntimeId::new(0), LogicalGenerationId::new(0));
        let fence = Arc::new(ResidentDomainRoutingMapOwner::with_gate_and_map(
            Arc::new(GenerationGate::new(Some(generation))),
            map_id,
        ));
        Self::new_for_generation(map_id, generation, routing_matcher, fence)
    }

    pub fn new_for_generation(
        map_id: u32,
        generation: GenerationToken,
        routing_matcher: RoutingMatcher,
        fence: Arc<ResidentDomainRoutingMapOwner>,
    ) -> Self {
        Self {
            map_id,
            generation,
            fence,
            routing_matcher,
            mutation: Mutex::new(()),
            state: Mutex::new(ResidentDnsDomainRoutingState {
                owner: DomainRoutingOwner::default(),
                cache: DnsCacheStore::new(
                    ResidentDnsResourceProfile::selected().dns_cache_entry_limit(),
                ),
                domain_bitmap: Vec::new(),
            }),
            maintenance: maintenance::ResidentDnsDomainRoutingMaintenanceSignal::default(),
            #[cfg(test)]
            test_apply_map: None,
        }
    }

    pub fn record_accepted_response(
        &self,
        cache_plan: &DnsResponseCachePlan,
    ) -> Result<(), String> {
        let now_unix = unix_now();
        self.sweep_expired_until(now_unix)?;
        let plan = {
            let mut state = self.lock_state()?;
            build_resident_dns_domain_routing_update_plan(
                &self.routing_matcher,
                &mut state.domain_bitmap,
                cache_plan,
            )?
        };
        if let Some(plan) = plan {
            self.commit_response(plan)?;
            self.maintenance.notify_deadline_changed();
        }
        Ok(())
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, ResidentDnsDomainRoutingState>, String> {
        self.state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())
    }

    fn lock_mutation(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.mutation
            .lock()
            .map_err(|_| "resident DNS domain routing mutation lock poisoned".to_owned())
    }

    fn commit_response(&self, plan: ResidentDnsDomainRoutingUpdatePlan) -> Result<bool, String> {
        // Serialize writers, but keep committed cache state available while BPF
        // executes. The generation fence still surrounds every map transaction.
        let _mutation = self.lock_mutation()?;
        let mut state = self.lock_state()?;
        if plan.entry.cache_expires_at() <= unix_now() || state.cache.capacity() == 0 {
            return Ok(false);
        }
        let evicted = state
            .cache
            .capacity_eviction_key_for_insert(&plan.key)
            .and_then(|key| state.cache.shared_entry(&key));
        let mut owner = std::mem::take(&mut state.owner);
        drop(state);
        let removes = evicted
            .iter()
            .filter(|entry| !entry.route_owner_key.is_empty())
            .map(|entry| DomainRoutingDnsEvent::remove(&entry.route_owner_key));
        let update = DomainRoutingDnsEvent::from_keys(
            &plan.entry.route_owner_key,
            &plan.entry.domain_bitmap,
            plan.ips,
        );
        let result = self.apply_events(&mut owner, removes.chain(std::iter::once(update)));
        let mut state = self.lock_state()?;
        state.owner = owner;
        result.map_err(|error| format!("apply resident DNS domain routing response: {error}"))?;
        state
            .cache
            .insert_with_eviction(plan.key, plan.entry, |_, _| Ok::<_, String>(()))
    }

    pub fn cache_entry_count(&self) -> Result<usize, String> {
        let now_unix = unix_now();
        self.sweep_expired_until(now_unix)?;
        let state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        Ok(state.cache.cache_stats_entries(unix_now()))
    }

    pub fn remove_request(&self, request: &DnsPacketView<'_>) -> Result<(), String> {
        let question = request
            .questions()
            .next()
            .ok_or_else(|| "DNS request has no question".to_owned())?;
        let key = DnsCacheKey::new(
            question
                .qname_to_canonical_string()
                .map_err(|e| e.to_string())?,
            question.qtype(),
            question.qclass(),
        );
        let _mutation = self.lock_mutation()?;
        let mut state = self.lock_state()?;
        let Some(entry) = state.cache.shared_entry(&key) else {
            return Ok(());
        };
        let mut owner = std::mem::take(&mut state.owner);
        drop(state);
        let result = if entry.route_owner_key.is_empty() {
            Ok(())
        } else {
            self.apply_event(
                &mut owner,
                DomainRoutingDnsEvent::remove(&entry.route_owner_key),
            )
        };
        let mut state = self.lock_state()?;
        state.owner = owner;
        result.map_err(|e| format!("remove resident DNS domain routing owner: {e}"))?;
        state.cache.remove(&key);
        drop(state);
        self.maintenance.notify_deadline_changed();
        Ok(())
    }

    fn sweep_expired_until(&self, now_unix: i64) -> Result<(), String> {
        loop {
            if self
                .lock_state()?
                .cache
                .next_expiry_unix()
                .is_none_or(|deadline| deadline > now_unix)
            {
                return Ok(());
            }
            self.sweep_expired_batch(now_unix)?;
            std::thread::yield_now();
        }
    }

    fn sweep_expired_batch(&self, now_unix: i64) -> Result<(), String> {
        let _mutation = self.lock_mutation()?;
        let mut state = self.lock_state()?;
        let expired = state.cache.expired_entries_shared(now_unix, 128);
        if expired.is_empty() {
            return Ok(());
        }
        let mut owner = std::mem::take(&mut state.owner);
        drop(state);
        let events = expired
            .iter()
            .filter(|(_, entry)| !entry.route_owner_key.is_empty())
            .map(|(_, entry)| DomainRoutingDnsEvent::remove(&entry.route_owner_key));
        let result = self.apply_events(&mut owner, events);
        let mut state = self.lock_state()?;
        state.owner = owner;
        result.map_err(|err| format!("remove expired resident DNS domain routing owner: {err}"))?;
        state.cache.sweep_entries_limited(now_unix, 128);
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

    pub fn activate_generation(&self) -> Result<(), String> {
        let _mutation = self.lock_mutation()?;
        let mut state = self.lock_state()?;
        let owner = std::mem::take(&mut state.owner);
        drop(state);
        let result = self.fence.activate_with(
            self.generation,
            self.map_id,
            &owner,
            apply_domain_routing_state_entries_by_id,
        );
        self.lock_state()?.owner = owner;
        result.map_err(|error| format!("activate resident DNS domain routing generation: {error}"))
    }
}

impl ResidentDomainRoutingMapOwner {
    #[cfg(test)]
    fn with_gate_and_map(gate: Arc<GenerationGate>, map_id: u32) -> Self {
        Self {
            inner: gate.resource(ResidentDomainRoutingMapState {
                map_id: Some(map_id),
                tracker: DomainRoutingTracker::default(),
            }),
        }
    }

    fn apply_event_with(
        &self,
        generation: GenerationToken,
        map_id: u32,
        owner: &mut DomainRoutingOwner,
        event: DomainRoutingDnsEvent<'_>,
        apply: impl FnOnce(
            u32,
            &[dae_runtime_control::DomainRoutingStateEntry],
            &[DomainRoutingIpKey],
        ) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut event = Some(event);
        let mut apply = Some(apply);
        let applied = self.inner.with_active(generation, |state| {
            if state.map_id != Some(map_id) {
                return Ok::<_, io::Error>(None);
            }
            let apply = apply
                .take()
                .ok_or_else(|| io::Error::other("domain routing map apply callback was reused"))?;
            let event = event
                .take()
                .ok_or_else(|| io::Error::other("domain routing event was reused"))?;
            let sync_event = event.clone();
            let report = owner.apply_dns_event_with(map_id, event, apply)?;
            if report.owner_snapshot_changed {
                state
                    .tracker
                    .sync_owner(sync_event.owner_key, sync_event.into_snapshot());
            }
            Ok(Some(report))
        })?;
        if applied.flatten().is_none() {
            owner.apply_dns_event_with(
                map_id,
                event
                    .take()
                    .ok_or_else(|| io::Error::other("domain routing event was reused"))?,
                |_, _, _| Ok(()),
            )?;
        }
        Ok(())
    }

    fn apply_events_with<'event>(
        &self,
        generation: GenerationToken,
        map_id: u32,
        owner: &mut DomainRoutingOwner,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
        apply: impl FnOnce(
            u32,
            &[dae_runtime_control::DomainRoutingStateEntry],
            &[DomainRoutingIpKey],
        ) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut events = Some(events.into_iter().collect::<Vec<_>>());
        let mut apply = Some(apply);
        let applied = self.inner.with_active(generation, |state| {
            if state.map_id != Some(map_id) {
                return Ok::<_, io::Error>(None);
            }
            let apply = apply
                .take()
                .ok_or_else(|| io::Error::other("domain routing map apply callback was reused"))?;
            let events = events
                .take()
                .ok_or_else(|| io::Error::other("domain routing event was reused"))?;
            let sync_events = events.clone();
            let report = owner.apply_dns_events_with(map_id, events, apply)?;
            if report.owner_snapshot_changed {
                for event in sync_events {
                    state
                        .tracker
                        .sync_owner(event.owner_key, event.into_snapshot());
                }
            }
            Ok(Some(()))
        })?;
        if applied.flatten().is_none() {
            owner.apply_dns_events_with(
                map_id,
                events
                    .take()
                    .ok_or_else(|| io::Error::other("domain routing event was reused"))?,
                |_, _, _| Ok(()),
            )?;
        }
        Ok(())
    }

    fn activate_with(
        &self,
        generation: GenerationToken,
        map_id: u32,
        owner: &DomainRoutingOwner,
        apply: impl FnOnce(
            u32,
            &[dae_runtime_control::DomainRoutingStateEntry],
            &[DomainRoutingIpKey],
        ) -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.switch(generation, |state| {
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
            state.map_id = Some(map_id);
            state.tracker = desired.clone();
            Ok(())
        })
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
    let mut entry = DnsCacheEntry::new(
        cache_plan.entry.deadline_unix,
        cache_plan.entry.original_deadline_unix,
    );
    entry.route_owner_key = cache_plan.entry.route_owner_key.clone();
    entry.ips = cache_plan.entry.ips.clone();
    entry.has_any_ip = cache_plan.entry.has_any_ip;
    entry.domain_bitmap.extend_from_slice(bitmap);
    Ok(Some(ResidentDnsDomainRoutingUpdatePlan {
        key: cache_plan.key.clone(),
        entry,
        ips,
    }))
}
