use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;

use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore, DnsPacketView, DnsResponseCachePlan};
use dae_routing::RoutingMatcher;
#[cfg(test)]
use dae_runtime_control::DomainRoutingStateEntry;
use dae_runtime_control::{
    DomainRoutingDnsEvent, DomainRoutingIpKey, DomainRoutingOwner, ip_to_key,
};

use super::{TCP_SNIFF_DOMAIN_ROUTING_TTL_SECS, unix_now};

mod maintenance;
mod reload;
#[cfg(test)]
mod tests;
pub(in crate::production_runtime_owner) use self::maintenance::ResidentDnsDomainRoutingMaintenanceHandle;
#[cfg(test)]
pub(super) use self::reload::build_resident_dns_domain_routing_update_plan_from_entry;
pub(super) use self::reload::{
    ResidentDnsDomainRoutingReloadSnapshot, ResidentDnsDomainRoutingRestoreReport,
};

const TCP_SNIFF_OWNER_PREFIX: &str = "tcp-sniff";

#[cfg(test)]
type ResidentDomainRoutingMapApply =
    fn(u32, &[DomainRoutingStateEntry], &[DomainRoutingIpKey]) -> io::Result<()>;

#[derive(Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentDnsDomainRouting {
    map_id: u32,
    routing_matcher: RoutingMatcher,
    state: Mutex<ResidentDnsDomainRoutingState>,
    maintenance: maintenance::ResidentDnsDomainRoutingMaintenanceSignal,
    #[cfg(test)]
    test_apply_map: Option<ResidentDomainRoutingMapApply>,
}

#[derive(Debug)]
struct ResidentDnsDomainRoutingState {
    owner: DomainRoutingOwner,
    cache: DnsCacheStore,
    domain_bitmap: Vec<u32>,
    sniff_owners: BTreeMap<String, ResidentSniffDomainOwner>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentSniffDomainOwner {
    owner_key: String,
    domain: String,
    ip: IpAddr,
    deadline_unix: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentDnsDomainRoutingUpdatePlan {
    pub(super) key: DnsCacheKey,
    pub(super) entry: DnsCacheEntry,
    pub(super) ips: Vec<DomainRoutingIpKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentDomainRoutingIpUpdatePlan {
    pub(super) owner_key: String,
    pub(super) bitmap: [u32; 32],
    pub(super) ip: DomainRoutingIpKey,
}

impl ResidentDnsDomainRouting {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        map_id: u32,
        routing_matcher: RoutingMatcher,
    ) -> Self {
        Self {
            map_id,
            routing_matcher,
            state: Mutex::new(ResidentDnsDomainRoutingState {
                owner: DomainRoutingOwner::default(),
                cache: DnsCacheStore::default(),
                domain_bitmap: Vec::new(),
                sniff_owners: BTreeMap::new(),
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_sniffed_domain_ip(
        &self,
        domain: &str,
        ip: IpAddr,
    ) -> Result<bool, String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.sweep_expired_locked(now_unix, &mut state)?;
        let Some(plan) = build_resident_domain_routing_ip_update_plan(
            &self.routing_matcher,
            &mut state.domain_bitmap,
            TCP_SNIFF_OWNER_PREFIX,
            domain,
            ip,
        )?
        else {
            return Ok(false);
        };
        self.apply_event(
            &mut state.owner,
            DomainRoutingDnsEvent::from_keys(&plan.owner_key, &plan.bitmap, [plan.ip]),
        )
        .map_err(|err| format!("apply resident TCP sniff domain routing update: {err}"))?;
        let owner_key = plan.owner_key;
        state.sniff_owners.insert(
            owner_key.clone(),
            ResidentSniffDomainOwner {
                owner_key,
                domain: domain.trim().trim_end_matches('.').to_ascii_lowercase(),
                ip,
                deadline_unix: now_unix.saturating_add(TCP_SNIFF_DOMAIN_ROUTING_TTL_SECS),
            },
        );
        drop(state);
        self.maintenance.notify_deadline_changed();
        Ok(true)
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
        if !removed.route_owner_key.is_empty() {
            if let Err(err) = self.apply_event(
                &mut state.owner,
                DomainRoutingDnsEvent::remove(&removed.route_owner_key),
            ) {
                state.cache.restore_removed_entry(removed_key, removed);
                return Err(format!("remove resident DNS domain routing owner: {err}"));
            }
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
        let expired_sniff_owners = state
            .sniff_owners
            .iter()
            .filter(|(_, owner)| owner.deadline_unix <= now_unix)
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        for owner in expired_sniff_owners {
            self.apply_event(&mut state.owner, DomainRoutingDnsEvent::remove(&owner))
                .map_err(|err| {
                    format!("remove expired resident TCP sniff domain routing owner: {err}")
                })?;
            state.sniff_owners.remove(&owner);
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
            return owner
                .apply_dns_event_with(self.map_id, event, apply_map)
                .map(|_| ());
        }
        owner.apply_dns_event_by_id(self.map_id, event).map(|_| ())
    }

    fn apply_events<'event>(
        &self,
        owner: &mut DomainRoutingOwner,
        events: impl IntoIterator<Item = DomainRoutingDnsEvent<'event>>,
    ) -> io::Result<()> {
        #[cfg(test)]
        if let Some(apply_map) = self.test_apply_map {
            return owner
                .apply_dns_events_with(self.map_id, events, apply_map)
                .map(|_| ());
        }
        owner
            .apply_dns_events_by_id(self.map_id, events)
            .map(|_| ())
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

pub(super) fn build_resident_domain_routing_ip_update_plan(
    routing_matcher: &RoutingMatcher,
    domain_bitmap: &mut Vec<u32>,
    owner_prefix: &str,
    domain: &str,
    ip: IpAddr,
) -> Result<Option<ResidentDomainRoutingIpUpdatePlan>, String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || ip.is_unspecified() {
        return Ok(None);
    }
    let bitmap_words = routing_matcher
        .domain_bitmap_for_domain_into(domain, domain_bitmap)
        .map_err(|err| format!("match resident sniffed domain routing bitmap: {err}"))?;
    if bitmap_words.iter().all(|word| *word == 0) {
        return Ok(None);
    }
    Ok(Some(ResidentDomainRoutingIpUpdatePlan {
        owner_key: format!("{owner_prefix}|{domain}|{ip}"),
        bitmap: domain_bitmap_array(bitmap_words),
        ip: ip_to_key(ip),
    }))
}

fn domain_bitmap_array(bitmap_words: &[u32]) -> [u32; 32] {
    let mut bitmap = [0; 32];
    for (index, word) in bitmap_words.iter().copied().enumerate().take(bitmap.len()) {
        bitmap[index] = word;
    }
    bitmap
}
