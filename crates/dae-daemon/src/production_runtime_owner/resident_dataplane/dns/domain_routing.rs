use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;

use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore, DnsPacketView, DnsResponseCachePlan};
use dae_routing::RoutingMatcher;
use dae_runtime_control::{
    DomainRoutingDnsEvent, DomainRoutingIpKey, DomainRoutingOwner, ip_to_key,
};

use super::{TCP_SNIFF_DOMAIN_ROUTING_TTL_SECS, unix_now};

#[derive(Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentDnsDomainRouting {
    map_id: u32,
    routing_matcher: RoutingMatcher,
    state: Mutex<ResidentDnsDomainRoutingState>,
}

#[derive(Debug)]
struct ResidentDnsDomainRoutingState {
    owner: DomainRoutingOwner,
    cache: DnsCacheStore,
    domain_bitmap: Vec<u32>,
    sniff_owners: BTreeMap<String, i64>,
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
        state
            .owner
            .apply_dns_event_by_id(
                self.map_id,
                DomainRoutingDnsEvent::from_keys(
                    &plan.entry.route_owner_key,
                    &plan.entry.domain_bitmap,
                    plan.ips.iter().copied(),
                ),
            )
            .map_err(|err| format!("apply resident DNS domain routing response: {err}"))?;
        state
            .cache
            .insert_without_route_owner_key(now_unix, plan.key, plan.entry);
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
            "tcp-sniff",
            domain,
            ip,
        )?
        else {
            return Ok(false);
        };
        state
            .owner
            .apply_dns_event_by_id(
                self.map_id,
                DomainRoutingDnsEvent::from_keys(&plan.owner_key, &plan.bitmap, [plan.ip]),
            )
            .map_err(|err| format!("apply resident TCP sniff domain routing update: {err}"))?;
        state.sniff_owners.insert(
            plan.owner_key,
            now_unix.saturating_add(TCP_SNIFF_DOMAIN_ROUTING_TTL_SECS),
        );
        Ok(true)
    }

    pub(super) fn remove_request(&self, request: &DnsPacketView<'_>) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        let Some(removed) = state
            .cache
            .remove_packet_question(
                &request
                    .questions()
                    .next()
                    .ok_or_else(|| "DNS request has no question".to_owned())?,
            )
            .map_err(|err| format!("remove resident DNS domain routing cache entry: {err}"))?
        else {
            return Ok(());
        };
        if removed.route_owner_key.is_empty() {
            return Ok(());
        }
        state
            .owner
            .apply_dns_event_by_id(
                self.map_id,
                DomainRoutingDnsEvent::remove(&removed.route_owner_key),
            )
            .map_err(|err| format!("remove resident DNS domain routing owner: {err}"))?;
        Ok(())
    }

    fn sweep_expired_locked(
        &self,
        now_unix: i64,
        state: &mut ResidentDnsDomainRoutingState,
    ) -> Result<(), String> {
        for expired in state.cache.sweep(now_unix) {
            if expired.route_owner_key.is_empty() {
                continue;
            }
            state
                .owner
                .apply_dns_event_by_id(
                    self.map_id,
                    DomainRoutingDnsEvent::remove(&expired.route_owner_key),
                )
                .map_err(|err| {
                    format!("remove expired resident DNS domain routing owner: {err}")
                })?;
        }
        let expired_sniff_owners = state
            .sniff_owners
            .iter()
            .filter(|(_, deadline)| **deadline <= now_unix)
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        for owner in expired_sniff_owners {
            state
                .owner
                .apply_dns_event_by_id(self.map_id, DomainRoutingDnsEvent::remove(&owner))
                .map_err(|err| {
                    format!("remove expired resident TCP sniff domain routing owner: {err}")
                })?;
            state.sniff_owners.remove(&owner);
        }
        Ok(())
    }
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
