use super::*;
use serde_json::{Value, json};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResidentDnsReloadSnapshot {
    response_cache: ResidentDnsRuntimeCacheSnapshot,
    domain_routing: Option<ResidentDnsDomainRoutingReloadSnapshot>,
}

#[derive(Debug)]
pub struct ResidentDnsReloadHandle {
    response_cache: Arc<ResidentDnsRuntimeCache>,
    domain_routing: Option<Arc<ResidentDnsDomainRouting>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResidentDnsReloadRestoreReport {
    response_cache_entries: usize,
    domain_routing: Option<ResidentDnsDomainRoutingRestoreReport>,
}

impl ResidentDnsReloadSnapshot {
    pub fn entry_count(&self) -> usize {
        self.response_cache.entry_count()
            + self
                .domain_routing
                .as_ref()
                .map(ResidentDnsDomainRoutingReloadSnapshot::entry_count)
                .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count() == 0
    }
}

impl ResidentDnsReloadHandle {
    pub fn new(
        response_cache: Arc<ResidentDnsRuntimeCache>,
        domain_routing: Option<Arc<ResidentDnsDomainRouting>>,
    ) -> Self {
        Self {
            response_cache,
            domain_routing,
        }
    }

    pub fn snapshot_for_reload(&self) -> Result<ResidentDnsReloadSnapshot, String> {
        let response_cache = self.response_cache.snapshot_for_reload()?;
        let domain_routing = self
            .domain_routing
            .as_ref()
            .map(|domain_routing| domain_routing.snapshot_for_reload())
            .transpose()?;
        Ok(ResidentDnsReloadSnapshot {
            response_cache,
            domain_routing,
        })
    }

    pub fn cache_entry_counts(&self) -> Result<(usize, usize), String> {
        let response_cache_entries = self.response_cache.entry_count()?;
        let domain_routing_entries = self
            .domain_routing
            .as_ref()
            .map(|domain_routing| domain_routing.cache_entry_count())
            .transpose()?
            .unwrap_or(0);
        Ok((response_cache_entries, domain_routing_entries))
    }
}

impl ResidentDnsReloadRestoreReport {
    pub fn restore_into(
        plan: &ResidentDnsPlan,
        snapshot: &ResidentDnsReloadSnapshot,
    ) -> Result<Self, String> {
        let response_cache_entries = plan
            .cache
            .restore_reload_snapshot(&snapshot.response_cache)?;
        let domain_routing = match (
            plan.domain_routing.as_ref(),
            snapshot.domain_routing.as_ref(),
        ) {
            (Some(domain_routing), Some(snapshot)) => {
                Some(domain_routing.restore_reload_snapshot(snapshot)?)
            }
            _ => None,
        };
        Ok(Self {
            response_cache_entries,
            domain_routing,
        })
    }

    pub fn to_value(&self) -> Value {
        let domain_routing = self
            .domain_routing
            .as_ref()
            .map(|report| {
                json!({
                    "status": "pass",
                    "acceptedResponseEntries": report.accepted_response_entries,
                    "sniffedDomainEntries": report.sniffed_domain_entries,
                    "skippedExpiredEntries": report.skipped_expired_entries,
                    "skippedUnmatchedEntries": report.skipped_unmatched_entries,
                })
            })
            .unwrap_or_else(|| {
                json!({
                    "status": "skipped",
                    "reason": "domain routing snapshot unavailable or runtime domain_routing_map disabled",
                })
            });
        json!({
            "status": "pass",
            "responseCacheEntries": self.response_cache_entries,
            "domainRouting": domain_routing,
        })
    }
}
