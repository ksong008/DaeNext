use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use dae_resident_core::ResidentDnsResourceProfile;
use dae_resident_transport::{
    ProxyDnsRequestContext, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};

use crate::unix_now;
use dae_dns::cache::DNS_CACHE_MAX_ENTRIES;
use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStats, DnsPacketView};

mod reload;
pub use self::reload::ResidentDnsRuntimeCacheSnapshot;
mod deadline_index;
use self::deadline_index::{ResidentDnsCacheDeadline, ResidentDnsCacheDeadlineIndex};

const DNS_RUNTIME_CACHE_SWEEP_INTERVAL_SECS: i64 = 60;

#[derive(Debug)]
pub struct ResidentDnsRuntimeCache {
    state: Mutex<ResidentDnsRuntimeCacheState>,
    inflight: Mutex<BTreeMap<ResidentDnsResponseCacheKey, Arc<ResidentDnsFlightState>>>,
    flight_entry_limit: usize,
    flight_follower_limit: usize,
    flight_retained_budget: Arc<ResidentDnsFlightRetainedBudget>,
}

impl Default for ResidentDnsRuntimeCache {
    fn default() -> Self {
        let resources = ResidentDnsResourceProfile::selected();
        Self {
            state: Mutex::new(ResidentDnsRuntimeCacheState::default()),
            inflight: Mutex::new(BTreeMap::new()),
            flight_entry_limit: resources.flight_entry_limit(),
            flight_follower_limit: resources.flight_followers_per_entry(),
            flight_retained_budget: Arc::new(ResidentDnsFlightRetainedBudget::new(
                resources.flight_retained_bytes(),
            )),
        }
    }
}

#[derive(Debug, Default)]
struct ResidentDnsRuntimeCacheState {
    entries: BTreeMap<ResidentDnsResponseCacheKey, ResidentDnsStoredCacheEntry>,
    deadlines: ResidentDnsCacheDeadlineIndex,
    stats: DnsCacheStats,
    next_sweep_unix: i64,
}

#[derive(Debug)]
struct ResidentDnsStoredCacheEntry {
    entry: DnsCacheEntry,
    deadline: ResidentDnsCacheDeadline,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ResidentDnsResponseCacheKey {
    base: DnsCacheKey,
    scope: ResidentDnsResponseCacheScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ResidentDnsResponseCacheScope {
    Reject,
    AsIs {
        original_dst: SocketAddr,
    },
    Upstream {
        index: u8,
        scheme: String,
        authority: String,
        path: String,
    },
}

impl ResidentDnsResponseCacheKey {
    pub fn new(base: DnsCacheKey, scope: ResidentDnsResponseCacheScope) -> Self {
        Self { base, scope }
    }

    pub fn with_base(&self, base: DnsCacheKey) -> Self {
        Self {
            base,
            scope: self.scope.clone(),
        }
    }

    fn first_for_base(base: &DnsCacheKey) -> Self {
        Self {
            base: base.clone(),
            scope: ResidentDnsResponseCacheScope::Reject,
        }
    }
}

impl ResidentDnsResponseCacheScope {
    pub fn upstream(index: u8, scheme: &str, authority: &str, path: &str) -> Self {
        Self::Upstream {
            index,
            scheme: scheme.to_owned(),
            authority: authority.to_owned(),
            path: path.to_owned(),
        }
    }
}

#[derive(Debug)]
struct ResidentDnsFlightState {
    outcome: Mutex<Option<Arc<ResidentDnsFlightOutcome>>>,
    notify: tokio::sync::Notify,
    followers: AtomicUsize,
}

impl ResidentDnsFlightState {
    fn new() -> Self {
        Self {
            outcome: Mutex::new(None),
            notify: tokio::sync::Notify::new(),
            followers: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
struct ResidentDnsFlightOutcome {
    result: Result<Arc<[u8]>, Arc<str>>,
    _retained: Option<ResidentDnsFlightRetainedLease>,
}

#[derive(Debug)]
struct ResidentDnsFlightRetainedBudget {
    current: AtomicUsize,
    limit: usize,
}

impl ResidentDnsFlightRetainedBudget {
    fn new(limit: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            limit: limit.max(1),
        }
    }

    fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<ResidentDnsFlightRetainedLease> {
        let bytes = bytes.max(1);
        self.current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= self.limit)
            })
            .ok()?;
        Some(ResidentDnsFlightRetainedLease {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

#[derive(Debug)]
struct ResidentDnsFlightRetainedLease {
    budget: Arc<ResidentDnsFlightRetainedBudget>,
    bytes: usize,
}

impl Drop for ResidentDnsFlightRetainedLease {
    fn drop(&mut self) {
        let _ = self
            .budget
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(self.bytes))
            });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentDnsFlightRole {
    Leader,
    DetachedLeader,
    Follower,
}

pub struct ResidentDnsFlightPermit<'a> {
    cache: &'a ResidentDnsRuntimeCache,
    key: ResidentDnsResponseCacheKey,
    state: Arc<ResidentDnsFlightState>,
    role: ResidentDnsFlightRole,
    published: bool,
}

impl ResidentDnsRuntimeCache {
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_flight_entry_limit(flight_entry_limit: usize) -> Self {
        let resources = ResidentDnsResourceProfile::selected();
        Self::with_flight_limits(
            flight_entry_limit,
            resources.flight_followers_per_entry(),
            resources.flight_retained_bytes(),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_flight_limits(
        flight_entry_limit: usize,
        flight_follower_limit: usize,
        flight_retained_bytes: usize,
    ) -> Self {
        Self {
            state: Mutex::new(ResidentDnsRuntimeCacheState::default()),
            inflight: Mutex::new(BTreeMap::new()),
            flight_entry_limit: flight_entry_limit.max(1),
            flight_follower_limit: flight_follower_limit.max(1),
            flight_retained_budget: Arc::new(ResidentDnsFlightRetainedBudget::new(
                flight_retained_bytes,
            )),
        }
    }

    pub fn begin_flight(
        &self,
        key: ResidentDnsResponseCacheKey,
    ) -> Result<ResidentDnsFlightPermit<'_>, String> {
        let mut inflight = self
            .inflight
            .lock()
            .map_err(|_| "resident DNS inflight lock poisoned".to_owned())?;
        let (state, role) = match inflight.get(&key) {
            Some(state) => {
                state
                    .followers
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |followers| {
                        (followers < self.flight_follower_limit).then_some(followers + 1)
                    })
                    .map_err(|_| {
                        format!(
                            "resident DNS flight follower limit reached: limit={}",
                            self.flight_follower_limit
                        )
                    })?;
                (Arc::clone(state), ResidentDnsFlightRole::Follower)
            }
            None => {
                let state = Arc::new(ResidentDnsFlightState::new());
                if inflight.len() >= self.flight_entry_limit {
                    (state, ResidentDnsFlightRole::DetachedLeader)
                } else {
                    inflight.insert(key.clone(), Arc::clone(&state));
                    (state, ResidentDnsFlightRole::Leader)
                }
            }
        };
        Ok(ResidentDnsFlightPermit {
            cache: self,
            key,
            state,
            role,
            published: false,
        })
    }

    pub fn lookup_response_into(
        &self,
        key: &ResidentDnsResponseCacheKey,
        request: &DnsPacketView<'_>,
        ignore_fixed_ttl: bool,
        out: &mut Vec<u8>,
    ) -> Result<bool, String> {
        self.lookup_response_into_with_udp_limit(key, request, ignore_fixed_ttl, false, out)
    }

    pub fn lookup_udp_response_into(
        &self,
        key: &ResidentDnsResponseCacheKey,
        request: &DnsPacketView<'_>,
        ignore_fixed_ttl: bool,
        out: &mut Vec<u8>,
    ) -> Result<bool, String> {
        self.lookup_response_into_with_udp_limit(key, request, ignore_fixed_ttl, true, out)
    }

    fn lookup_response_into_with_udp_limit(
        &self,
        key: &ResidentDnsResponseCacheKey,
        request: &DnsPacketView<'_>,
        ignore_fixed_ttl: bool,
        udp_limit: bool,
        out: &mut Vec<u8>,
    ) -> Result<bool, String> {
        out.clear();
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        lookup_scoped_response_into(
            &mut state,
            now_unix,
            key,
            request,
            ignore_fixed_ttl,
            udp_limit,
            out,
        )
    }

    pub fn lookup_key_has_any_ip(
        &self,
        key: &DnsCacheKey,
        ignore_fixed_ttl: bool,
    ) -> Result<bool, String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        sweep_expired_if_due(&mut state, now_unix);
        let first_scoped_key = ResidentDnsResponseCacheKey::first_for_base(key);
        Ok(state
            .entries
            .range(first_scoped_key..)
            .take_while(|(candidate, _)| &candidate.base == key)
            .any(|(_, stored)| {
                stored.entry.lookup_deadline(ignore_fixed_ttl) > now_unix && stored.entry.has_any_ip
            }))
    }

    pub fn insert_response(
        &self,
        now_unix: i64,
        key: ResidentDnsResponseCacheKey,
        mut entry: DnsCacheEntry,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        sweep_expired_if_due(&mut state, now_unix);
        if !state.entries.contains_key(&key) {
            evict_entries(&mut state, now_unix);
        }
        entry.route_owner_key = key.base.to_string();
        insert_cache_entry(&mut state, key, entry);
        Ok(())
    }

    pub fn remove_base_key(&self, key: &DnsCacheKey) -> Result<Vec<DnsCacheEntry>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        let first_scoped_key = ResidentDnsResponseCacheKey::first_for_base(key);
        let scoped_keys = state
            .entries
            .range(first_scoped_key..)
            .map(|(candidate, _)| candidate)
            .take_while(|candidate| &candidate.base == key)
            .cloned()
            .collect::<Vec<_>>();
        let mut removed = Vec::with_capacity(scoped_keys.len());
        for scoped_key in scoped_keys {
            if let Some(entry) = remove_cache_entry(&mut state, &scoped_key) {
                removed.push(entry);
            }
        }
        state.stats.remove_callback_total += removed.len() as u64;
        Ok(removed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn inflight_len(&self) -> usize {
        self.inflight
            .lock()
            .map(|inflight| inflight.len())
            .unwrap_or(0)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn flight_retained_bytes(&self) -> usize {
        self.flight_retained_budget.current.load(Ordering::Acquire)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn entry_len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or(0)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn deadline_len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.deadlines.len())
            .unwrap_or(0)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn stats(&self) -> dae_dns::DnsCacheStats {
        self.state
            .lock()
            .map(|state| state.stats.clone())
            .unwrap_or_default()
    }
}

fn lookup_scoped_response_into(
    state: &mut ResidentDnsRuntimeCacheState,
    now_unix: i64,
    key: &ResidentDnsResponseCacheKey,
    request: &DnsPacketView<'_>,
    ignore_fixed_ttl: bool,
    udp_limit: bool,
    out: &mut Vec<u8>,
) -> Result<bool, String> {
    let (lookup_deadline, cache_expires_at) = {
        let Some(stored) = state.entries.get(key) else {
            return Ok(false);
        };
        (
            stored.entry.lookup_deadline(ignore_fixed_ttl),
            stored.entry.cache_expires_at(),
        )
    };
    if lookup_deadline > now_unix {
        state.stats.hit_total += 1;
        let restored = state
            .entries
            .get(key)
            .and_then(|stored| stored.entry.fill_packed_response_into(request.id(), out))
            .is_some();
        if !restored {
            return Ok(false);
        }
        if udp_limit {
            let response = std::mem::take(out);
            let response =
                crate::udp_response::fit_dns_response_to_udp_request(request.packet(), response)
                    .map_err(|error| format!("fit cached DNS response to request: {error}"))?;
            out.extend_from_slice(&response);
        }
        return Ok(true);
    }
    if cache_expires_at <= now_unix {
        remove_cache_entry(state, key);
        state.stats.expired_removal_total += 1;
        state.stats.remove_callback_total += 1;
    }
    Ok(false)
}

fn evict_entries(state: &mut ResidentDnsRuntimeCacheState, now_unix: i64) {
    remove_expired_entries(state, now_unix);
    while state.entries.len() >= DNS_CACHE_MAX_ENTRIES {
        let Some(deadline) = state.deadlines.pop_first() else {
            break;
        };
        if state
            .entries
            .get(&deadline.key)
            .is_some_and(|stored| stored.deadline == deadline)
        {
            state.entries.remove(&deadline.key);
            state.stats.remove_callback_total += 1;
        }
    }
}

fn sweep_expired_if_due(state: &mut ResidentDnsRuntimeCacheState, now_unix: i64) {
    if now_unix < state.next_sweep_unix {
        return;
    }
    remove_expired_entries(state, now_unix);
    state.next_sweep_unix = now_unix.saturating_add(DNS_RUNTIME_CACHE_SWEEP_INTERVAL_SECS);
}

fn remove_expired_entries(state: &mut ResidentDnsRuntimeCacheState, now_unix: i64) {
    let mut removed = 0_usize;
    while let Some(deadline) = state.deadlines.pop_expired(now_unix) {
        if state
            .entries
            .get(&deadline.key)
            .is_some_and(|stored| stored.deadline == deadline)
        {
            state.entries.remove(&deadline.key);
            removed += 1;
        }
    }
    state.stats.expired_removal_total += removed as u64;
    state.stats.remove_callback_total += removed as u64;
}

fn insert_cache_entry(
    state: &mut ResidentDnsRuntimeCacheState,
    key: ResidentDnsResponseCacheKey,
    entry: DnsCacheEntry,
) {
    if let Some(previous) = state.entries.remove(&key) {
        state.deadlines.remove(&previous.deadline);
    }
    let deadline = state
        .deadlines
        .insert(key.clone(), entry.cache_expires_at());
    state
        .entries
        .insert(key, ResidentDnsStoredCacheEntry { entry, deadline });
}

fn remove_cache_entry(
    state: &mut ResidentDnsRuntimeCacheState,
    key: &ResidentDnsResponseCacheKey,
) -> Option<DnsCacheEntry> {
    let stored = state.entries.remove(key)?;
    state.deadlines.remove(&stored.deadline);
    Some(stored.entry)
}

impl ResidentDnsFlightPermit<'_> {
    pub fn is_leader(&self) -> bool {
        matches!(
            self.role,
            ResidentDnsFlightRole::Leader | ResidentDnsFlightRole::DetachedLeader
        )
    }

    pub async fn wait(
        &self,
        context: ProxyDnsRequestContext,
        request_id: u16,
    ) -> Result<Vec<u8>, String> {
        if self.is_leader() {
            return Err("resident DNS flight leader cannot wait for itself".to_owned());
        }
        loop {
            let notified = self.state.notify.notified();
            if let Some(outcome) = self.outcome()? {
                return restore_flight_response_id(outcome, request_id);
            }
            context
                .run(
                    ProxyDnsRequestStage::Queued,
                    ProxyDnsRequestFailure::Cancelled,
                    async {
                        notified.await;
                        Ok::<(), std::convert::Infallible>(())
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }
    }

    pub fn publish(&mut self, result: Result<&[u8], &str>) -> Result<(), String> {
        if !self.is_leader() {
            return Err("resident DNS flight follower cannot publish".to_owned());
        }
        let result = result.map(Arc::<[u8]>::from).map_err(Arc::<str>::from);
        let retained_bytes = match &result {
            Ok(response) => response.len(),
            Err(error) => error.len(),
        };
        let (result, retained) = match self
            .cache
            .flight_retained_budget
            .try_reserve(retained_bytes)
        {
            Some(retained) => (result, Some(retained)),
            None => (
                Err(Arc::<str>::from(
                    "resident DNS flight retained response byte limit reached",
                )),
                None,
            ),
        };
        let outcome = Arc::new(ResidentDnsFlightOutcome {
            result,
            _retained: retained,
        });
        let published_error = outcome.result.as_ref().err().map(ToString::to_string);
        self.publish_outcome(outcome)?;
        match published_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn outcome(&self) -> Result<Option<Arc<ResidentDnsFlightOutcome>>, String> {
        self.state
            .outcome
            .lock()
            .map(|outcome| outcome.clone())
            .map_err(|_| "resident DNS flight outcome lock poisoned".to_owned())
    }

    fn publish_outcome(&mut self, outcome: Arc<ResidentDnsFlightOutcome>) -> Result<(), String> {
        {
            let mut current = self
                .state
                .outcome
                .lock()
                .map_err(|_| "resident DNS flight outcome lock poisoned".to_owned())?;
            if current.is_some() {
                return Err("resident DNS flight outcome was already published".to_owned());
            }
            *current = Some(outcome);
        }
        self.published = true;
        self.state.notify.notify_waiters();
        self.remove_registry_entry();
        Ok(())
    }

    fn remove_registry_entry(&self) {
        if self.role == ResidentDnsFlightRole::DetachedLeader {
            return;
        }
        if let Ok(mut inflight) = self.cache.inflight.lock()
            && inflight
                .get(&self.key)
                .is_some_and(|current| Arc::ptr_eq(current, &self.state))
        {
            inflight.remove(&self.key);
        }
    }
}

fn restore_flight_response_id(
    outcome: Arc<ResidentDnsFlightOutcome>,
    request_id: u16,
) -> Result<Vec<u8>, String> {
    let response = outcome.result.as_ref().map_err(|error| error.to_string())?;
    if response.len() < 2 {
        return Err("resident DNS flight response is too short to restore request id".to_owned());
    }
    let mut response = response.to_vec();
    response[0..2].copy_from_slice(&request_id.to_be_bytes());
    Ok(response)
}

impl Drop for ResidentDnsFlightPermit<'_> {
    fn drop(&mut self) {
        if self.role == ResidentDnsFlightRole::Follower {
            let _ = self.state.followers.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |followers| Some(followers.saturating_sub(1)),
            );
        }
        if !self.is_leader() || self.published {
            return;
        }
        if let Ok(mut outcome) = self.state.outcome.lock()
            && outcome.is_none()
        {
            *outcome = Some(Arc::new(ResidentDnsFlightOutcome {
                result: Err(Arc::<str>::from(
                    "resident DNS flight leader ended before publishing a result",
                )),
                _retained: None,
            }));
        }
        self.state.notify.notify_waiters();
        self.remove_registry_entry();
    }
}
