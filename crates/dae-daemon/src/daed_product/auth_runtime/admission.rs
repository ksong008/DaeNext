use super::*;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ProductAuthSourceKey {
    Ip(IpAddr),
    Unknown,
}

impl From<Option<IpAddr>> for ProductAuthSourceKey {
    fn from(source: Option<IpAddr>) -> Self {
        source.map(Self::Ip).unwrap_or(Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProductAuthUsernameKey([u8; 32]);

impl ProductAuthUsernameKey {
    fn new(username: &str) -> Self {
        let digest = Sha256::digest(username.as_bytes());
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Self(key)
    }
}

#[derive(Clone, Copy, Debug)]
struct ProductAuthBackoffEntry {
    failures: u32,
    blocked_until: Instant,
    updated_at: Instant,
}

#[derive(Default)]
struct ProductAuthAdmissionState {
    in_flight_total: usize,
    in_flight_by_source: HashMap<ProductAuthSourceKey, usize>,
    in_flight_by_username: HashMap<ProductAuthUsernameKey, usize>,
    source_backoff: HashMap<ProductAuthSourceKey, ProductAuthBackoffEntry>,
    username_backoff: HashMap<ProductAuthUsernameKey, ProductAuthBackoffEntry>,
}

pub(super) struct ProductAuthAdmission {
    config: ProductAuthRuntimeConfig,
    state: Mutex<ProductAuthAdmissionState>,
}

pub(super) enum ProductAuthAdmissionRejection {
    Capacity,
    Backoff(Duration),
    Unavailable,
}

pub(super) struct ProductAuthAdmissionLease {
    admission: Arc<ProductAuthAdmission>,
    source: ProductAuthSourceKey,
    username: ProductAuthUsernameKey,
    completed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ProductAuthAdmissionSnapshot {
    pub(super) in_flight: usize,
    pub(super) active_sources: usize,
    pub(super) active_usernames: usize,
    pub(super) tracked_source_backoffs: usize,
    pub(super) tracked_username_backoffs: usize,
}

impl ProductAuthAdmission {
    pub(super) fn new(config: ProductAuthRuntimeConfig) -> Self {
        Self {
            config,
            state: Mutex::new(ProductAuthAdmissionState::default()),
        }
    }

    pub(super) fn acquire(
        self: &Arc<Self>,
        source: Option<IpAddr>,
        username: &str,
    ) -> Result<ProductAuthAdmissionLease, ProductAuthAdmissionRejection> {
        let source = ProductAuthSourceKey::from(source);
        let username = ProductAuthUsernameKey::new(username);
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProductAuthAdmissionRejection::Unavailable)?;
        prune_expired_backoffs(&mut state, now, self.config.backoff_ttl);
        if let Some(retry_after) = active_backoff(&state, source, username, now) {
            return Err(ProductAuthAdmissionRejection::Backoff(retry_after));
        }
        if state.in_flight_total >= self.config.waiter_limit
            || state.in_flight_by_source.get(&source).copied().unwrap_or(0)
                >= self.config.per_source_limit
            || state
                .in_flight_by_username
                .get(&username)
                .copied()
                .unwrap_or(0)
                >= self.config.per_username_limit
        {
            return Err(ProductAuthAdmissionRejection::Capacity);
        }
        state.in_flight_total += 1;
        *state.in_flight_by_source.entry(source).or_default() += 1;
        *state.in_flight_by_username.entry(username).or_default() += 1;
        Ok(ProductAuthAdmissionLease {
            admission: Arc::clone(self),
            source,
            username,
            completed: false,
        })
    }

    pub(super) fn snapshot(&self) -> ProductAuthAdmissionSnapshot {
        self.state
            .lock()
            .map(|state| ProductAuthAdmissionSnapshot {
                in_flight: state.in_flight_total,
                active_sources: state.in_flight_by_source.len(),
                active_usernames: state.in_flight_by_username.len(),
                tracked_source_backoffs: state.source_backoff.len(),
                tracked_username_backoffs: state.username_backoff.len(),
            })
            .unwrap_or_default()
    }

    fn finish(
        &self,
        source: ProductAuthSourceKey,
        username: ProductAuthUsernameKey,
        outcome: ProductAuthAttemptOutcome,
    ) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        release_in_flight(&mut state, source, username);
        let now = Instant::now();
        match outcome {
            ProductAuthAttemptOutcome::Success => {
                state.source_backoff.remove(&source);
                state.username_backoff.remove(&username);
            }
            ProductAuthAttemptOutcome::CredentialFailure => {
                update_backoff(&mut state.source_backoff, source, now, self.config);
                update_backoff(&mut state.username_backoff, username, now, self.config);
            }
            ProductAuthAttemptOutcome::Neutral => {}
        }
    }

    fn release(&self, source: ProductAuthSourceKey, username: ProductAuthUsernameKey) {
        if let Ok(mut state) = self.state.lock() {
            release_in_flight(&mut state, source, username);
        }
    }
}

impl ProductAuthAdmissionLease {
    pub(super) fn complete(mut self, outcome: ProductAuthAttemptOutcome) {
        self.admission.finish(self.source, self.username, outcome);
        self.completed = true;
    }
}

impl Drop for ProductAuthAdmissionLease {
    fn drop(&mut self) {
        if !self.completed {
            self.admission.release(self.source, self.username);
        }
    }
}

fn active_backoff(
    state: &ProductAuthAdmissionState,
    source: ProductAuthSourceKey,
    username: ProductAuthUsernameKey,
    now: Instant,
) -> Option<Duration> {
    [
        state.source_backoff.get(&source),
        state.username_backoff.get(&username),
    ]
    .into_iter()
    .flatten()
    .filter_map(|entry| entry.blocked_until.checked_duration_since(now))
    .max()
}

fn prune_expired_backoffs(state: &mut ProductAuthAdmissionState, now: Instant, ttl: Duration) {
    state.source_backoff.retain(|_, entry| {
        now.saturating_duration_since(entry.updated_at) < ttl || entry.blocked_until > now
    });
    state.username_backoff.retain(|_, entry| {
        now.saturating_duration_since(entry.updated_at) < ttl || entry.blocked_until > now
    });
}

fn release_in_flight(
    state: &mut ProductAuthAdmissionState,
    source: ProductAuthSourceKey,
    username: ProductAuthUsernameKey,
) {
    state.in_flight_total = state.in_flight_total.saturating_sub(1);
    decrement_or_remove(&mut state.in_flight_by_source, &source);
    decrement_or_remove(&mut state.in_flight_by_username, &username);
}

fn decrement_or_remove<K: Eq + std::hash::Hash + Copy>(map: &mut HashMap<K, usize>, key: &K) {
    let Some(count) = map.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        map.remove(key);
    }
}

fn update_backoff<K: Eq + std::hash::Hash + Copy>(
    map: &mut HashMap<K, ProductAuthBackoffEntry>,
    key: K,
    now: Instant,
    config: ProductAuthRuntimeConfig,
) {
    if !map.contains_key(&key)
        && map.len() >= config.tracked_key_capacity
        && let Some(oldest) = map
            .iter()
            .min_by_key(|(_, entry)| entry.updated_at)
            .map(|(key, _)| *key)
    {
        map.remove(&oldest);
    }
    let entry = map.entry(key).or_insert(ProductAuthBackoffEntry {
        failures: 0,
        blocked_until: now,
        updated_at: now,
    });
    if now.saturating_duration_since(entry.updated_at) >= config.backoff_ttl {
        entry.failures = 0;
    }
    entry.failures = entry.failures.saturating_add(1);
    let exponent = entry.failures.saturating_sub(1).min(16);
    let factor = 1_u32 << exponent;
    let delay = config
        .backoff_base
        .saturating_mul(factor)
        .min(config.backoff_max);
    entry.blocked_until = now.checked_add(delay).unwrap_or(now);
    entry.updated_at = now;
}
