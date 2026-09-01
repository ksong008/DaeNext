use super::*;
use serde_json::{Value, json};

pub struct AsyncVlessTlsClient {
    pub(super) engine: AsyncVlessTlsEngine,
}

pub type AsyncResidentTlsClient = AsyncVlessTlsClient;

pub(crate) enum AsyncVlessTlsEngine {
    RealityBoring {
        tls: tokio_boring::SslStream<AsyncResidentTcpStream>,
    },
    Boring {
        tls: tokio_boring::SslStream<AsyncResidentTcpStream>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ResidentTlsClientConfigKey {
    pub(super) protocol_namespace: String,
    pub(super) server_name: String,
    pub(super) flow: String,
    pub(super) alpn: Vec<String>,
    pub(super) allow_insecure: bool,
    pub(super) system_ca: Option<SystemCaIdentity>,
    pub(super) utls_fingerprint: Option<ResidentTlsFingerprintConfigKey>,
    pub(super) ech: Option<[u8; 32]>,
    pub(super) reality: Option<ResidentRealityConfigKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ResidentTlsFingerprintConfigKey {
    pub(super) source: &'static str,
    pub(super) requested: String,
    pub(super) name: String,
    pub(super) canonical: String,
    pub(super) family: String,
    pub(super) client: String,
    pub(super) randomized: bool,
    pub(super) alpn_policy: String,
    pub(super) default_alpn: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ResidentRealityConfigKey {
    pub(super) public_key: [u8; 32],
    pub(super) short_id: Vec<u8>,
    pub(super) mldsa65_verify: Option<[u8; 32]>,
}

pub(super) static BORING_CONNECTOR_CACHE: OnceLock<
    Mutex<ResidentTlsConfigCache<ResidentBoringTlsContextEntry>>,
> = OnceLock::new();

const RESIDENT_TLS_CONFIG_CACHE_MAX_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResidentTlsConfigCacheClearReport {
    pub boring: usize,
    pub boring_sessions: usize,
    pub boring_session_attempts: u64,
    pub boring_session_reused: u64,
    pub boring_session_rejected: u64,
    pub boring_session_stored: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResidentTlsConfigCacheRetainReport {
    pub before: usize,
    pub after: usize,
    pub pruned: usize,
    pub active_keys: usize,
    pub ca_identity_fallbacks: usize,
}

#[derive(Debug)]
pub(crate) struct ResidentTlsConfigCache<T> {
    entries: BTreeMap<ResidentTlsClientConfigKey, ResidentTlsConfigCacheEntry<T>>,
    next_generation: u64,
    retain_runs: u64,
    retained_pruned: u64,
    last_active_keys: usize,
    last_ca_identity_fallbacks: usize,
}

#[derive(Debug)]
struct ResidentTlsConfigCacheEntry<T> {
    value: Arc<T>,
    generation: u64,
}

impl<T> Default for ResidentTlsConfigCache<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_generation: 0,
            retain_runs: 0,
            retained_pruned: 0,
            last_active_keys: 0,
            last_ca_identity_fallbacks: 0,
        }
    }
}

impl<T> ResidentTlsConfigCache<T> {
    pub(super) fn get(&mut self, key: &ResidentTlsClientConfigKey) -> Option<Arc<T>> {
        let generation = self.touch_generation();
        let entry = self.entries.get_mut(key)?;
        entry.generation = generation;
        Some(Arc::clone(&entry.value))
    }

    pub(super) fn insert_or_get(
        &mut self,
        key: ResidentTlsClientConfigKey,
        value: Arc<T>,
    ) -> Arc<T> {
        let generation = self.touch_generation();
        let result = if let Some(entry) = self.entries.get_mut(&key) {
            entry.generation = generation;
            Arc::clone(&entry.value)
        } else {
            self.entries.insert(
                key.clone(),
                ResidentTlsConfigCacheEntry {
                    value: Arc::clone(&value),
                    generation,
                },
            );
            value
        };
        self.prune_except(&key);
        result
    }

    fn touch_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }

    fn prune_except(&mut self, keep: &ResidentTlsClientConfigKey) {
        if self.entries.len() <= RESIDENT_TLS_CONFIG_CACHE_MAX_ENTRIES {
            return;
        }
        let mut removable = self
            .entries
            .iter()
            .filter(|(key, _)| *key != keep)
            .map(|(key, entry)| (entry.generation, key.clone()))
            .collect::<Vec<_>>();
        removable.sort_by_key(|(generation, _)| *generation);
        let remove_count = self
            .entries
            .len()
            .saturating_sub(RESIDENT_TLS_CONFIG_CACHE_MAX_ENTRIES);
        for (_, key) in removable.into_iter().take(remove_count) {
            self.entries.remove(&key);
        }
    }

    fn clear(&mut self) -> usize {
        let cleared = self.entries.len();
        self.entries.clear();
        cleared
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn retain_active(
        &mut self,
        exact: &BTreeSet<ResidentTlsClientConfigKey>,
        ca_agnostic: &BTreeSet<ResidentTlsClientConfigKey>,
    ) -> ResidentTlsConfigCacheRetainReport {
        let before = self.entries.len();
        self.entries.retain(|key, _| {
            exact.contains(key)
                || (!ca_agnostic.is_empty() && {
                    let mut normalized = key.clone();
                    normalized.system_ca = None;
                    ca_agnostic.contains(&normalized)
                })
        });
        let after = self.entries.len();
        let pruned = before.saturating_sub(after);
        self.retain_runs = self.retain_runs.saturating_add(1);
        self.retained_pruned = self.retained_pruned.saturating_add(pruned as u64);
        self.last_active_keys = exact.len().saturating_add(ca_agnostic.len());
        self.last_ca_identity_fallbacks = ca_agnostic.len();
        ResidentTlsConfigCacheRetainReport {
            before,
            after,
            pruned,
            active_keys: self.last_active_keys,
            ca_identity_fallbacks: self.last_ca_identity_fallbacks,
        }
    }
}

impl ResidentTlsConfigCache<ResidentBoringTlsContextEntry> {
    fn clear_boring(&mut self) -> (usize, ResidentBoringTlsSessionStats) {
        let mut sessions = ResidentBoringTlsSessionStats::default();
        for entry in self.entries.values() {
            sessions.merge(entry.value.clear_sessions());
        }
        (self.clear(), sessions)
    }
}

pub fn clear_resident_tls_config_caches() -> ResidentTlsConfigCacheClearReport {
    let (boring, boring_sessions) = BORING_CONNECTOR_CACHE
        .get()
        .and_then(|cache| cache.lock().ok().map(|mut cache| cache.clear_boring()))
        .unwrap_or_default();
    let _ = dae_outbound_quic::system_ca::invalidate_system_ca_snapshot();
    ResidentTlsConfigCacheClearReport {
        boring,
        boring_sessions: boring_sessions.entries,
        boring_session_attempts: boring_sessions.attempted,
        boring_session_reused: boring_sessions.reused,
        boring_session_rejected: boring_sessions.rejected,
        boring_session_stored: boring_sessions.stored,
    }
}

pub fn retain_resident_tls_config_cache_for_plans<'a>(
    plans: impl IntoIterator<Item = &'a ResidentProxyPlan>,
) -> ResidentTlsConfigCacheRetainReport {
    let mut exact = BTreeSet::new();
    let mut ca_agnostic = BTreeSet::new();
    let system_ca = system_ca_snapshot();
    for plan in plans {
        collect_active_tls_keys(
            plan,
            system_ca.as_deref().ok(),
            &mut exact,
            &mut ca_agnostic,
        );
    }
    BORING_CONNECTOR_CACHE
        .get()
        .and_then(|cache| {
            cache
                .lock()
                .ok()
                .map(|mut cache| cache.retain_active(&exact, &ca_agnostic))
        })
        .unwrap_or(ResidentTlsConfigCacheRetainReport {
            active_keys: exact.len().saturating_add(ca_agnostic.len()),
            ca_identity_fallbacks: ca_agnostic.len(),
            ..ResidentTlsConfigCacheRetainReport::default()
        })
}

fn collect_active_tls_keys(
    plan: &ResidentProxyPlan,
    system_ca: Option<&SystemCaSnapshot>,
    exact: &mut BTreeSet<ResidentTlsClientConfigKey>,
    ca_agnostic: &mut BTreeSet<ResidentTlsClientConfigKey>,
) {
    let proxy_system_ca_not_required = plan.allow_insecure || plan.reality.is_some();
    collect_active_tls_key(
        ResidentTlsClientConfigKey::from_proxy(
            plan,
            (!proxy_system_ca_not_required)
                .then_some(system_ca)
                .flatten(),
        ),
        proxy_system_ca_not_required,
        system_ca.is_some(),
        exact,
        ca_agnostic,
    );
    if let Some(endpoint) = plan.xhttp_download.as_ref() {
        let endpoint_system_ca_not_required = endpoint.allow_insecure || endpoint.reality.is_some();
        collect_active_tls_key(
            ResidentTlsClientConfigKey::from_xhttp_endpoint(
                endpoint,
                (!endpoint_system_ca_not_required)
                    .then_some(system_ca)
                    .flatten(),
            ),
            endpoint_system_ca_not_required,
            system_ca.is_some(),
            exact,
            ca_agnostic,
        );
    }
    if let Some(parent) = plan.chain_parent.as_deref() {
        collect_active_tls_keys(parent, system_ca, exact, ca_agnostic);
    }
}

fn collect_active_tls_key(
    mut key: ResidentTlsClientConfigKey,
    system_ca_not_required: bool,
    system_ca_available: bool,
    exact: &mut BTreeSet<ResidentTlsClientConfigKey>,
    ca_agnostic: &mut BTreeSet<ResidentTlsClientConfigKey>,
) {
    if system_ca_not_required || system_ca_available {
        exact.insert(key);
    } else {
        key.system_ca = None;
        ca_agnostic.insert(key);
    }
}

pub fn resident_tls_config_cache_metrics() -> Value {
    let cache = BORING_CONNECTOR_CACHE
        .get()
        .and_then(|cache| cache.lock().ok())
        .map(|cache| {
            (
                cache.len(),
                cache.retain_runs,
                cache.retained_pruned,
                cache.last_active_keys,
                cache.last_ca_identity_fallbacks,
            )
        })
        .unwrap_or_default();
    json!({
        "boringEntries": cache.0,
        "maxEntries": RESIDENT_TLS_CONFIG_CACHE_MAX_ENTRIES,
        "retainRuns": cache.1,
        "prunedEntries": cache.2,
        "lastActiveKeys": cache.3,
        "lastCaIdentityFallbacks": cache.4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_key(flow: &str) -> ResidentTlsClientConfigKey {
        ResidentTlsClientConfigKey {
            protocol_namespace: "test".to_owned(),
            server_name: "example.com".to_owned(),
            flow: flow.to_owned(),
            alpn: Vec::new(),
            allow_insecure: false,
            system_ca: None,
            utls_fingerprint: None,
            ech: None,
            reality: None,
        }
    }

    #[test]
    fn resident_tls_config_cache_clear_releases_retained_entries() {
        let mut cache = ResidentTlsConfigCache::<usize>::default();
        let first = cache_key("first");
        let second = cache_key("second");

        cache.insert_or_get(first, Arc::new(1));
        cache.insert_or_get(second, Arc::new(2));

        assert_eq!(cache.clear(), 2);
        assert_eq!(cache.clear(), 0);
    }

    #[test]
    fn resident_tls_config_cache_partitions_system_ca_identity() {
        let mut cache = ResidentTlsConfigCache::<usize>::default();
        let mut first = cache_key("tls");
        first.system_ca = Some(SystemCaIdentity {
            path: "/etc/ssl/certs/ca-certificates.crt".into(),
            sha256: "first".to_owned(),
            certificate_count: 1,
        });
        let mut second = first.clone();
        second.system_ca.as_mut().unwrap().sha256 = "second".to_owned();

        cache.insert_or_get(first.clone(), Arc::new(1));
        cache.insert_or_get(second.clone(), Arc::new(2));

        assert_eq!(*cache.get(&first).unwrap(), 1);
        assert_eq!(*cache.get(&second).unwrap(), 2);
    }

    #[test]
    fn resident_tls_config_cache_partitions_protocol_and_server_name() {
        let mut cache = ResidentTlsConfigCache::<usize>::default();
        let first = cache_key("tls");
        let mut other_protocol = first.clone();
        other_protocol.protocol_namespace = "other-protocol".to_owned();
        let mut other_server = first.clone();
        other_server.server_name = "other.example".to_owned();

        cache.insert_or_get(first.clone(), Arc::new(1));
        cache.insert_or_get(other_protocol.clone(), Arc::new(2));
        cache.insert_or_get(other_server.clone(), Arc::new(3));

        assert_eq!(*cache.get(&first).unwrap(), 1);
        assert_eq!(*cache.get(&other_protocol).unwrap(), 2);
        assert_eq!(*cache.get(&other_server).unwrap(), 3);
    }

    #[test]
    fn resident_tls_config_cache_retain_removes_inactive_keys() {
        let mut cache = ResidentTlsConfigCache::<usize>::default();
        let first = cache_key("first");
        let second = cache_key("second");
        cache.insert_or_get(first.clone(), Arc::new(1));
        cache.insert_or_get(second, Arc::new(2));

        let active = std::iter::once(first).collect::<BTreeSet<_>>();
        let report = cache.retain_active(&active, &BTreeSet::new());

        assert_eq!(
            report,
            ResidentTlsConfigCacheRetainReport {
                before: 2,
                after: 1,
                pruned: 1,
                active_keys: 1,
                ca_identity_fallbacks: 0,
            }
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn resident_tls_config_cache_ca_fallback_keeps_only_matching_active_plans() {
        let mut cache = ResidentTlsConfigCache::<usize>::default();
        let mut active_old_ca = cache_key("active");
        active_old_ca.system_ca = Some(SystemCaIdentity {
            path: "/etc/ssl/certs/ca-certificates.crt".into(),
            sha256: "old".to_owned(),
            certificate_count: 1,
        });
        let mut inactive = cache_key("inactive");
        inactive.system_ca = active_old_ca.system_ca.clone();
        cache.insert_or_get(active_old_ca.clone(), Arc::new(1));
        cache.insert_or_get(inactive, Arc::new(2));

        let mut active_without_identity = active_old_ca.clone();
        active_without_identity.system_ca = None;
        let fallback = std::iter::once(active_without_identity).collect::<BTreeSet<_>>();
        let report = cache.retain_active(&BTreeSet::new(), &fallback);

        assert_eq!(report.before, 2);
        assert_eq!(report.after, 1);
        assert_eq!(report.pruned, 1);
        assert_eq!(report.ca_identity_fallbacks, 1);
        assert!(cache.get(&active_old_ca).is_some());
    }

    #[test]
    fn resident_tls_config_cache_exact_ca_identity_replaces_fallback_retention() {
        let mut cache = ResidentTlsConfigCache::<usize>::default();
        let mut old_ca = cache_key("active");
        old_ca.system_ca = Some(SystemCaIdentity {
            path: "/etc/ssl/certs/ca-certificates.crt".into(),
            sha256: "old".to_owned(),
            certificate_count: 1,
        });
        let mut current_ca = old_ca.clone();
        current_ca.system_ca.as_mut().unwrap().sha256 = "current".to_owned();
        cache.insert_or_get(old_ca, Arc::new(1));
        cache.insert_or_get(current_ca.clone(), Arc::new(2));

        let exact = std::iter::once(current_ca.clone()).collect::<BTreeSet<_>>();
        let report = cache.retain_active(&exact, &BTreeSet::new());

        assert_eq!(report.after, 1);
        assert_eq!(*cache.get(&current_ca).unwrap(), 2);
    }
}
