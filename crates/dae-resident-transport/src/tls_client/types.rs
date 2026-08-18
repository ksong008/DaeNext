use super::*;
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

#[derive(Debug)]
pub(crate) struct ResidentTlsConfigCache<T> {
    entries: BTreeMap<ResidentTlsClientConfigKey, ResidentTlsConfigCacheEntry<T>>,
    next_generation: u64,
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
    let _ = dae_outbound::shared_transport::invalidate_system_ca_snapshot();
    ResidentTlsConfigCacheClearReport {
        boring,
        boring_sessions: boring_sessions.entries,
        boring_session_attempts: boring_sessions.attempted,
        boring_session_reused: boring_sessions.reused,
        boring_session_rejected: boring_sessions.rejected,
        boring_session_stored: boring_sessions.stored,
    }
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
}
