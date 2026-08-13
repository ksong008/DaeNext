use super::*;
pub(crate) struct AsyncVlessTlsClient {
    pub(super) engine: AsyncVlessTlsEngine,
}

pub(crate) type AsyncResidentTlsClient = AsyncVlessTlsClient;

pub(crate) enum AsyncVlessTlsEngine {
    Rustls {
        tls: tokio_rustls::client::TlsStream<AsyncResidentTcpStream>,
    },
    RealityRustls {
        tls: tokio_rustls::client::TlsStream<AsyncResidentTcpStream>,
    },
    RealityBoring {
        tls: tokio_boring::SslStream<AsyncResidentTcpStream>,
    },
    Boring {
        tls: tokio_boring::SslStream<AsyncResidentTcpStream>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentTlsProvider {
    StandardRustls,
    RealityRustls,
    RealityFingerprintBoring,
    FingerprintAwareBoring,
}

impl ResidentTlsProvider {
    pub(crate) const fn evidence_label(self) -> &'static str {
        match self {
            Self::StandardRustls => "rustls",
            Self::RealityRustls => "rustls-reality",
            Self::RealityFingerprintBoring => "reality-boringssl",
            Self::FingerprintAwareBoring => "boringssl",
        }
    }

    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Result<Self, String> {
        match proxy.execution_plan().security {
            ResidentSecurityUnderlayPlan::StandardTls
            | ResidentSecurityUnderlayPlan::InsecureTls
            | ResidentSecurityUnderlayPlan::FragmentedTls => {
                if cfg!(feature = "test-boringssl-tcp-tls") {
                    Ok(Self::FingerprintAwareBoring)
                } else {
                    Ok(Self::StandardRustls)
                }
            }
            ResidentSecurityUnderlayPlan::FingerprintAwareTls => Ok(Self::FingerprintAwareBoring),
            ResidentSecurityUnderlayPlan::RealityFingerprint => Ok(Self::RealityFingerprintBoring),
            ResidentSecurityUnderlayPlan::RealityRustls => {
                if cfg!(feature = "test-boringssl-tcp-tls") {
                    Ok(Self::RealityFingerprintBoring)
                } else {
                    Ok(Self::RealityRustls)
                }
            }
            other => Err(format!(
                "resident TLS factory cannot open security underlay {} for protocol {}",
                other.graph_label(),
                proxy.protocol
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ResidentTlsClientConfigKey {
    pub(super) flow: String,
    pub(super) alpn: Vec<String>,
    pub(super) allow_insecure: bool,
    pub(super) utls_fingerprint: Option<ResidentTlsFingerprintConfigKey>,
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
}

pub(crate) static RUSTLS_CLIENT_CONFIG_CACHE: OnceLock<
    Mutex<ResidentTlsConfigCache<ClientConfig>>,
> = OnceLock::new();
pub(crate) static BORING_CONNECTOR_CACHE: OnceLock<Mutex<ResidentTlsConfigCache<SslConnector>>> =
    OnceLock::new();

const RESIDENT_TLS_CONFIG_CACHE_MAX_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResidentTlsConfigCacheClearReport {
    pub(crate) rustls: usize,
    pub(crate) boring: usize,
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

pub(crate) fn clear_resident_tls_config_caches() -> ResidentTlsConfigCacheClearReport {
    let rustls = RUSTLS_CLIENT_CONFIG_CACHE
        .get()
        .and_then(|cache| cache.lock().ok().map(|mut cache| cache.clear()))
        .unwrap_or(0);
    let boring = BORING_CONNECTOR_CACHE
        .get()
        .and_then(|cache| cache.lock().ok().map(|mut cache| cache.clear()))
        .unwrap_or(0);
    ResidentTlsConfigCacheClearReport { rustls, boring }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_key(flow: &str) -> ResidentTlsClientConfigKey {
        ResidentTlsClientConfigKey {
            flow: flow.to_owned(),
            alpn: Vec::new(),
            allow_insecure: false,
            utls_fingerprint: None,
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
}
