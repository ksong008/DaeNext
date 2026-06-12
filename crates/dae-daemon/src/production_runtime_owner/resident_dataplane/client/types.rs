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
    Boring {
        tls: tokio_boring::SslStream<TokioTcpStream>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentTlsProvider {
    StandardRustls,
    RealityRustls,
    FingerprintAwareBoring,
}

impl ResidentTlsProvider {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Result<Self, String> {
        match proxy.tls.as_str() {
            "tls" => {
                if proxy.utls_fingerprint.is_some() {
                    Ok(Self::FingerprintAwareBoring)
                } else {
                    Ok(Self::StandardRustls)
                }
            }
            "reality" => Ok(Self::RealityRustls),
            other => Err(format!(
                "resident TLS factory cannot open security underlay {other} for protocol {}",
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
}
