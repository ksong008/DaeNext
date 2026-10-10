use super::*;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock, Weak};

struct Entry {
    policy: BoringQuicClientPolicy,
    ca: Option<SystemCaIdentity>,
    sessions: Option<Weak<dyn quinn_boring::SessionCache>>,
    config: quinn::ClientConfig,
}
#[cfg(test)]
thread_local! { static BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
static CONFIGS: OnceLock<Mutex<VecDeque<Entry>>> = OnceLock::new();

pub(super) fn client_config(
    policy: &BoringQuicClientPolicy,
    transport: Arc<quinn::TransportConfig>,
    sessions: Option<BoringQuicSessionCache>,
    ca: Option<Arc<SystemCaSnapshot>>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let ca = if verification_requires_system_roots(&policy.verification) {
        Some(match ca {
            Some(ca) => ca,
            None => system_ca_snapshot().map_err(|error| {
                OutboundError::BadSharedTransport(format!(
                    "load BoringSSL QUIC system CA bundle: {error}"
                ))
            })?,
        })
    } else {
        None
    };
    let ca_identity = ca.as_ref().map(|ca| ca.identity());
    let configs = CONFIGS.get_or_init(|| Mutex::new(VecDeque::new()));
    {
        let mut cache = configs.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(index) = cache.iter().position(|entry| {
            &entry.policy == policy
                && entry.ca.as_ref() == ca_identity
                && match (&entry.sessions, &sessions) {
                    (None, None) => true,
                    (Some(old), Some(new)) => {
                        old.upgrade().is_some_and(|old| Arc::ptr_eq(&old, new))
                    }
                    _ => false,
                }
        }) {
            let entry = cache.remove(index).expect("cached index");
            let mut config = entry.config.clone();
            cache.push_back(entry);
            // Congestion factories and transport limits belong to this caller.
            config.transport_config(transport);
            return Ok(config);
        }
    }
    #[cfg(test)]
    BUILDS.with(|count| count.set(count.get() + 1));
    let crypto =
        build_boring_quic_client_crypto_with_session_cache(policy, sessions.clone(), ca.clone())?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport);
    let entry = Entry {
        policy: policy.clone(),
        ca: ca_identity.cloned(),
        sessions: sessions.as_ref().map(Arc::downgrade),
        config: config.clone(),
    };
    let retired = {
        let mut cache = configs.lock().unwrap_or_else(|error| error.into_inner());
        let retired = if cache.len() >= 64 {
            cache.pop_front()
        } else {
            None
        };
        cache.push_back(entry);
        retired
    };
    drop(retired);
    Ok(config)
}

#[cfg(test)]
mod tests;
