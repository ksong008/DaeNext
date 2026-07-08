use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

#[derive(Debug, Default)]
pub(super) struct ResidentDnsIpversionPreferenceRegistry {
    waiters: Mutex<BTreeMap<DnsCacheKey, Vec<tokio::sync::oneshot::Sender<bool>>>>,
}

impl ResidentDnsIpversionPreferenceRegistry {
    pub(super) async fn wait_for_preferred(
        &self,
        key: &DnsCacheKey,
        timeout: Duration,
    ) -> Option<bool> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Ok(mut waiters) = self.waiters.lock() {
            waiters.entry(key.clone()).or_default().push(tx);
        } else {
            return None;
        }
        match time::timeout(timeout, rx).await {
            Ok(Ok(has_ip)) => Some(has_ip),
            _ => {
                self.remove_closed_waiters(&key);
                None
            }
        }
    }

    pub(super) fn notify_preferred(&self, key: &DnsCacheKey, has_ip: bool) {
        let waiters = self
            .waiters
            .lock()
            .ok()
            .and_then(|mut waiters| waiters.remove(key))
            .unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(has_ip);
        }
    }

    fn remove_closed_waiters(&self, key: &DnsCacheKey) {
        if let Ok(mut waiters) = self.waiters.lock()
            && let Some(entries) = waiters.get_mut(key)
        {
            entries.retain(|waiter| !waiter.is_closed());
            if entries.is_empty() {
                waiters.remove(key);
            }
        }
    }
}

pub(super) fn dns_ipversion_preference_wait_timeout() -> Duration {
    RESIDENT_IDLE_SLEEP
}
