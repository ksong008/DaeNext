use super::*;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const DOMAIN_ROUTING_MAINTENANCE_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct ResidentDnsDomainRoutingMaintenanceState {
    generation: u64,
    started: bool,
    stopped: bool,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ResidentDnsDomainRoutingMaintenanceSignal {
    shared: Arc<(Mutex<ResidentDnsDomainRoutingMaintenanceState>, Condvar)>,
}

#[derive(Debug)]
pub(crate) struct ResidentDnsDomainRoutingMaintenanceHandle {
    signal: ResidentDnsDomainRoutingMaintenanceSignal,
}

impl ResidentDnsDomainRoutingMaintenanceSignal {
    pub(super) fn notify_deadline_changed(&self) {
        let (state, wake) = &*self.shared;
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.generation = state.generation.wrapping_add(1);
        wake.notify_one();
    }

    fn begin(&self) -> Result<(), String> {
        let (state, _) = &*self.shared;
        let mut state = state
            .lock()
            .map_err(|_| "resident DNS domain routing maintenance lock poisoned".to_owned())?;
        if state.started {
            return Err("resident DNS domain routing maintenance already started".to_owned());
        }
        state.started = true;
        Ok(())
    }

    fn generation(&self) -> Option<u64> {
        let (state, _) = &*self.shared;
        let state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (!state.stopped).then_some(state.generation)
    }

    fn wait_for_change(&self, generation: u64, timeout: Option<Duration>) -> bool {
        let (state, wake) = &*self.shared;
        let state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.stopped || state.generation != generation {
            return state.stopped;
        }
        let state = match timeout {
            Some(timeout) if timeout.is_zero() => state,
            Some(timeout) => {
                let result = wake.wait_timeout_while(state, timeout, |state| {
                    !state.stopped && state.generation == generation
                });
                match result {
                    Ok((state, _)) => state,
                    Err(poisoned) => poisoned.into_inner().0,
                }
            }
            None => {
                let result = wake.wait_while(state, |state| {
                    !state.stopped && state.generation == generation
                });
                result.unwrap_or_else(|poisoned| poisoned.into_inner())
            }
        };
        state.stopped
    }

    fn stop(&self) {
        let (state, wake) = &*self.shared;
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.stopped = true;
        wake.notify_all();
    }
}

impl ResidentDnsDomainRoutingMaintenanceHandle {
    pub(crate) fn stop(&self) {
        self.signal.stop();
    }
}

impl Drop for ResidentDnsDomainRoutingMaintenanceHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

impl ResidentDnsDomainRouting {
    pub(crate) fn start_maintenance(
        self: &Arc<Self>,
    ) -> Result<(ResidentDnsDomainRoutingMaintenanceHandle, JoinHandle<()>), String> {
        self.maintenance.begin()?;
        let signal = self.maintenance.clone();
        let domain_routing = Arc::clone(self);
        let handle = thread::spawn(move || run_domain_routing_maintenance(domain_routing, signal));
        Ok((
            ResidentDnsDomainRoutingMaintenanceHandle {
                signal: self.maintenance.clone(),
            },
            handle,
        ))
    }

    fn next_expiry_unix(&self) -> Result<Option<i64>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        Ok(state.cache.next_expiry_unix())
    }

    fn sweep_expired(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.sweep_expired_locked(unix_now(), &mut state)
    }
}

fn run_domain_routing_maintenance(
    domain_routing: Arc<ResidentDnsDomainRouting>,
    signal: ResidentDnsDomainRoutingMaintenanceSignal,
) {
    loop {
        let Some(generation) = signal.generation() else {
            return;
        };
        let next_expiry = match domain_routing.next_expiry_unix() {
            Ok(next_expiry) => next_expiry,
            Err(_) => {
                if signal.wait_for_change(generation, Some(DOMAIN_ROUTING_MAINTENANCE_RETRY_DELAY))
                {
                    return;
                }
                continue;
            }
        };
        let now_unix = unix_now();
        if next_expiry.is_some_and(|deadline| deadline <= now_unix) {
            if domain_routing.sweep_expired().is_err()
                && signal.wait_for_change(generation, Some(DOMAIN_ROUTING_MAINTENANCE_RETRY_DELAY))
            {
                return;
            }
            continue;
        }
        let timeout = next_expiry.map(|deadline| {
            Duration::from_secs(
                deadline
                    .saturating_sub(now_unix)
                    .try_into()
                    .unwrap_or(u64::MAX),
            )
        });
        if signal.wait_for_change(generation, timeout) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_routing::RoutingMatcher;
    use std::time::Instant;

    const TEST_WAIT_LIMIT: Duration = Duration::from_secs(3);
    const TEST_POLL_INTERVAL: Duration = Duration::from_millis(10);
    const TEST_STOP_LIMIT: Duration = Duration::from_millis(500);

    fn test_domain_routing_with_apply(
        apply_event: ResidentDomainRoutingMapApply,
    ) -> Arc<ResidentDnsDomainRouting> {
        let matcher = RoutingMatcher::from_typed_sets(Vec::new(), Vec::new(), Vec::new()).unwrap();
        let mut domain_routing = ResidentDnsDomainRouting::new(1, matcher);
        domain_routing.test_apply_map = Some(apply_event);
        Arc::new(domain_routing)
    }

    fn test_domain_routing() -> Arc<ResidentDnsDomainRouting> {
        test_domain_routing_with_apply(apply_resident_domain_routing_event_in_memory)
    }

    fn insert_test_owner(
        domain_routing: &ResidentDnsDomainRouting,
        name: &str,
        deadline_unix: i64,
    ) {
        let key = DnsCacheKey::new(name, 1, 1);
        let owner_key = key.to_string();
        let ip = ip_to_key("192.0.2.30".parse().unwrap());
        let mut state = domain_routing.state.lock().unwrap();
        state
            .owner
            .apply_dns_event_with(
                domain_routing.map_id,
                DomainRoutingDnsEvent::from_keys(&owner_key, &[1], [ip]),
                |_, _, _| Ok(()),
            )
            .map(|_| ())
            .unwrap();
        let mut entry = DnsCacheEntry::new(deadline_unix, deadline_unix);
        entry.route_owner_key = owner_key;
        entry.ips.push("192.0.2.30".parse().unwrap());
        state
            .cache
            .insert_without_route_owner_key(unix_now(), key, entry);
        drop(state);
        domain_routing.maintenance.notify_deadline_changed();
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(started.elapsed() < TEST_WAIT_LIMIT, "condition timed out");
            thread::sleep(TEST_POLL_INTERVAL);
        }
    }

    #[test]
    fn quiet_period_expiry_removes_cache_and_owner() {
        let domain_routing = test_domain_routing();
        insert_test_owner(
            &domain_routing,
            "quiet.example",
            unix_now().saturating_add(1),
        );
        let (maintenance, thread) = domain_routing.start_maintenance().unwrap();

        wait_until(|| {
            let state = domain_routing.state.lock().unwrap();
            state.cache.is_empty() && state.owner.tracker().owner_count() == 0
        });

        maintenance.stop();
        thread.join().unwrap();
    }

    #[test]
    fn earlier_deadline_wakes_existing_wait() {
        let domain_routing = test_domain_routing();
        insert_test_owner(
            &domain_routing,
            "later.example",
            unix_now().saturating_add(3600),
        );
        let (maintenance, thread) = domain_routing.start_maintenance().unwrap();
        thread::sleep(TEST_POLL_INTERVAL);
        insert_test_owner(
            &domain_routing,
            "earlier.example",
            unix_now().saturating_add(1),
        );

        wait_until(|| {
            let state = domain_routing.state.lock().unwrap();
            state.cache.len() == 1 && state.owner.tracker().owner_count() == 1
        });

        maintenance.stop();
        thread.join().unwrap();
    }

    #[test]
    fn stop_interrupts_long_deadline_wait() {
        let domain_routing = test_domain_routing();
        insert_test_owner(
            &domain_routing,
            "long.example",
            unix_now().saturating_add(3600),
        );
        let (maintenance, thread) = domain_routing.start_maintenance().unwrap();
        thread::sleep(TEST_POLL_INTERVAL);

        let started = Instant::now();
        maintenance.stop();
        thread.join().unwrap();
        assert!(started.elapsed() < TEST_STOP_LIMIT);
    }

    #[test]
    fn failed_expiry_removal_keeps_cache_and_owner_for_retry() {
        fn reject_map_update(
            _: u32,
            _: &[DomainRoutingStateEntry],
            _: &[DomainRoutingIpKey],
        ) -> io::Result<()> {
            Err(io::Error::other("injected domain routing map failure"))
        }

        let domain_routing = test_domain_routing_with_apply(reject_map_update);
        insert_test_owner(
            &domain_routing,
            "retry.example",
            unix_now().saturating_sub(1),
        );

        let err = domain_routing.sweep_expired().unwrap_err();
        assert!(err.contains("injected domain routing map failure"));
        let state = domain_routing.state.lock().unwrap();
        assert_eq!(state.cache.len(), 1);
        assert_eq!(state.owner.tracker().owner_count(), 1);
    }
}
