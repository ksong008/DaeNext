use super::*;
use dae_resident_transport::ProxyDnsRequestContext;
use std::sync::Condvar;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn context() -> ProxyDnsRequestContext {
    ProxyDnsRequestContext::from_timeout(Duration::from_secs(3))
}

fn seed_expired_owners(routing: &ResidentDnsDomainRouting, count: usize) {
    let mut state = routing.state.lock().unwrap();
    state.cache = DnsCacheStore::new(count + 16);
    let now = unix_now();
    for id in 0..count {
        let key = DnsCacheKey::new(format!("expired-{id}.example.test"), 1, 1);
        let owner_key = key.to_string();
        let ip = ip_to_key(format!("192.0.{}.{}", id / 256, id % 256).parse().unwrap());
        state
            .owner
            .apply_dns_event_with(
                routing.map_id,
                DomainRoutingDnsEvent::from_keys(&owner_key, &[1], [ip]),
                |_, _, _| Ok(()),
            )
            .unwrap();
        let mut entry = DnsCacheEntry::new(now - 1, now - 1);
        entry.route_owner_key = owner_key;
        state
            .cache
            .insert_without_route_owner_key(now - 10, key, entry);
    }
}

#[test]
fn accepting_response_and_reading_metrics_leave_expiry_to_maintenance() {
    fn fail_expiry(
        _: u32,
        _: &[DomainRoutingStateEntry],
        deletes: &[DomainRoutingIpKey],
    ) -> io::Result<()> {
        if deletes.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other("injected expiry removal failure"))
        }
    }
    let mut routing = matching_domain_routing();
    seed_expired_owners(&routing, 256);
    routing.test_apply_map = Some(fail_expiry);
    assert_eq!(routing.cache_entry_count().unwrap(), 0);
    assert_eq!(routing.state.lock().unwrap().cache.len(), 256);
    routing
        .record_accepted_response(&response_plan(
            "live.example.test",
            "203.0.113.1",
            unix_now() + 300,
        ))
        .unwrap();
    assert_eq!(routing.cache_entry_count().unwrap(), 1);
    assert_eq!(routing.state.lock().unwrap().cache.len(), 257);
    assert!(routing.sweep_expired_batch(unix_now()).is_err());
    assert_eq!(
        routing.state.lock().unwrap().owner.tracker().owner_count(),
        257
    );
}

#[derive(Default)]
struct ApplyGate {
    entered: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}

impl ApplyGate {
    fn wait(&self) -> io::Result<()> {
        self.entered.store(true, Ordering::Release);
        let (guard, timeout) = self
            .wake
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(2),
                |released| !*released,
            )
            .unwrap();
        drop(guard);
        if timeout.timed_out() {
            return Err(io::Error::other("test did not release blocking apply gate"));
        }
        Ok(())
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

struct ReleaseOnDrop(Arc<ApplyGate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn slow_maintenance_keeps_runtime_and_metrics_responsive_and_yields_to_commits() {
    static GATE: Mutex<Option<Arc<ApplyGate>>> = Mutex::new(None);
    fn gated_apply(
        _: u32,
        _: &[DomainRoutingStateEntry],
        _: &[DomainRoutingIpKey],
    ) -> io::Result<()> {
        let gate = GATE.lock().unwrap().as_ref().unwrap().clone();
        gate.wait()
    }
    let gate = Arc::new(ApplyGate::default());
    let _release = ReleaseOnDrop(Arc::clone(&gate));
    *GATE.lock().unwrap() = Some(Arc::clone(&gate));
    let mut routing = matching_domain_routing();
    seed_expired_owners(&routing, 512);
    routing.test_apply_map = Some(gated_apply);
    let routing = Arc::new(routing);
    let (maintenance, thread) = routing.start_maintenance().unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !gate.entered.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    let unpublished_expired = Arc::new(AtomicUsize::new(0));
    let accepted = {
        let routing = Arc::clone(&routing);
        let observed = Arc::clone(&unpublished_expired);
        tokio::spawn(async move {
            let cache = Arc::clone(&routing);
            routing
                .record_accepted_response_async(
                    response_plan("live.example.test", "203.0.113.1", unix_now() + 300),
                    context(),
                    move || {
                        observed.store(
                            cache.state.lock().unwrap().cache.len() - 1,
                            Ordering::Release,
                        );
                        Ok(())
                    },
                )
                .await
        })
    };
    let rejected = {
        let routing = Arc::clone(&routing);
        tokio::spawn(async move {
            routing
                .remove_key_async(
                    DnsCacheKey::new("absent.example.test", 1, 1),
                    context(),
                    || Ok(()),
                )
                .await
        })
    };
    let heartbeat = Instant::now();
    assert_eq!(routing.cache_entry_count().unwrap(), 0);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(heartbeat.elapsed() < Duration::from_millis(500));
    assert!(!accepted.is_finished());
    assert!(!rejected.is_finished());
    gate.release();
    tokio::time::timeout(Duration::from_secs(1), accepted)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), rejected)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        unpublished_expired.load(Ordering::Acquire) > 0,
        "foreground commit drained expiry backlog"
    );
    maintenance.stop();
    tokio::task::spawn_blocking(move || thread.join().unwrap())
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn admission_timeout_and_cancellation_do_not_commit_or_leak_a_slot() {
    let routing = Arc::new(matching_domain_routing());
    let admission = Arc::clone(&routing.dispatch).lock_owned().await;
    let published = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&published);
    assert!(
        routing
            .record_accepted_response_async(
                response_plan("expired-wait.example.test", "203.0.113.1", unix_now() + 300),
                ProxyDnsRequestContext::from_timeout(Duration::from_millis(20)),
                move || {
                    flag.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .await
            .is_err()
    );
    let cancelled = {
        let routing = Arc::clone(&routing);
        tokio::spawn(async move {
            routing
                .record_accepted_response_async(
                    response_plan("cancelled.example.test", "203.0.113.2", unix_now() + 300),
                    context(),
                    || panic!("cancelled transaction published"),
                )
                .await
        })
    };
    tokio::task::yield_now().await;
    assert!(!cancelled.is_finished());
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    drop(admission);
    routing
        .record_accepted_response_async(
            response_plan("live.example.test", "203.0.113.3", unix_now() + 300),
            context(),
            || Ok(()),
        )
        .await
        .unwrap();
    assert!(!published.load(Ordering::Acquire));
    assert_eq!(
        routing.state.lock().unwrap().owner.tracker().owner_count(),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn reject_invalidates_an_accepted_response_waiting_for_admission() {
    let routing = Arc::new(matching_domain_routing());
    let admission = Arc::clone(&routing.dispatch).lock_owned().await;
    let plan = response_plan("rejected.example.test", "203.0.113.1", unix_now() + 300);
    let key = plan.key.clone();
    let mut queued =
        Box::pin(routing.record_accepted_response_async(plan, context(), || {
            panic!("rejected response published")
        }));
    tokio::select! {
        biased;
        result = &mut queued => panic!("transaction bypassed admission: {result:?}"),
        _ = tokio::task::yield_now() => {}
    }
    // Model a synchronous control-plane invalidation while the async response
    // is queued. Its revision must have been registered before admission.
    {
        let mutation = routing.lock_mutation().unwrap();
        routing
            .remove_key_locked(&key, || Ok(()), &mutation)
            .unwrap();
    }
    drop(admission);
    queued.await.unwrap();
    assert_eq!(
        routing.state.lock().unwrap().owner.tracker().owner_count(),
        0
    );
}

#[test]
fn timed_out_blocking_job_keeps_admission_until_it_exits_without_publishing() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let gate = Arc::new(ApplyGate::default());
    let _release = ReleaseOnDrop(Arc::clone(&gate));
    runtime.block_on(async {
        let blocker = {
            let gate = Arc::clone(&gate);
            tokio::task::spawn_blocking(move || gate.wait().unwrap())
        };
        while !gate.entered.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let routing = Arc::new(matching_domain_routing());
        for _ in 0..2 {
            assert!(
                routing
                    .record_accepted_response_async(
                        response_plan("timeout.example.test", "203.0.113.1", unix_now() + 300),
                        ProxyDnsRequestContext::from_timeout(Duration::from_millis(20)),
                        || panic!("timed out blocking transaction published"),
                    )
                    .await
                    .is_err()
            );
            assert!(
                routing.dispatch.try_lock().is_err(),
                "timed out caller released a queued blocking job's slot"
            );
        }
        gate.release();
        blocker.await.unwrap();
        routing
            .record_accepted_response_async(
                response_plan("live.example.test", "203.0.113.2", unix_now() + 300),
                context(),
                || Ok(()),
            )
            .await
            .unwrap();
        assert_eq!(
            routing.state.lock().unwrap().owner.tracker().owner_count(),
            1
        );
    });
}
