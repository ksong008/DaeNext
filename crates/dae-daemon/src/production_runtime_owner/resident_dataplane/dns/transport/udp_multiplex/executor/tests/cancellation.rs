use super::super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct BuildCancellationGuard(Arc<AtomicUsize>);

impl Drop for BuildCancellationGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn closed_initialization_receiver_prevents_build_from_starting() {
    let builds = Arc::new(AtomicUsize::new(0));
    let actors = Arc::new(AtomicUsize::new(0));
    let build_count = Arc::clone(&builds);
    let actor_count = Arc::clone(&actors);
    let (ready, receiver) = tokio::sync::oneshot::channel();
    drop(receiver);

    run_dns_udp_actor_build(ready, move || async move {
        build_count.fetch_add(1, Ordering::SeqCst);
        actor_count.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<ResidentDnsUdpActorRegistration<()>, String>>().await
    })
    .await;

    assert_eq!(builds.load(Ordering::SeqCst), 0);
    assert_eq!(actors.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn caller_cancellation_stops_an_in_progress_build_before_actor_creation() {
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let payload_admission = runtime.payload_admission.clone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime,
        Arc::clone(&metrics),
    ));
    let builds = Arc::new(AtomicUsize::new(0));
    let actors = Arc::new(AtomicUsize::new(0));
    let cancellations = Arc::new(AtomicUsize::new(0));
    let (started, build_started) = tokio::sync::oneshot::channel();
    let worker = Arc::clone(&executor);
    let build_count = Arc::clone(&builds);
    let actor_count = Arc::clone(&actors);
    let cancellation_count = Arc::clone(&cancellations);
    let caller = tokio::spawn(async move {
        worker
            .spawn_actor(move || async move {
                build_count.fetch_add(1, Ordering::SeqCst);
                let _cancel = BuildCancellationGuard(cancellation_count);
                let _ = started.send(());
                std::future::pending::<()>().await;
                actor_count.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<ResidentDnsUdpActorRegistration<()>, String>>().await
            })
            .await
    });
    build_started.await.unwrap();

    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while cancellations.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert_eq!(actors.load(Ordering::SeqCst), 0);
    assert_eq!(payload_admission.current(), 0);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["dnsUdpActorsOpened"], 0);
    assert_eq!(snapshot["proxyDnsUdpQueuedBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingBytesCurrent"], 0);

    let deadline = tokio::time::Instant::now()
        + crate::production_runtime_owner::resident_dataplane::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(executor.shutdown(deadline).await["status"], "pass");
}
