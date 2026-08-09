use super::*;

use std::future::pending;
use std::sync::{Arc, Mutex};

use crate::production_runtime_owner::resident_dataplane::{
    RESIDENT_IDLE_SLEEP, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
};

#[derive(Clone, Copy)]
enum ForcedExchangeOutcome {
    Success,
    Pending,
}

struct ForcedCleanupExchange {
    exchange_outcome: ForcedExchangeOutcome,
    endpoint_delay: std::time::Duration,
    deadlines: Arc<Mutex<Vec<time::Instant>>>,
    metrics: Option<Arc<ResidentDataplaneMetrics>>,
}

impl ForcedCleanupExchange {
    fn new(
        exchange_outcome: ForcedExchangeOutcome,
        metrics: Option<Arc<ResidentDataplaneMetrics>>,
    ) -> (Self, Arc<Mutex<Vec<time::Instant>>>) {
        let deadlines = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                exchange_outcome,
                endpoint_delay: std::time::Duration::ZERO,
                deadlines: Arc::clone(&deadlines),
                metrics,
            },
            deadlines,
        )
    }

    fn with_endpoint_delay(mut self, delay: std::time::Duration) -> Self {
        self.endpoint_delay = delay;
        self
    }

    fn record_deadline(&self, deadline: ProxiedDoh3CleanupDeadline) {
        self.deadlines.lock().unwrap().push(deadline.instant());
    }
}

impl ProxiedDoh3ExchangeTarget for ForcedCleanupExchange {
    async fn exchange(&mut self) -> Result<Vec<u8>, ProxyDnsRequestError> {
        match self.exchange_outcome {
            ForcedExchangeOutcome::Success => Ok(vec![0x12, 0x34]),
            ForcedExchangeOutcome::Pending => pending().await,
        }
    }

    fn discard_client(&mut self) -> bool {
        true
    }

    fn close_connection(&mut self) -> bool {
        true
    }

    async fn close_endpoint_and_wait_idle(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3EndpointCompletion>, String> {
        self.record_deadline(deadline);
        time::sleep(self.endpoint_delay).await;
        Ok(Some(ProxiedDoh3EndpointCompletion::ForcedDrop))
    }

    async fn finish_driver(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3DriverCompletion>, String> {
        self.record_deadline(deadline);
        Ok(Some(ProxiedDoh3DriverCompletion::Aborted))
    }

    async fn shutdown_bridge(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ResidentProxyUdpBridgeShutdownCompletion>, String> {
        self.record_deadline(deadline);
        Ok(Some(ResidentProxyUdpBridgeShutdownCompletion::Aborted))
    }

    fn observe_cleanup(&self, outcome: &ProxiedDoh3CleanupOutcome) {
        if let Some(metrics) = self.metrics.as_ref() {
            outcome.record_metrics(metrics);
        }
    }
}

#[tokio::test]
async fn completed_exchange_is_not_rewritten_by_the_expired_request_deadline() {
    let request_timeout = RESIDENT_IDLE_SLEEP.saturating_mul(20);
    let cleanup_delay = request_timeout.saturating_mul(2);
    assert!(cleanup_delay < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);
    let context = ProxyDnsRequestContext::from_timeout(request_timeout);
    let request_deadline = context.deadline();
    let (target, _) = ForcedCleanupExchange::new(ForcedExchangeOutcome::Success, None);
    let target = target.with_endpoint_delay(cleanup_delay);

    let response = lifecycle::run_proxied_doh3_exchange_with_context(target, context)
        .await
        .unwrap();

    assert_eq!(response, vec![0x12, 0x34]);
    assert!(time::Instant::now() >= request_deadline);
}

#[tokio::test]
async fn expired_exchange_deadline_starts_one_independent_cleanup_deadline() {
    let context = ProxyDnsRequestContext::from_timeout(RESIDENT_IDLE_SLEEP);
    let request_deadline = context.deadline();
    let (target, deadlines) = ForcedCleanupExchange::new(ForcedExchangeOutcome::Pending, None);

    let error = lifecycle::run_proxied_doh3_exchange_with_context(target, context)
        .await
        .unwrap_err();

    assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    let deadlines = deadlines.lock().unwrap();
    assert_eq!(deadlines.len(), 3);
    assert!(deadlines.iter().all(|deadline| *deadline == deadlines[0]));
    assert!(deadlines[0] > request_deadline);
}

#[tokio::test]
async fn one_cleanup_deadline_drives_all_forced_completion_classes() {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (target, deadlines) =
        ForcedCleanupExchange::new(ForcedExchangeOutcome::Pending, Some(Arc::clone(&metrics)));
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    drop(cancel);

    let (result, cleanup) =
        lifecycle::run_owned_proxied_doh3_exchange_observed(target, cancelled).await;

    let error = result.unwrap_err();
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Cancelled);
    assert!(error.to_string().contains("cleanup_outcome="));
    assert_eq!(
        cleanup.endpoint,
        Some(ProxiedDoh3EndpointCompletion::ForcedDrop)
    );
    assert_eq!(cleanup.driver, Some(ProxiedDoh3DriverCompletion::Aborted));
    assert_eq!(
        cleanup.bridge,
        Some(ResidentProxyUdpBridgeShutdownCompletion::Aborted)
    );
    assert!(
        deadlines
            .lock()
            .unwrap()
            .iter()
            .all(|deadline| *deadline == cleanup.deadline.instant())
    );
    assert_eq!(deadlines.lock().unwrap().len(), 3);

    let snapshot = metrics.proxied_doh3_cleanup_snapshot();
    assert_eq!(snapshot["completedTotal"], 1);
    assert_eq!(snapshot["completionClasses"]["forced"], 1);
    assert_eq!(snapshot["completionClasses"]["failed"], 0);
    assert_eq!(snapshot["forcedComponents"]["endpointDrop"], 1);
    assert_eq!(snapshot["forcedComponents"]["driverAbort"], 1);
    assert_eq!(snapshot["forcedComponents"]["bridgeAbort"], 1);
}

#[tokio::test]
async fn forced_cleanup_is_observed_without_discarding_a_successful_response() {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (target, _) =
        ForcedCleanupExchange::new(ForcedExchangeOutcome::Success, Some(Arc::clone(&metrics)));
    let (_keep_open, cancelled) = tokio::sync::oneshot::channel();

    let (result, cleanup) =
        lifecycle::run_owned_proxied_doh3_exchange_observed(target, cancelled).await;

    assert_eq!(result.unwrap(), vec![0x12, 0x34]);
    assert!(cleanup.endpoint_forced_drop());
    assert!(cleanup.driver_aborted());
    assert!(cleanup.bridge_aborted());
    let snapshot = metrics.proxied_doh3_cleanup_snapshot();
    assert_eq!(snapshot["completionClasses"]["forced"], 1);
    assert_eq!(snapshot["completionClasses"]["failed"], 0);
}

#[tokio::test]
async fn endpoint_idle_deadline_reports_forced_drop() {
    let completion = lifecycle::wait_for_endpoint_idle_until(
        pending(),
        ProxiedDoh3CleanupDeadline::from_timeout(RESIDENT_IDLE_SLEEP),
    )
    .await;

    assert_eq!(completion, ProxiedDoh3EndpointCompletion::ForcedDrop);
}

#[tokio::test]
async fn driver_task_is_joined_when_it_finishes() {
    let completion = lifecycle::finish_or_abort_driver_task_until(
        tokio::spawn(async {}),
        ProxiedDoh3CleanupDeadline::from_timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE),
    )
    .await
    .unwrap();
    assert_eq!(completion, ProxiedDoh3DriverCompletion::Finished);
}

#[tokio::test]
async fn stalled_driver_task_is_aborted_and_joined() {
    struct TaskDropMarker(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for TaskDropMarker {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    let (started, task_started) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_dropped = Arc::clone(&dropped);
    let task = tokio::spawn(async move {
        let _marker = TaskDropMarker(task_dropped);
        let _ = started.send(());
        pending::<()>().await;
    });
    task_started.await.unwrap();
    let completion = lifecycle::finish_or_abort_driver_task_until(
        task,
        ProxiedDoh3CleanupDeadline::from_timeout(RESIDENT_IDLE_SLEEP),
    )
    .await
    .unwrap();
    assert_eq!(completion, ProxiedDoh3DriverCompletion::Aborted);
    assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
}
