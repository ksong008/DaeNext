use super::*;

use std::future::pending;
use std::sync::{Arc, Mutex};

mod bounded_cleanup;
mod h3_server;
mod persistent_cache;
mod production_resources;
mod resource_balance;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupEvent {
    ClientDiscarded,
    ConnectionClosed,
    EndpointClosedAndIdle,
    DriverFinished,
    BridgeShutdown,
}

const EXPECTED_CLEANUP: [CleanupEvent; 5] = [
    CleanupEvent::ClientDiscarded,
    CleanupEvent::ConnectionClosed,
    CleanupEvent::EndpointClosedAndIdle,
    CleanupEvent::DriverFinished,
    CleanupEvent::BridgeShutdown,
];

#[derive(Clone, Copy)]
enum FakeExchangeOutcome {
    Success,
    Failure(&'static str),
    ProtocolFailure(&'static str),
    DeadlineFailure(&'static str),
    Pending,
}

#[derive(Clone, Copy)]
struct FakeOwnedResources {
    client: bool,
    connection: bool,
    endpoint: bool,
    driver: bool,
    bridge: bool,
}

impl FakeOwnedResources {
    const NONE: Self = Self {
        client: false,
        connection: false,
        endpoint: false,
        driver: false,
        bridge: false,
    };

    const ALL: Self = Self {
        client: true,
        connection: true,
        endpoint: true,
        driver: true,
        bridge: true,
    };
}

struct FakeExchange {
    outcome: FakeExchangeOutcome,
    owned: FakeOwnedResources,
    cleanup_failure: Option<CleanupEvent>,
    events: Arc<Mutex<Vec<CleanupEvent>>>,
    exchange_started: Option<tokio::sync::oneshot::Sender<()>>,
}

impl FakeExchange {
    fn new(
        outcome: FakeExchangeOutcome,
        cleanup_failure: Option<CleanupEvent>,
    ) -> (Self, Arc<Mutex<Vec<CleanupEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                outcome,
                owned: FakeOwnedResources::ALL,
                cleanup_failure,
                events: Arc::clone(&events),
                exchange_started: None,
            },
            events,
        )
    }

    fn with_owned_resources(mut self, owned: FakeOwnedResources) -> Self {
        self.owned = owned;
        self
    }

    fn with_exchange_started(mut self, started: tokio::sync::oneshot::Sender<()>) -> Self {
        self.exchange_started = Some(started);
        self
    }

    fn record(&self, event: CleanupEvent) -> Result<(), String> {
        self.events.lock().unwrap().push(event);
        if self.cleanup_failure == Some(event) {
            Err(format!("{event:?} failed"))
        } else {
            Ok(())
        }
    }
}

impl ProxiedDoh3ExchangeTarget for FakeExchange {
    async fn exchange(&mut self) -> Result<Vec<u8>, ProxyDnsRequestError> {
        if let Some(started) = self.exchange_started.take() {
            let _ = started.send(());
        }
        match self.outcome {
            FakeExchangeOutcome::Success => Ok(vec![0x12, 0x34]),
            FakeExchangeOutcome::Failure(error) => Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Network,
                error,
            )),
            FakeExchangeOutcome::ProtocolFailure(error) => Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Protocol,
                error,
            )),
            FakeExchangeOutcome::DeadlineFailure(error) => Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Deadline,
                error,
            )),
            FakeExchangeOutcome::Pending => pending().await,
        }
    }

    fn discard_client(&mut self) -> bool {
        if std::mem::take(&mut self.owned.client) {
            self.record(CleanupEvent::ClientDiscarded).unwrap();
            true
        } else {
            false
        }
    }

    fn close_connection(&mut self) -> bool {
        if std::mem::take(&mut self.owned.connection) {
            self.record(CleanupEvent::ConnectionClosed).unwrap();
            true
        } else {
            false
        }
    }

    async fn close_endpoint_and_wait_idle(
        &mut self,
        _deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3EndpointCompletion>, String> {
        if std::mem::take(&mut self.owned.endpoint) {
            self.record(CleanupEvent::EndpointClosedAndIdle)?;
            Ok(Some(ProxiedDoh3EndpointCompletion::Idle))
        } else {
            Ok(None)
        }
    }

    async fn finish_driver(
        &mut self,
        _deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3DriverCompletion>, String> {
        if std::mem::take(&mut self.owned.driver) {
            self.record(CleanupEvent::DriverFinished)?;
            Ok(Some(ProxiedDoh3DriverCompletion::Finished))
        } else {
            Ok(None)
        }
    }

    async fn shutdown_bridge(
        &mut self,
        _deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ResidentOwnedTaskShutdownCompletion>, String> {
        if std::mem::take(&mut self.owned.bridge) {
            self.record(CleanupEvent::BridgeShutdown)?;
            Ok(Some(ResidentOwnedTaskShutdownCompletion::Joined))
        } else {
            Ok(None)
        }
    }

    fn observe_cleanup(&self, _outcome: &ProxiedDoh3CleanupOutcome) {}
}

fn recorded_events(events: &Arc<Mutex<Vec<CleanupEvent>>>) -> Vec<CleanupEvent> {
    events.lock().unwrap().clone()
}

#[tokio::test]
async fn every_exchange_exit_uses_the_same_cleanup_epilogue() {
    let outcomes = [
        FakeExchangeOutcome::Success,
        FakeExchangeOutcome::Failure("connect failed"),
        FakeExchangeOutcome::Failure("request send failed"),
        FakeExchangeOutcome::Failure("response headers failed"),
        FakeExchangeOutcome::Failure("response body failed"),
        FakeExchangeOutcome::Failure("response parse failed"),
        FakeExchangeOutcome::Failure("response size limit exceeded"),
        FakeExchangeOutcome::Failure("exchange timeout"),
    ];

    for outcome in outcomes {
        let (target, events) = FakeExchange::new(outcome, None);
        let (_keep_open, cancelled) = tokio::sync::oneshot::channel();
        let result = run_owned_proxied_doh3_exchange(target, cancelled).await;
        match outcome {
            FakeExchangeOutcome::Success => {
                assert_eq!(result.unwrap(), vec![0x12, 0x34]);
            }
            FakeExchangeOutcome::Failure(error) => {
                assert!(result.unwrap_err().to_string().contains(error));
            }
            FakeExchangeOutcome::ProtocolFailure(error) => {
                assert!(result.unwrap_err().to_string().contains(error));
            }
            FakeExchangeOutcome::DeadlineFailure(error) => {
                assert!(result.unwrap_err().to_string().contains(error));
            }
            FakeExchangeOutcome::Pending => unreachable!(),
        }
        assert_eq!(recorded_events(&events), EXPECTED_CLEANUP);
    }
}

#[tokio::test]
async fn protocol_failure_remains_typed_after_the_cleanup_epilogue() {
    let (target, events) = FakeExchange::new(
        FakeExchangeOutcome::ProtocolFailure("invalid response"),
        None,
    );
    let (_keep_open, cancelled) = tokio::sync::oneshot::channel();
    let error = run_owned_proxied_doh3_exchange(target, cancelled)
        .await
        .unwrap_err();

    assert_eq!(error.stage(), ProxyDnsRequestStage::Read);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Protocol);
    assert!(error.to_string().contains("invalid response"));
    assert_eq!(recorded_events(&events), EXPECTED_CLEANUP);
}

#[tokio::test]
async fn cancellation_is_signalled_to_the_owner_before_cleanup() {
    let (target, events) = FakeExchange::new(FakeExchangeOutcome::Pending, None);
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let owner_task = tokio::spawn(run_owned_proxied_doh3_exchange(target, cancelled));
    drop(ProxiedDoh3Cancellation::new(cancel));

    let error = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, owner_task)
        .await
        .expect("owner task should finish after cancellation")
        .expect("owner task should not panic")
        .unwrap_err();
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Cancelled);
    assert!(error.to_string().contains(PROXIED_DOH3_CANCELLED));
    assert_eq!(recorded_events(&events), EXPECTED_CLEANUP);
}

#[tokio::test]
async fn dropping_the_public_wrapper_still_cleans_the_detached_owner() {
    let (target, events) = FakeExchange::new(FakeExchangeOutcome::Pending, None);
    let (started, exchange_started) = tokio::sync::oneshot::channel();
    let caller_task = tokio::spawn(lifecycle::run_cancelable_proxied_doh3_exchange(
        target.with_exchange_started(started),
    ));
    exchange_started
        .await
        .expect("fake exchange should start before caller cancellation");

    caller_task.abort();
    assert!(caller_task.await.unwrap_err().is_cancelled());
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        loop {
            if recorded_events(&events) == EXPECTED_CLEANUP {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached owner should complete cleanup after caller drop");
}

#[tokio::test]
async fn caller_deadline_returns_typed_error_after_owned_cleanup() {
    let (target, events) = FakeExchange::new(FakeExchangeOutcome::Pending, None);
    let (started, exchange_started) = tokio::sync::oneshot::channel();
    let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_millis(100));
    let caller_task = tokio::spawn(lifecycle::run_proxied_doh3_exchange_with_context(
        target.with_exchange_started(started),
        context,
    ));
    exchange_started
        .await
        .expect("fake exchange should start before its caller deadline");

    let error = caller_task.await.unwrap().unwrap_err();
    assert_eq!(error.stage(), ProxyDnsRequestStage::Read);
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    assert_eq!(recorded_events(&events), EXPECTED_CLEANUP);
}

#[tokio::test]
async fn partial_initialization_cleans_only_acquired_resources() {
    let cases = [
        (FakeOwnedResources::NONE, Vec::new()),
        (
            FakeOwnedResources {
                bridge: true,
                ..FakeOwnedResources::NONE
            },
            vec![CleanupEvent::BridgeShutdown],
        ),
        (
            FakeOwnedResources {
                endpoint: true,
                bridge: true,
                ..FakeOwnedResources::NONE
            },
            vec![
                CleanupEvent::EndpointClosedAndIdle,
                CleanupEvent::BridgeShutdown,
            ],
        ),
        (
            FakeOwnedResources {
                connection: true,
                endpoint: true,
                bridge: true,
                ..FakeOwnedResources::NONE
            },
            vec![
                CleanupEvent::ConnectionClosed,
                CleanupEvent::EndpointClosedAndIdle,
                CleanupEvent::BridgeShutdown,
            ],
        ),
        (FakeOwnedResources::ALL, EXPECTED_CLEANUP.to_vec()),
    ];

    for (owned, expected) in cases {
        let (target, events) = FakeExchange::new(
            FakeExchangeOutcome::Failure("injected acquisition failure"),
            None,
        );
        let (_keep_open, cancelled) = tokio::sync::oneshot::channel();
        run_owned_proxied_doh3_exchange(target.with_owned_resources(owned), cancelled)
            .await
            .unwrap_err();
        assert_eq!(recorded_events(&events), expected);
    }
}

#[tokio::test]
async fn cleanup_failure_does_not_skip_later_cleanup_actions() {
    for failed_event in [
        CleanupEvent::EndpointClosedAndIdle,
        CleanupEvent::DriverFinished,
        CleanupEvent::BridgeShutdown,
    ] {
        let (target, events) = FakeExchange::new(
            FakeExchangeOutcome::Failure("request failed"),
            Some(failed_event),
        );
        let (_keep_open, cancelled) = tokio::sync::oneshot::channel();
        let error = run_owned_proxied_doh3_exchange(target, cancelled)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("request failed"));
        assert!(
            error
                .to_string()
                .contains(&format!("{failed_event:?} failed"))
        );
        assert_eq!(error.stage(), ProxyDnsRequestStage::Cleanup);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
        assert_eq!(recorded_events(&events), EXPECTED_CLEANUP);
    }
}

#[tokio::test]
async fn cancellation_and_deadline_types_survive_cleanup_failures() {
    let (cancelled_target, cancelled_events) = FakeExchange::new(
        FakeExchangeOutcome::Pending,
        Some(CleanupEvent::DriverFinished),
    );
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    drop(cancel);
    let cancelled_error = run_owned_proxied_doh3_exchange(cancelled_target, cancelled)
        .await
        .unwrap_err();
    assert_eq!(cancelled_error.stage(), ProxyDnsRequestStage::Read);
    assert_eq!(cancelled_error.failure(), ProxyDnsRequestFailure::Cancelled);
    assert!(
        cancelled_error
            .to_string()
            .contains("DriverFinished failed")
    );
    assert_eq!(recorded_events(&cancelled_events), EXPECTED_CLEANUP);

    let (deadline_target, deadline_events) = FakeExchange::new(
        FakeExchangeOutcome::DeadlineFailure("request deadline expired"),
        Some(CleanupEvent::BridgeShutdown),
    );
    let (_keep_open, cancelled) = tokio::sync::oneshot::channel();
    let deadline_error = run_owned_proxied_doh3_exchange(deadline_target, cancelled)
        .await
        .unwrap_err();
    assert_eq!(deadline_error.stage(), ProxyDnsRequestStage::Read);
    assert_eq!(deadline_error.failure(), ProxyDnsRequestFailure::Deadline);
    assert!(deadline_error.to_string().contains("BridgeShutdown failed"));
    assert_eq!(recorded_events(&deadline_events), EXPECTED_CLEANUP);
}
