use super::*;

use std::future::pending;
use std::sync::{Arc, Mutex};

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
    async fn exchange(&mut self) -> Result<Vec<u8>, String> {
        if let Some(started) = self.exchange_started.take() {
            let _ = started.send(());
        }
        match self.outcome {
            FakeExchangeOutcome::Success => Ok(vec![0x12, 0x34]),
            FakeExchangeOutcome::Failure(error) => Err(error.to_owned()),
            FakeExchangeOutcome::Pending => pending().await,
        }
    }

    fn discard_client(&mut self) {
        if std::mem::take(&mut self.owned.client) {
            self.record(CleanupEvent::ClientDiscarded).unwrap();
        }
    }

    fn close_connection(&mut self) {
        if std::mem::take(&mut self.owned.connection) {
            self.record(CleanupEvent::ConnectionClosed).unwrap();
        }
    }

    async fn close_endpoint_and_wait_idle(&mut self) -> Result<(), String> {
        if std::mem::take(&mut self.owned.endpoint) {
            self.record(CleanupEvent::EndpointClosedAndIdle)
        } else {
            Ok(())
        }
    }

    async fn finish_driver(&mut self) -> Result<(), String> {
        if std::mem::take(&mut self.owned.driver) {
            self.record(CleanupEvent::DriverFinished)
        } else {
            Ok(())
        }
    }

    async fn shutdown_bridge(&mut self) -> Result<(), String> {
        if std::mem::take(&mut self.owned.bridge) {
            self.record(CleanupEvent::BridgeShutdown)
        } else {
            Ok(())
        }
    }
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
                assert!(result.unwrap_err().contains(error));
            }
            FakeExchangeOutcome::Pending => unreachable!(),
        }
        assert_eq!(recorded_events(&events), EXPECTED_CLEANUP);
    }
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
    assert_eq!(error, PROXIED_DOH3_CANCELLED);
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

        assert!(error.contains("request failed"));
        assert!(error.contains(&format!("{failed_event:?} failed")));
        assert_eq!(recorded_events(&events), EXPECTED_CLEANUP);
    }
}

#[tokio::test]
async fn driver_task_is_joined_when_it_finishes() {
    let completion = finish_or_abort_driver_task(tokio::spawn(async {}))
        .await
        .unwrap();
    assert_eq!(completion, ProxiedDoh3DriverCompletion::Finished);
}

#[tokio::test]
async fn stalled_driver_task_is_aborted_and_joined() {
    let completion = lifecycle::finish_or_abort_driver_task_with_grace(
        tokio::spawn(pending()),
        RESIDENT_IDLE_SLEEP,
    )
    .await
    .unwrap();
    assert_eq!(completion, ProxiedDoh3DriverCompletion::Aborted);
}
