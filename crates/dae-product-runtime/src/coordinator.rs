use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use dae_product_core::product_now_text;
use serde_json::{Value, json};

const APPLY_GATE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const APPLY_GATE_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeApplyIntent {
    ApiReload,
    LocalControlReload,
    SubscriptionRefresh,
    StartupRestore,
    InterfaceRecovery,
}

impl RuntimeApplyIntent {
    pub fn source(self) -> &'static str {
        match self {
            Self::ApiReload => "api-runtime-reload",
            Self::LocalControlReload => "local-control",
            Self::SubscriptionRefresh => "subscription-refresh",
            Self::StartupRestore => "startup-restore",
            Self::InterfaceRecovery => "interface-monitor",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeApplyCoordinator {
    gate: Arc<Mutex<()>>,
    next_intent: Arc<AtomicU64>,
    stop_epoch: Arc<AtomicU64>,
    stop_pending: Arc<AtomicU64>,
    state: Arc<Mutex<RuntimeApplyCoordinatorState>>,
    gate_wait_timeout: Duration,
}

#[derive(Clone, Debug, Default)]
struct RuntimeApplyCoordinatorState {
    active_intent: Option<u64>,
    active_source: Option<String>,
    phase: String,
    last_completed_intent: Option<u64>,
    last_result: Option<String>,
    coalesced_count: u64,
    superseded_count: u64,
    updated_at: Option<String>,
}

pub struct RuntimeApplyPermit<'a> {
    coordinator: &'a RuntimeApplyCoordinator,
    _gate: MutexGuard<'a, ()>,
    intent_id: u64,
    finished: bool,
}

pub struct RuntimeStopPermit<'a> {
    coordinator: &'a RuntimeApplyCoordinator,
    _gate: MutexGuard<'a, ()>,
    intent_id: u64,
    finished: bool,
    pending_released: bool,
}

impl Default for RuntimeApplyCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeApplyCoordinator {
    pub fn new() -> Self {
        Self {
            gate: Arc::new(Mutex::new(())),
            next_intent: Arc::new(AtomicU64::new(1)),
            stop_epoch: Arc::new(AtomicU64::new(0)),
            stop_pending: Arc::new(AtomicU64::new(0)),
            state: Arc::new(Mutex::new(RuntimeApplyCoordinatorState {
                phase: "idle".to_owned(),
                ..RuntimeApplyCoordinatorState::default()
            })),
            gate_wait_timeout: APPLY_GATE_WAIT_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_gate_wait_timeout(timeout: Duration) -> Self {
        let mut coordinator = Self::new();
        coordinator.gate_wait_timeout = timeout;
        coordinator
    }

    pub fn begin_apply(
        &self,
        intent: RuntimeApplyIntent,
    ) -> Result<RuntimeApplyPermit<'_>, String> {
        let intent_id = self.next_intent.fetch_add(1, Ordering::Relaxed);
        if self.stop_pending.load(Ordering::Acquire) != 0 {
            self.record_superseded();
            return Err("runtime apply intent was superseded by stop".to_owned());
        }
        let accepted_stop_epoch = self.stop_epoch.load(Ordering::Acquire);
        let gate = match self.gate.try_lock() {
            Ok(gate) => gate,
            Err(TryLockError::WouldBlock) => {
                lock_gate_with_timeout(&self.gate, self.gate_wait_timeout)?
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err("runtime apply coordinator lock poisoned".to_owned());
            }
        };
        if self.stop_epoch.load(Ordering::Acquire) != accepted_stop_epoch
            || self.stop_pending.load(Ordering::Acquire) != 0
        {
            self.record_superseded();
            drop(gate);
            return Err("runtime apply intent was superseded by stop".to_owned());
        }
        if let Ok(mut state) = self.state.lock() {
            state.active_intent = Some(intent_id);
            state.active_source = Some(intent.source().to_owned());
            state.phase = "accepted".to_owned();
            state.updated_at = Some(product_now_text());
        }
        Ok(RuntimeApplyPermit {
            coordinator: self,
            _gate: gate,
            intent_id,
            finished: false,
        })
    }

    pub fn begin_stop(&self) -> Result<RuntimeStopPermit<'_>, String> {
        let intent_id = self.next_intent.fetch_add(1, Ordering::Relaxed);
        self.stop_pending.fetch_add(1, Ordering::AcqRel);
        self.stop_epoch.fetch_add(1, Ordering::AcqRel);
        let gate = match self.gate.lock() {
            Ok(gate) => gate,
            Err(_) => {
                self.stop_pending.fetch_sub(1, Ordering::AcqRel);
                return Err("runtime apply coordinator lock poisoned".to_owned());
            }
        };
        if let Ok(mut state) = self.state.lock() {
            state.active_intent = Some(intent_id);
            state.active_source = Some("stop".to_owned());
            state.phase = "stopping".to_owned();
            state.updated_at = Some(product_now_text());
        }
        Ok(RuntimeStopPermit {
            coordinator: self,
            _gate: gate,
            intent_id,
            finished: false,
            pending_released: false,
        })
    }

    fn record_superseded(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.superseded_count = state.superseded_count.saturating_add(1);
            state.updated_at = Some(product_now_text());
        }
    }

    pub fn summary(&self) -> Value {
        let Ok(state) = self.state.lock() else {
            return json!({"state": "error", "error": "runtime apply coordinator state lock poisoned"});
        };
        json!({
            "state": state.phase,
            "activeIntent": state.active_intent,
            "activeSource": state.active_source,
            "lastCompletedIntent": state.last_completed_intent,
            "lastResult": state.last_result,
            "coalescedCount": state.coalesced_count,
            "supersededCount": state.superseded_count,
            "stopPending": self.stop_pending.load(Ordering::Acquire),
            "updatedAt": state.updated_at,
        })
    }
}

fn lock_gate_with_timeout(
    gate: &Mutex<()>,
    timeout: Duration,
) -> Result<MutexGuard<'_, ()>, String> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        match gate.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "runtime apply gate busy; intent rejected after {}s",
                        timeout.as_secs()
                    ));
                }
                thread::sleep(APPLY_GATE_POLL_INTERVAL);
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err("runtime apply coordinator lock poisoned".to_owned());
            }
        }
    }
}

impl RuntimeApplyPermit<'_> {
    pub fn set_phase(&self, phase: &str) {
        if let Ok(mut state) = self.coordinator.state.lock()
            && state.active_intent == Some(self.intent_id)
        {
            state.phase = phase.to_owned();
            state.updated_at = Some(product_now_text());
        }
    }

    pub fn finish(mut self, result: &str) {
        self.record_finish(result);
        self.finished = true;
    }

    pub fn finish_coalesced(mut self) {
        if let Ok(mut state) = self.coordinator.state.lock() {
            state.coalesced_count = state.coalesced_count.saturating_add(1);
        }
        self.record_finish("coalesced");
        self.finished = true;
    }

    fn record_finish(&self, result: &str) {
        if let Ok(mut state) = self.coordinator.state.lock()
            && state.active_intent == Some(self.intent_id)
        {
            state.active_intent = None;
            state.active_source = None;
            state.phase = "idle".to_owned();
            state.last_completed_intent = Some(self.intent_id);
            state.last_result = Some(result.to_owned());
            state.updated_at = Some(product_now_text());
        }
    }
}

impl Drop for RuntimeApplyPermit<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.record_finish("abandoned");
        }
    }
}

impl RuntimeStopPermit<'_> {
    pub fn finish(mut self, result: &str) {
        self.record_finish(result);
        self.finished = true;
        self.release_pending();
    }

    fn record_finish(&self, result: &str) {
        if let Ok(mut state) = self.coordinator.state.lock()
            && state.active_intent == Some(self.intent_id)
        {
            state.active_intent = None;
            state.active_source = None;
            state.phase = "idle".to_owned();
            state.last_completed_intent = Some(self.intent_id);
            state.last_result = Some(result.to_owned());
            state.updated_at = Some(product_now_text());
        }
    }

    fn release_pending(&mut self) {
        if self.pending_released {
            return;
        }
        let previous = self.coordinator.stop_pending.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "runtime stop pending counter underflow");
        self.pending_released = true;
    }
}

impl Drop for RuntimeStopPermit<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.record_finish("abandoned");
        }
        self.release_pending();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn stop_epoch_supersedes_an_apply_that_was_already_waiting() {
        let coordinator = Arc::new(RuntimeApplyCoordinator::new());
        let first = coordinator
            .begin_apply(RuntimeApplyIntent::ApiReload)
            .unwrap();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let waiting_coordinator = Arc::clone(&coordinator);
        let waiting = thread::spawn(move || {
            waiting_tx.send(()).unwrap();
            match waiting_coordinator.begin_apply(RuntimeApplyIntent::LocalControlReload) {
                Ok(permit) => {
                    permit.finish("succeeded");
                    Ok(())
                }
                Err(err) => Err(err),
            }
        });
        waiting_rx.recv().unwrap();
        let stop_coordinator = Arc::clone(&coordinator);
        let stop = thread::spawn(move || {
            let permit = stop_coordinator.begin_stop()?;
            permit.finish("stopped");
            Ok::<(), String>(())
        });
        while coordinator.stop_epoch.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }
        first.finish("succeeded");

        assert_eq!(
            waiting.join().unwrap().unwrap_err(),
            "runtime apply intent was superseded by stop"
        );
        stop.join().unwrap().unwrap();
        assert_eq!(coordinator.summary()["lastResult"], json!("stopped"));
    }

    #[test]
    fn pending_stop_waits_for_active_apply_and_rejects_new_apply() {
        let coordinator = Arc::new(RuntimeApplyCoordinator::with_gate_wait_timeout(
            Duration::from_millis(50),
        ));
        let active = coordinator
            .begin_apply(RuntimeApplyIntent::ApiReload)
            .unwrap();
        let stop_coordinator = Arc::clone(&coordinator);
        let stop = thread::spawn(move || {
            let permit = stop_coordinator.begin_stop()?;
            permit.finish("stopped");
            Ok::<(), String>(())
        });
        while coordinator.stop_pending.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }

        let started_at = Instant::now();
        let rejected = coordinator.begin_apply(RuntimeApplyIntent::LocalControlReload);
        assert!(matches!(
            rejected,
            Err(ref error) if error == "runtime apply intent was superseded by stop"
        ));
        assert!(started_at.elapsed() < Duration::from_millis(50));
        thread::sleep(Duration::from_millis(100));
        assert_eq!(coordinator.summary()["stopPending"], json!(1));

        active.finish("succeeded");
        stop.join().unwrap().unwrap();
        assert_eq!(coordinator.summary()["stopPending"], json!(0));
        let later = coordinator
            .begin_apply(RuntimeApplyIntent::LocalControlReload)
            .unwrap();
        later.finish("succeeded");
    }

    #[test]
    fn begin_apply_rejects_after_gate_wait_timeout() {
        let coordinator = Arc::new(RuntimeApplyCoordinator::with_gate_wait_timeout(
            Duration::from_millis(150),
        ));
        let first = coordinator
            .begin_apply(RuntimeApplyIntent::ApiReload)
            .unwrap();
        let started_at = Instant::now();
        let rejected = coordinator.begin_apply(RuntimeApplyIntent::LocalControlReload);
        let elapsed = started_at.elapsed();
        let message = match rejected {
            Err(message) => message,
            Ok(_) => panic!("begin_apply should be rejected while the gate is busy"),
        };
        assert!(message.contains("gate busy") && message.contains("intent rejected"));
        assert!(elapsed >= Duration::from_millis(150));
        first.finish("succeeded");
        let later = coordinator
            .begin_apply(RuntimeApplyIntent::LocalControlReload)
            .unwrap();
        later.finish("succeeded");
        assert_eq!(coordinator.summary()["lastResult"], json!("succeeded"));
    }
}
