use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::writer_metrics::ResidentEventWriterMetrics;
use super::{
    ResidentEvent, clear_resident_event_log_file_direct, persist_resident_event_direct,
    prune_resident_event_log_file_direct,
};

mod control;

use self::control::{deadline_after, send_command_until};

const RESIDENT_EVENT_WRITER_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

static ACTIVE_EVENT_WRITER: OnceLock<Mutex<Option<ResidentEventWriterHandle>>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct ResidentEventWriterRuntime {
    handle: ResidentEventWriterHandle,
    thread: Option<JoinHandle<()>>,
    completion: Option<Receiver<ResidentEventWriterExit>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentEventWriterHandle {
    inner: Arc<ResidentEventWriterInner>,
}

#[derive(Debug)]
struct ResidentEventWriterInner {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
    sender: SyncSender<ResidentEventWriterCommand>,
    metrics: Arc<ResidentEventWriterMetrics>,
}

#[derive(Debug)]
enum ResidentEventWriterCommand {
    Event(ResidentEvent),
    Prune(ResidentEventWriterAck),
    Clear(ResidentEventWriterAck),
    Stop(ResidentEventWriterAck),
}

type ResidentEventWriterAck = SyncSender<Result<(), String>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentEventWriterExit {
    Completed,
    Panicked,
}

impl ResidentEventWriterRuntime {
    pub(crate) fn start(path: PathBuf, lock: Arc<Mutex<()>>, queue_capacity: usize) -> Self {
        let queue_capacity = queue_capacity.max(1);
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let metrics = Arc::new(ResidentEventWriterMetrics::new(queue_capacity as u64));
        let inner = Arc::new(ResidentEventWriterInner {
            path,
            lock,
            sender,
            metrics,
        });
        let handle = ResidentEventWriterHandle {
            inner: Arc::clone(&inner),
        };
        let thread_inner = Arc::clone(&inner);
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let exit = match catch_unwind(AssertUnwindSafe(|| {
                run_event_writer(thread_inner, receiver)
            })) {
                Ok(()) => ResidentEventWriterExit::Completed,
                Err(_) => ResidentEventWriterExit::Panicked,
            };
            let _ = completion_tx.send(exit);
        });
        let runtime = Self {
            handle: handle.clone(),
            thread: Some(thread),
            completion: Some(completion_rx),
        };
        set_active_resident_event_writer(Some(handle));
        runtime
    }

    pub(crate) fn metrics_snapshot(&self) -> Value {
        self.handle.metrics_snapshot()
    }

    pub(crate) fn read_handle(&self) -> ResidentEventWriterHandle {
        self.handle.clone()
    }

    pub(crate) fn clear(&self) -> std::io::Result<()> {
        self.handle.clear()
    }

    pub(crate) fn prune(&self) -> std::io::Result<()> {
        self.handle.prune()
    }

    #[cfg(test)]
    pub(crate) fn shutdown(&mut self) -> Value {
        self.shutdown_until(deadline_after(RESIDENT_EVENT_WRITER_CONTROL_TIMEOUT))
    }

    pub(crate) fn shutdown_until(&mut self, deadline: Instant) -> Value {
        clear_active_resident_event_writer(&self.handle.inner.path);
        if self.thread.is_none() {
            return json!({
                "schemaVersion": 1,
                "owner": "resident-event-writer",
                "status": "pass",
                "stopError": Value::Null,
                "threadJoined": true,
                "threadTimedOut": false,
                "threadPanicked": false,
                "alreadyStopped": true,
                "metrics": self.metrics_snapshot(),
            });
        }
        let stop_result = self
            .handle
            .control_until(ResidentEventWriterCommand::Stop, deadline);
        let thread_exit = self.wait_for_completion_until(deadline);
        let thread_joined = thread_exit.is_some();
        let thread_panicked = thread_exit == Some(ResidentEventWriterExit::Panicked);
        let thread_timed_out = !thread_joined;
        json!({
            "schemaVersion": 1,
            "owner": "resident-event-writer",
            "status": if stop_result.is_ok() && thread_joined && !thread_panicked { "pass" } else { "fail" },
            "stopError": stop_result.err().map(|err| err.to_string()),
            "threadJoined": thread_joined,
            "threadTimedOut": thread_timed_out,
            "threadPanicked": thread_panicked,
            "alreadyStopped": false,
            "metrics": self.metrics_snapshot(),
        })
    }

    fn wait_for_completion_until(&mut self, deadline: Instant) -> Option<ResidentEventWriterExit> {
        let mut reported_exit = None;
        loop {
            if reported_exit.is_none() {
                reported_exit = self.completion.as_ref().and_then(|completion| {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        completion.try_recv().ok()
                    } else {
                        completion.recv_timeout(remaining).ok()
                    }
                });
            }
            let thread_finished = self.thread.as_ref().is_none_or(JoinHandle::is_finished);
            if thread_finished {
                let join_panicked = self
                    .thread
                    .take()
                    .is_some_and(|thread| thread.join().is_err());
                self.completion.take();
                return Some(if join_panicked {
                    ResidentEventWriterExit::Panicked
                } else {
                    reported_exit.unwrap_or(ResidentEventWriterExit::Completed)
                });
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::yield_now();
        }
    }
}

impl ResidentEventWriterHandle {
    pub(super) fn submit(&self, event: ResidentEvent) {
        let class = event.class();
        let block_on_full_queue = event.block_on_full_queue();
        self.inner.metrics.command_enqueued();
        match self
            .inner
            .sender
            .try_send(ResidentEventWriterCommand::Event(event))
        {
            Ok(()) => {}
            Err(TrySendError::Full(ResidentEventWriterCommand::Event(event)))
                if block_on_full_queue =>
            {
                if let Err(err) = send_command_until(
                    &self.inner.sender,
                    ResidentEventWriterCommand::Event(event),
                    deadline_after(RESIDENT_EVENT_WRITER_CONTROL_TIMEOUT),
                ) {
                    self.inner.metrics.command_rejected();
                    self.inner
                        .metrics
                        .record_error(format!("send resident event: {err}"));
                }
            }
            Err(TrySendError::Full(ResidentEventWriterCommand::Event(_))) => {
                self.inner.metrics.command_rejected();
                self.inner.metrics.dropped(class);
            }
            Err(TrySendError::Disconnected(ResidentEventWriterCommand::Event(_))) => {
                self.inner.metrics.command_rejected();
                self.inner.metrics.dropped(class);
                self.inner
                    .metrics
                    .record_error("resident event writer channel disconnected");
            }
            Err(TrySendError::Full(command) | TrySendError::Disconnected(command)) => {
                self.inner.metrics.command_rejected();
                self.inner.metrics.record_error(format!(
                    "unexpected resident event writer command rejection: {}",
                    command.name()
                ));
            }
        }
    }

    pub(crate) fn metrics_snapshot(&self) -> Value {
        self.inner.metrics.snapshot()
    }

    pub(crate) fn clear(&self) -> std::io::Result<()> {
        self.control(ResidentEventWriterCommand::Clear)
    }

    pub(crate) fn prune(&self) -> std::io::Result<()> {
        self.control(ResidentEventWriterCommand::Prune)
    }
}

impl ResidentEventWriterCommand {
    fn name(&self) -> &'static str {
        match self {
            Self::Event(_) => "event",
            Self::Prune(_) => "prune",
            Self::Clear(_) => "clear",
            Self::Stop(_) => "stop",
        }
    }
}

pub(super) fn active_resident_event_writer_for_path(
    path: &Path,
) -> Option<ResidentEventWriterHandle> {
    ACTIVE_EVENT_WRITER.get().and_then(|slot| {
        slot.lock().ok().and_then(|guard| {
            guard
                .as_ref()
                .filter(|writer| writer.inner.path == path)
                .cloned()
        })
    })
}

fn set_active_resident_event_writer(writer: Option<ResidentEventWriterHandle>) {
    let slot = ACTIVE_EVENT_WRITER.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = slot.lock() {
        *guard = writer;
    }
}

fn clear_active_resident_event_writer(path: &Path) {
    let Some(slot) = ACTIVE_EVENT_WRITER.get() else {
        return;
    };
    let Ok(mut guard) = slot.lock() else {
        return;
    };
    if guard
        .as_ref()
        .is_some_and(|writer| writer.inner.path == path)
    {
        *guard = None;
    }
}

fn run_event_writer(
    inner: Arc<ResidentEventWriterInner>,
    receiver: Receiver<ResidentEventWriterCommand>,
) {
    while let Ok(command) = receiver.recv() {
        inner.metrics.command_dequeued();
        match command {
            ResidentEventWriterCommand::Event(event) => {
                match persist_resident_event_direct(&inner.path, &inner.lock, event) {
                    Ok(outcome) => {
                        if outcome.persisted {
                            inner.metrics.persisted();
                        } else {
                            inner.metrics.filtered();
                        }
                        if outcome.pruned {
                            inner.metrics.pruned();
                        }
                    }
                    Err(err) => inner
                        .metrics
                        .record_error(format!("persist resident event: {err}")),
                }
            }
            ResidentEventWriterCommand::Prune(ack) => {
                let result = prune_resident_event_log_file_direct(&inner.path)
                    .map(|()| inner.metrics.pruned())
                    .map_err(|err| err.to_string());
                let _ = ack.send(result);
            }
            ResidentEventWriterCommand::Clear(ack) => {
                let result = clear_resident_event_log_file_direct(&inner.path)
                    .map_err(|err| err.to_string());
                let _ = ack.send(result);
            }
            ResidentEventWriterCommand::Stop(ack) => {
                let _ = ack.send(Ok(()));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests;
