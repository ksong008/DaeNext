use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};

use super::writer_metrics::ResidentEventWriterMetrics;
use super::{
    ResidentEvent, clear_resident_event_log_file_direct, persist_resident_event_direct,
    prune_resident_event_log_file_direct,
};

const RESIDENT_EVENT_WRITER_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

static ACTIVE_EVENT_WRITER: OnceLock<Mutex<Option<ResidentEventWriterHandle>>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct ResidentEventWriterRuntime {
    handle: ResidentEventWriterHandle,
    thread: Option<JoinHandle<()>>,
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
        let thread = thread::spawn(move || run_event_writer(thread_inner, receiver));
        let runtime = Self {
            handle: handle.clone(),
            thread: Some(thread),
        };
        set_active_resident_event_writer(Some(handle));
        runtime
    }

    pub(crate) fn metrics_snapshot(&self) -> Value {
        self.handle.metrics_snapshot()
    }

    pub(crate) fn clear(&self) -> std::io::Result<()> {
        self.handle.clear()
    }

    pub(crate) fn prune(&self) -> std::io::Result<()> {
        self.handle.prune()
    }

    pub(crate) fn shutdown(&mut self) -> Value {
        clear_active_resident_event_writer(&self.handle.inner.path);
        let stop_result = self.handle.control(ResidentEventWriterCommand::Stop);
        let thread_joined = self
            .thread
            .take()
            .map(|thread| thread.join().is_ok())
            .unwrap_or(true);
        json!({
            "schemaVersion": 1,
            "owner": "resident-event-writer",
            "status": if stop_result.is_ok() && thread_joined { "pass" } else { "fail" },
            "stopError": stop_result.err().map(|err| err.to_string()),
            "threadJoined": thread_joined,
            "metrics": self.metrics_snapshot(),
        })
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
                if let Err(err) = self
                    .inner
                    .sender
                    .send(ResidentEventWriterCommand::Event(event))
                {
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

    fn control(
        &self,
        build: impl FnOnce(ResidentEventWriterAck) -> ResidentEventWriterCommand,
    ) -> std::io::Result<()> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.inner.metrics.command_enqueued();
        if let Err(err) = self.inner.sender.send(build(ack_tx)) {
            self.inner.metrics.command_rejected();
            let message = format!("send resident event writer control command: {err}");
            self.inner.metrics.record_error(message.clone());
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, message));
        }
        match ack_rx.recv_timeout(RESIDENT_EVENT_WRITER_CONTROL_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(std::io::Error::other(err)),
            Err(RecvTimeoutError::Timeout) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "resident event writer control command timed out",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "resident event writer control acknowledgement disconnected",
            )),
        }
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
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::mpsc;

    #[test]
    fn resident_event_writer_drops_datapath_errors_when_queue_is_full() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(ResidentEventWriterCommand::Event(ResidentEvent::new(
                json!({"event": "tcp_worker_started"}),
            )))
            .unwrap();
        let metrics = Arc::new(ResidentEventWriterMetrics::new(1));
        let handle = ResidentEventWriterHandle {
            inner: Arc::new(ResidentEventWriterInner {
                path: std::env::temp_dir().join(format!(
                    "resident-event-writer-drop-test-{}",
                    std::process::id()
                )),
                lock: Arc::new(Mutex::new(())),
                sender,
                metrics: Arc::clone(&metrics),
            }),
        };

        handle.submit(ResidentEvent::new(json!({
            "event": "udp_exchange_failed",
            "error": "sample",
        })));

        drop(receiver);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["droppedCount"], json!(1));
        assert_eq!(snapshot["droppedByClass"]["error"], json!(1));
        assert_eq!(snapshot["lastWriteError"], Value::Null);
    }

    #[test]
    fn resident_event_full_queue_blocking_policy_is_lifecycle_only() {
        assert!(ResidentEvent::new(json!({"event": "tcp_worker_started"})).block_on_full_queue());
        assert!(
            ResidentEvent::new(json!({"event": "runtime_reload_finished"})).block_on_full_queue()
        );
        assert!(ResidentEvent::new(json!({"event": "resident_fatal_error"})).block_on_full_queue());
        assert!(
            !ResidentEvent::new(json!({"event": "tcp_connection_failed"})).block_on_full_queue()
        );
        assert!(!ResidentEvent::new(json!({"event": "udp_exchange_failed"})).block_on_full_queue());
    }
}
