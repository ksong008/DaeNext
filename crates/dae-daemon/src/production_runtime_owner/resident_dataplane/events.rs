use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
#[cfg(test)]
use serde_json::json;

mod model;
mod writer;
mod writer_metrics;

use self::model::{ResidentEvent, ResidentEventLifecycleClass, ResidentEventPersistOutcome};
pub(crate) use self::writer::ResidentEventWriterRuntime;

pub(crate) type ResidentEventLogSink = Arc<dyn Fn(&Value) + Send + Sync + 'static>;
pub(crate) type ResidentEventLogPolicy =
    Arc<dyn Fn(&Value) -> ResidentEventLogDecision + Send + Sync + 'static>;

const DEFAULT_RESIDENT_EVENT_LOG_MAX_ENTRIES: usize = 10_000;
const DEFAULT_RESIDENT_EVENT_LOG_MAX_BYTES: u64 = 50 * 1024 * 1024;

static EVENT_LOG_SINK: OnceLock<Mutex<Option<ResidentEventLogSink>>> = OnceLock::new();
static EVENT_LOG_POLICY: OnceLock<Mutex<Option<ResidentEventLogPolicy>>> = OnceLock::new();
static EVENT_LOG_APPEND_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub(crate) struct ResidentEventLogDecision {
    pub(crate) persist: bool,
    pub(crate) level: Option<String>,
    pub(crate) max_entries: usize,
    pub(crate) max_bytes: u64,
}

impl Default for ResidentEventLogDecision {
    fn default() -> Self {
        Self {
            persist: true,
            level: None,
            max_entries: DEFAULT_RESIDENT_EVENT_LOG_MAX_ENTRIES,
            max_bytes: DEFAULT_RESIDENT_EVENT_LOG_MAX_BYTES,
        }
    }
}

pub(crate) fn set_event_log_sink(sink: Option<ResidentEventLogSink>) {
    let slot = EVENT_LOG_SINK.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = slot.lock() {
        *guard = sink;
    }
}

pub(crate) fn set_event_log_policy(policy: Option<ResidentEventLogPolicy>) {
    let slot = EVENT_LOG_POLICY.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = slot.lock() {
        *guard = policy;
    }
}

fn clear_resident_event_log_file_direct(path: &Path) -> io::Result<()> {
    let _ = path;
    EVENT_LOG_APPEND_COUNT.store(0, Ordering::Relaxed);
    Ok(())
}

pub(super) fn append_event(path: &Path, lock: &Mutex<()>, value: Value) {
    let event = ResidentEvent::new(value);
    if let Some(writer) = writer::active_resident_event_writer_for_path(path) {
        writer.submit(event);
        return;
    }
    let _ = persist_resident_event_direct(path, lock, event);
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn event_log_sink() -> Option<ResidentEventLogSink> {
    EVENT_LOG_SINK
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|guard| guard.clone()))
}

fn event_log_policy() -> Option<ResidentEventLogPolicy> {
    EVENT_LOG_POLICY
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|guard| guard.clone()))
}

fn event_log_decision(value: &Value) -> ResidentEventLogDecision {
    event_log_policy()
        .map(|policy| normalize_event_log_decision(policy(value)))
        .unwrap_or_default()
}

fn normalize_event_log_decision(
    mut decision: ResidentEventLogDecision,
) -> ResidentEventLogDecision {
    decision.max_entries = decision.max_entries.max(1);
    decision.max_bytes = decision.max_bytes.max(1024);
    decision
}

fn prune_resident_event_log_file_direct(path: &Path) -> io::Result<()> {
    let _ = path;
    Ok(())
}

fn persist_resident_event_direct(
    path: &Path,
    lock: &Mutex<()>,
    event: ResidentEvent,
) -> io::Result<ResidentEventPersistOutcome> {
    let _ = (path, lock);
    let persist = event.should_persist();
    if !persist {
        return Ok(ResidentEventPersistOutcome {
            persisted: false,
            pruned: false,
        });
    }
    let value = event.into_serializable_value();
    EVENT_LOG_APPEND_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Some(sink) = event_log_sink() {
        sink(&value);
    }

    Ok(ResidentEventPersistOutcome {
        persisted: true,
        pruned: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    static EVENT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn event_test_guard() -> std::sync::MutexGuard<'static, ()> {
        EVENT_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap()
    }

    #[test]
    fn resident_event_log_policy_filters_and_dispatches_to_sink() {
        let _guard = event_test_guard();
        let dir = std::env::temp_dir().join(format!(
            "resident-event-log-test-{}-{}",
            std::process::id(),
            current_unix()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let lock = Mutex::new(());
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let sink_captured = Arc::clone(&captured);
        set_event_log_sink(Some(Arc::new(move |event| {
            sink_captured.lock().unwrap().push(event.clone());
        })));
        set_event_log_policy(Some(Arc::new(|event| ResidentEventLogDecision {
            persist: event.get("event").and_then(Value::as_str) != Some("drop"),
            level: Some("info".to_owned()),
            max_entries: 2,
            max_bytes: 4096,
        })));

        append_event(&path, &lock, json!({"event": "keep", "value": 1}));
        append_event(&path, &lock, json!({"event": "drop", "value": 2}));
        append_event(&path, &lock, json!({"event": "keep", "value": 3}));
        append_event(&path, &lock, json!({"event": "keep", "value": 4}));
        prune_resident_event_log_file_direct(&path).unwrap();

        let events = captured.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["value"], json!(1));
        assert_eq!(events[1]["value"], json!(3));
        assert_eq!(events[2]["value"], json!(4));
        assert_eq!(events[0]["residentLogLevel"], json!("info"));
        drop(events);

        clear_resident_event_log_file_direct(&path).unwrap();
        assert!(!path.exists());

        set_event_log_sink(None);
        set_event_log_policy(None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resident_events_preserve_lossless_events_when_policy_filters() {
        let _guard = event_test_guard();
        let dir = std::env::temp_dir().join(format!(
            "resident-event-lossless-test-{}-{}",
            std::process::id(),
            current_unix()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let lock = Mutex::new(());
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let sink_captured = Arc::clone(&captured);
        set_event_log_sink(Some(Arc::new(move |event| {
            sink_captured.lock().unwrap().push(event.clone());
        })));
        set_event_log_policy(Some(Arc::new(|_| ResidentEventLogDecision {
            persist: false,
            level: Some("debug".to_owned()),
            max_entries: 100,
            max_bytes: 4096,
        })));

        append_event(&path, &lock, json!({"event": "tcp_connection_finished"}));
        append_event(
            &path,
            &lock,
            json!({"event": "tcp_connection_failed", "error": "sample"}),
        );

        let events = captured.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event"], json!("tcp_connection_failed"));
        assert_eq!(events[0]["lifecycleClass"], json!("error"));
        assert_eq!(events[0]["severity"], json!("error"));
        assert_eq!(events[0]["priority"], json!(90));
        assert_eq!(events[0]["residentLogLevel"], json!("debug"));
        assert!(!path.exists());

        set_event_log_sink(None);
        set_event_log_policy(None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resident_events_bounded_writer_records_metrics_and_dispatches_to_sink_without_jsonl_file() {
        let _guard = event_test_guard();
        let dir = std::env::temp_dir().join(format!(
            "resident-event-writer-test-{}-{}",
            std::process::id(),
            current_unix()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let fallback_lock = Mutex::new(());
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let sink_captured = Arc::clone(&captured);
        set_event_log_sink(Some(Arc::new(move |event| {
            sink_captured.lock().unwrap().push(event.clone());
        })));
        set_event_log_policy(None);
        let mut writer =
            ResidentEventWriterRuntime::start(path.clone(), Arc::new(Mutex::new(())), 64);

        append_event(
            &path,
            &fallback_lock,
            json!({"event": "tcp_worker_started"}),
        );
        append_event(
            &path,
            &fallback_lock,
            json!({"event": "tcp_connection_failed", "error": "sample"}),
        );
        let packet_event = ResidentEvent::new(json!({"event": "udp_packet_finished"}));
        assert_eq!(packet_event.class(), ResidentEventLifecycleClass::Packet);
        writer.prune().unwrap();
        let metrics = writer.metrics_snapshot();
        assert_eq!(metrics["owner"], "resident-event-writer");
        assert_eq!(metrics["queueCapacity"], 64);
        assert_eq!(metrics["persistedCount"], 2);
        assert_eq!(metrics["droppedCount"], 0);
        assert_eq!(metrics["lastWriteError"], Value::Null);
        let shutdown = writer.shutdown();
        assert_eq!(shutdown["status"], "pass");

        let events = captured.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event"], json!("tcp_worker_started"));
        assert_eq!(events[1]["event"], json!("tcp_connection_failed"));
        assert_eq!(events[0]["eventSchemaVersion"], json!(1));
        assert_eq!(events[0]["lifecycleClass"], json!("startup"));
        assert_eq!(events[1]["lifecycleClass"], json!("error"));
        assert!(!path.exists());

        set_event_log_sink(None);
        fs::remove_dir_all(dir).unwrap();
    }
}
