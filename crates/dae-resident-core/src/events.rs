use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::{ArcSwap, ArcSwapOption};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

mod model;
mod writer;
mod writer_metrics;

pub use self::model::ResidentEventKind;
pub use self::model::ResidentEventMetadata;
use self::model::{ResidentEvent, ResidentEventLifecycleClass, ResidentEventPersistOutcome};
pub use self::writer::{ResidentEventWriterHandle, ResidentEventWriterRuntime};

pub type ResidentEventLogSink = Arc<dyn Fn(&Value) + Send + Sync + 'static>;
pub type ResidentEventLogPolicy =
    Arc<dyn Fn(&Value) -> ResidentEventLogDecision + Send + Sync + 'static>;
pub type ResidentEventLogPrefilter =
    Arc<dyn Fn(ResidentEventMetadata) -> ResidentEventLogDecision + Send + Sync + 'static>;

const DEFAULT_RESIDENT_EVENT_LOG_MAX_ENTRIES: usize = 10_000;
const DEFAULT_RESIDENT_EVENT_LOG_MAX_BYTES: u64 = 50 * 1024 * 1024;

static EVENT_LOG_SINK: OnceLock<ArcSwapOption<ResidentEventLogSinkHolder>> = OnceLock::new();
static EVENT_LOG_POLICIES: OnceLock<ArcSwap<ResidentEventLogPolicies>> = OnceLock::new();
static EVENT_LOG_APPEND_COUNT: AtomicU64 = AtomicU64::new(0);

/// Per-event admission decision produced by the resident event log policy.
///
/// `max_entries` / `max_bytes` are **advisory** retention bounds carried for
/// the sink consumer (e.g. the daemon product log, which enforces its own
/// limits from its configuration). The resident events module is
/// dispatch-only: it retains no log file or buffer, so it does not hard-enforce
/// these bounds itself.
#[derive(Clone, Debug)]
pub struct ResidentEventLogDecision {
    pub persist: bool,
    pub level: Option<String>,
    pub max_entries: usize,
    pub max_bytes: u64,
}

#[derive(Default)]
struct ResidentEventLogPolicies {
    value: Option<ResidentEventLogPolicy>,
    prefilter: Option<ResidentEventLogPrefilter>,
}

struct ResidentEventLogSinkHolder {
    sink: ResidentEventLogSink,
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

pub fn set_event_log_sink(sink: Option<ResidentEventLogSink>) {
    EVENT_LOG_SINK
        .get_or_init(ArcSwapOption::empty)
        .store(sink.map(|sink| Arc::new(ResidentEventLogSinkHolder { sink })));
}

#[cfg(test)]
pub(crate) fn set_event_log_policy(policy: Option<ResidentEventLogPolicy>) {
    set_event_log_policies(policy, None);
}

pub fn set_event_log_policies(
    policy: Option<ResidentEventLogPolicy>,
    prefilter: Option<ResidentEventLogPrefilter>,
) {
    EVENT_LOG_POLICIES
        .get_or_init(|| ArcSwap::from_pointee(ResidentEventLogPolicies::default()))
        .store(Arc::new(ResidentEventLogPolicies {
            value: policy,
            prefilter,
        }));
}

/// No-op retained for control-plane compatibility; see
/// [`prune_resident_event_log_file_direct`].
///
/// File-based persistence was removed: resident events are dispatch-only to the
/// configured sink and the module retains no log file or buffer to clear. The
/// only in-module state is the (informational) append counter, which is reset
/// here. Reports success so the clear control-plane contract is preserved;
/// actual log retention is owned by the sink consumer (daemon product log).
fn clear_resident_event_log_file_direct(path: &Path) -> io::Result<()> {
    let _ = path;
    EVENT_LOG_APPEND_COUNT.store(0, Ordering::Relaxed);
    Ok(())
}

pub fn append_event(path: &Path, lock: &Mutex<()>, value: Value) {
    let event = ResidentEvent::new(value);
    append_resident_event(path, lock, event);
}

pub fn append_event_with_metadata<F>(
    path: &Path,
    lock: &Mutex<()>,
    metadata: ResidentEventMetadata,
    build: F,
) where
    F: FnOnce() -> Value,
{
    let Some(admission) = admit_event(metadata) else {
        return;
    };
    append_admitted_event(path, lock, admission, build());
}

pub enum ResidentEventAdmission {
    Legacy,
    Typed {
        metadata: ResidentEventMetadata,
        decision: ResidentEventLogDecision,
    },
}

pub fn admit_event(metadata: ResidentEventMetadata) -> Option<ResidentEventAdmission> {
    let Some(decision) = event_log_decision_from_metadata(metadata) else {
        return Some(ResidentEventAdmission::Legacy);
    };
    (decision.persist || metadata.lossless())
        .then_some(ResidentEventAdmission::Typed { metadata, decision })
}

pub fn append_admitted_event(
    path: &Path,
    lock: &Mutex<()>,
    admission: ResidentEventAdmission,
    value: Value,
) {
    let event = match admission {
        ResidentEventAdmission::Legacy => ResidentEvent::new(value),
        ResidentEventAdmission::Typed { metadata, decision } => {
            ResidentEvent::from_metadata(value, metadata, decision)
        }
    };
    append_resident_event(path, lock, event);
}

fn append_resident_event(path: &Path, lock: &Mutex<()>, event: ResidentEvent) {
    let event = match writer::submit_to_active_resident_event_writer(path, event) {
        Ok(()) => return,
        Err(event) => event,
    };
    let _ = persist_resident_event_direct(path, lock, event);
}

pub fn path_string(path: &Path) -> String {
    path.display().to_string()
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn dispatch_to_event_log_sink(value: &Value) {
    let Some(slot) = EVENT_LOG_SINK.get() else {
        return;
    };
    let sink = slot.load();
    if let Some(sink) = sink.as_ref() {
        (sink.sink)(value);
    }
}

fn event_log_decision(value: &Value) -> ResidentEventLogDecision {
    let Some(slot) = EVENT_LOG_POLICIES.get() else {
        return ResidentEventLogDecision::default();
    };
    let policies = slot.load();
    policies
        .value
        .as_ref()
        .map(|policy| normalize_event_log_decision(policy(value)))
        .unwrap_or_default()
}

fn event_log_decision_from_metadata(
    metadata: ResidentEventMetadata,
) -> Option<ResidentEventLogDecision> {
    let slot = EVENT_LOG_POLICIES.get()?;
    let policies = slot.load();
    policies
        .prefilter
        .as_ref()
        .map(|prefilter| normalize_event_log_decision(prefilter(metadata)))
}

/// Normalizes a policy decision to non-degenerate values.
///
/// `max_entries` / `max_bytes` are advisory retention bounds (see
/// [`ResidentEventLogDecision`]); the clamps guarantee that any consumer of a
/// decision never observes a zero or empty bound, even if the policy function
/// returns one.
fn normalize_event_log_decision(
    mut decision: ResidentEventLogDecision,
) -> ResidentEventLogDecision {
    decision.max_entries = decision.max_entries.max(1);
    decision.max_bytes = decision.max_bytes.max(1024);
    decision
}

/// No-op retained for control-plane compatibility.
///
/// File-based persistence was removed: resident events are dispatch-only to the
/// configured sink and the module retains no log file or buffer to prune.
/// Retention limits (`max_entries` / `max_bytes`) are enforced by the sink
/// consumer (daemon product log), not by this module. Reports success so the
/// prune control-plane contract is preserved.
fn prune_resident_event_log_file_direct(path: &Path) -> io::Result<()> {
    let _ = path;
    Ok(())
}

/// Dispatches a resident event to the configured sink; no file is written.
///
/// File persistence was replaced by sink dispatch: this counts the append and
/// forwards the serialized event to [`dispatch_to_event_log_sink`]. The caller
/// (writer thread or the no-writer fallback) observes
/// [`ResidentEventPersistOutcome`] to drive the persisted/filtered metrics.
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
    dispatch_to_event_log_sink(&value);

    Ok(ResidentEventPersistOutcome {
        persisted: true,
        pruned: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};

    static EVENT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    /// Serializes tests that mutate the global sink/policy singletons.
    pub(super) fn event_test_guard() -> std::sync::MutexGuard<'static, ()> {
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
    fn resident_event_prefilter_skips_json_construction() {
        let _guard = event_test_guard();
        let path = std::env::temp_dir().join(format!(
            "resident-event-prefilter-test-{}-{}",
            std::process::id(),
            current_unix()
        ));
        let lock = Mutex::new(());
        let built = AtomicBool::new(false);
        set_event_log_policies(
            Some(Arc::new(|_| ResidentEventLogDecision::default())),
            Some(Arc::new(|metadata| {
                assert_eq!(metadata.name(), "udp_packet_finished");
                ResidentEventLogDecision {
                    persist: false,
                    level: Some("debug".to_owned()),
                    max_entries: 100,
                    max_bytes: 4096,
                }
            })),
        );

        append_event_with_metadata(
            &path,
            &lock,
            ResidentEventMetadata::new(ResidentEventKind::UdpPacketFinished)
                .with_route_log_context(),
            || {
                built.store(true, Ordering::Relaxed);
                json!({"event": "udp_packet_finished"})
            },
        );

        assert!(!built.load(Ordering::Relaxed));
        assert!(!path.exists());
        set_event_log_policies(None, None);
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
