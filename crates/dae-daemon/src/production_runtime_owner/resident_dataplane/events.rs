use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
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
const RESIDENT_EVENT_LOG_PRUNE_INTERVAL: u64 = 256;

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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, [])?;
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
    let decision = normalize_event_log_decision(event_log_decision(&Value::Null));
    prune_resident_event_log_file_with_limits(path, decision.max_entries, decision.max_bytes)
}

fn persist_resident_event_direct(
    path: &Path,
    lock: &Mutex<()>,
    event: ResidentEvent,
) -> io::Result<ResidentEventPersistOutcome> {
    let persist = event.should_persist();
    if !persist {
        return Ok(ResidentEventPersistOutcome {
            persisted: false,
            pruned: false,
        });
    }
    let max_bytes = event.max_bytes();
    let max_entries = event.max_entries();
    let value = event.into_serializable_value();
    let mut pruned = false;
    {
        let _guard = lock
            .lock()
            .map_err(|_| io::Error::other("resident event log lock poisoned"))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{value}")?;
        let count = EVENT_LOG_APPEND_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let should_prune_by_count = count % RESIDENT_EVENT_LOG_PRUNE_INTERVAL == 0;
        let should_prune_by_size = fs::metadata(path)
            .map(|metadata| metadata.len() > max_bytes)
            .unwrap_or(false);
        if should_prune_by_count || should_prune_by_size {
            prune_resident_event_log_file_with_limits(path, max_entries, max_bytes)?;
            pruned = true;
        }
    }

    if let Some(sink) = event_log_sink() {
        sink(&value);
    }

    Ok(ResidentEventPersistOutcome {
        persisted: true,
        pruned,
    })
}

fn prune_resident_event_log_file_with_limits(
    path: &Path,
    max_entries: usize,
    max_bytes: u64,
) -> io::Result<()> {
    let data = match read_tail_bytes(path, max_bytes) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let tmp_path = path.with_extension("jsonl.tmp");
    write_pruned_event_tail(&tmp_path, &data, max_entries)?;
    fs::rename(tmp_path, path)
}

fn resident_event_line_allowed_by_policy(line: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    ResidentEvent::new(value).should_persist()
}

fn write_pruned_event_tail(path: &Path, data: &[u8], max_entries: usize) -> io::Result<()> {
    let mut ranges = Vec::new();
    let mut start = 0_usize;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start + offset)
            .unwrap_or(data.len());
        if end > start
            && let Ok(line) = std::str::from_utf8(&data[start..end])
            && resident_event_line_allowed_by_policy(line)
        {
            ranges.push((start, end));
        }
        start = end.saturating_add(1);
    }
    let keep_from = ranges.len().saturating_sub(max_entries);
    let file = fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    for (start, end) in ranges.into_iter().skip(keep_from) {
        writer.write_all(&data[start..end])?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}

fn read_tail_bytes(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(Vec::new());
    }
    let offset = size.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(offset))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    if offset > 0
        && let Some(newline) = data.iter().position(|byte| *byte == b'\n')
    {
        data = data.split_off(newline + 1);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    static EVENT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn event_test_guard() -> std::sync::MutexGuard<'static, ()> {
        EVENT_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap()
    }

    #[test]
    fn resident_event_log_policy_filters_and_prunes_file() {
        let _guard = event_test_guard();
        let dir = std::env::temp_dir().join(format!(
            "resident-event-log-test-{}-{}",
            std::process::id(),
            current_unix()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let lock = Mutex::new(());
        set_event_log_sink(None);
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

        let lines = fs::read_to_string(&path).unwrap();
        assert!(!lines.contains("\"value\":1"));
        assert!(!lines.contains("\"value\":2"));
        assert!(lines.contains("\"value\":3"));
        assert!(lines.contains("\"value\":4"));
        assert!(lines.contains("\"residentLogLevel\":\"info\""));

        clear_resident_event_log_file_direct(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "");

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
        set_event_log_sink(None);
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

        let lines = fs::read_to_string(&path).unwrap();
        assert!(!lines.contains("tcp_connection_finished"));
        assert!(lines.contains("tcp_connection_failed"));
        assert!(lines.contains("\"lifecycleClass\":\"error\""));
        assert!(lines.contains("\"severity\":\"error\""));
        assert!(lines.contains("\"priority\":90"));
        assert!(lines.contains("\"residentLogLevel\":\"debug\""));

        set_event_log_policy(None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resident_events_bounded_writer_records_metrics_and_flushes_jsonl() {
        let _guard = event_test_guard();
        let dir = std::env::temp_dir().join(format!(
            "resident-event-writer-test-{}-{}",
            std::process::id(),
            current_unix()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let fallback_lock = Mutex::new(());
        set_event_log_sink(None);
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

        let lines = fs::read_to_string(&path).unwrap();
        assert!(lines.contains("tcp_worker_started"));
        assert!(lines.contains("tcp_connection_failed"));
        assert!(lines.contains("\"eventSchemaVersion\":1"));
        assert!(lines.contains("\"lifecycleClass\":\"startup\""));
        assert!(lines.contains("\"lifecycleClass\":\"error\""));

        fs::remove_dir_all(dir).unwrap();
    }
}
