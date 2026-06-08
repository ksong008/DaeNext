use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

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

pub(crate) fn clear_resident_event_log_file(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, [])?;
    EVENT_LOG_APPEND_COUNT.store(0, Ordering::Relaxed);
    Ok(())
}

pub(super) fn append_event(path: &Path, lock: &Mutex<()>, mut value: Value) {
    let decision = event_log_decision(&value);
    {
        let Ok(_guard) = lock.lock() else {
            return;
        };
        if let Value::Object(map) = &mut value {
            map.entry("timestampUnix".to_owned())
                .or_insert_with(|| json!(current_unix()));
            if let Some(level) = decision.level.as_deref() {
                map.entry("residentLogLevel".to_owned())
                    .or_insert_with(|| json!(level));
            }
        }
        if decision.persist {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{value}");
            }
            let count = EVENT_LOG_APPEND_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            let should_prune_by_count = count % RESIDENT_EVENT_LOG_PRUNE_INTERVAL == 0;
            let should_prune_by_size = fs::metadata(path)
                .map(|metadata| metadata.len() > decision.max_bytes)
                .unwrap_or(false);
            if should_prune_by_count || should_prune_by_size {
                let _ = prune_resident_event_log_file(path);
            }
        }
    }

    if decision.persist
        && let Some(sink) = event_log_sink()
    {
        sink(&value);
    }
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

pub(crate) fn prune_resident_event_log_file(path: &Path) -> io::Result<()> {
    let decision = normalize_event_log_decision(event_log_decision(&Value::Null));
    prune_resident_event_log_file_with_limits(path, decision.max_entries, decision.max_bytes)
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
    let mut lines = data
        .trim_end_matches('\n')
        .lines()
        .filter(|line| resident_event_line_allowed_by_policy(line))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if lines.len() > max_entries {
        lines = lines.split_off(lines.len() - max_entries);
    }
    let mut pruned = lines.join("\n");
    if !pruned.is_empty() {
        pruned.push('\n');
    }
    let tmp_path = path.with_extension("jsonl.tmp");
    fs::write(&tmp_path, pruned)?;
    fs::rename(tmp_path, path)
}

fn resident_event_line_allowed_by_policy(line: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    event_log_decision(&value).persist
}

fn read_tail_bytes(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(String::new());
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
    Ok(String::from_utf8_lossy(&data).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_event_log_policy_filters_and_prunes_file() {
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
        prune_resident_event_log_file(&path).unwrap();

        let lines = fs::read_to_string(&path).unwrap();
        assert!(!lines.contains("\"value\":1"));
        assert!(!lines.contains("\"value\":2"));
        assert!(lines.contains("\"value\":3"));
        assert!(lines.contains("\"value\":4"));
        assert!(lines.contains("\"residentLogLevel\":\"info\""));

        clear_resident_event_log_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "");

        set_event_log_policy(None);
        fs::remove_dir_all(dir).unwrap();
    }
}
