use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

pub(crate) type ResidentEventLogSink = Arc<dyn Fn(&Value) + Send + Sync + 'static>;

static EVENT_LOG_SINK: OnceLock<Mutex<Option<ResidentEventLogSink>>> = OnceLock::new();

pub(crate) fn set_event_log_sink(sink: Option<ResidentEventLogSink>) {
    let slot = EVENT_LOG_SINK.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = slot.lock() {
        *guard = sink;
    }
}

pub(super) fn append_event(path: &Path, lock: &Mutex<()>, mut value: Value) {
    {
        let Ok(_guard) = lock.lock() else {
            return;
        };
        if let Value::Object(map) = &mut value {
            map.entry("timestampUnix".to_owned())
                .or_insert_with(|| json!(current_unix()));
        }
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{value}");
        }
    }

    if let Some(sink) = event_log_sink() {
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
