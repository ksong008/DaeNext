use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde_json::Value;

pub(super) fn append_event(path: &Path, lock: &Mutex<()>, value: Value) {
    let Ok(_guard) = lock.lock() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{value}");
    }
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}
