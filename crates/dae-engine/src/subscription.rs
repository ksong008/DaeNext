use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

pub const SUBSCRIPTION_RESOLVE_CONCURRENCY: usize = 6;

pub fn cleanup_subscription_persist_files(
    config_dir: impl AsRef<Path>,
    active_tags: &HashSet<String>,
) -> io::Result<Vec<String>> {
    let persist_dir = config_dir.as_ref().join("persist.d");
    let entries = match fs::read_dir(&persist_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut remaining = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let tag = file_name.strip_suffix(".sub").unwrap_or(&file_name);
        if active_tags.contains(tag) {
            remaining.push(file_name.into_owned());
            continue;
        }

        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }

    remaining.sort();
    Ok(remaining)
}
