use super::*;

/// Reclaim old versions' hard-link pins. Current snapshots create no directories.
/// Ignore symlinks and invalid names. Legacy pins have a one-day lifetime cap.
pub(super) fn cleanup_abandoned_snapshots(config_dir: &Path) -> io::Result<usize> {
    let entries = match fs::read_dir(config_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut cleaned = 0;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        let Some((pid, serial)) = name
            .to_str()
            .and_then(|name| name.strip_prefix(".daed-log-snapshot-"))
            .and_then(|suffix| suffix.split_once('-'))
        else {
            continue;
        };
        let Ok(pid) = pid.parse::<i32>() else {
            continue;
        };
        if pid <= 0 || serial.parse::<u64>().is_err() {
            continue;
        }
        #[cfg(unix)]
        {
            // ESRCH alone proves absence; EPERM still denotes a live process.
            let absent = unsafe { libc::kill(pid, 0) } == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            let expired = entry
                .metadata()
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|mtime| mtime.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_secs(86400));
            if (absent || expired) && fs::remove_dir_all(entry.path()).is_ok() {
                cleaned += 1;
            }
        }
    }
    Ok(cleaned)
}

#[cfg(all(test, unix))]
#[path = "snapshot_cleanup_tests.rs"]
mod tests;
