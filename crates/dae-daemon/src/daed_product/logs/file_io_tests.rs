use super::*;

#[path = "snapshot_response_tests.rs"]
mod snapshot_response_tests;

#[cfg(test)]
thread_local! {
    pub(crate) static LOG_CLEAR_INTERRUPT_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static LOG_CLEAR_INTERRUPT_DURING_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn interrupt_log_clear_after_rename() -> io::Result<()> {
    if LOG_CLEAR_INTERRUPT_AFTER_RENAME.replace(false) {
        return Err(io::Error::other("injected interrupted log clear"));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    pub(crate) static LOG_READER_AFTER_ENUMERATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn observe_log_reader_enumeration() {
    if let Some(callback) = LOG_READER_AFTER_ENUMERATION.with(|slot| slot.borrow_mut().take()) {
        callback();
    }
}

#[cfg(test)]
pub(crate) fn prune_log_file_with_settings(
    path: &Path,
    max_entries: i64,
    max_bytes: i64,
) -> io::Result<()> {
    let max_entries = normalize_log_max_entries(max_entries) as usize;
    let max_bytes = normalize_log_max_bytes(max_bytes) as u64;
    let data = match read_tail_bytes(path, max_bytes) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if data.is_empty() {
        return Ok(());
    }
    #[cfg(test)]
    observe_log_prune_rewrite(path);
    let tmp_path = path.with_extension("jsonl.tmp");
    write_pruned_log_tail(&tmp_path, &data, max_entries)?;
    set_log_file_permissions(&tmp_path)?;
    fs::rename(tmp_path, path)
}

#[cfg(test)]
fn write_pruned_log_tail(path: &Path, data: &[u8], max_entries: usize) -> io::Result<()> {
    let mut ranges = Vec::new();
    let mut start = 0_usize;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start + offset)
            .unwrap_or(data.len());
        if end > start {
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
