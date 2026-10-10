use super::*;

#[cfg(test)]
pub(crate) fn scan_log_entries_from_cursor(
    config_dir: &Path,
    cursor: ProductLogScanCursor,
    after_id: u64,
    mut on_entry: impl FnMut(ProductLogEntry) -> io::Result<()>,
) -> io::Result<ProductLogScanState> {
    Ok(
        scan_log_entries_from_cursor_limited(config_dir, cursor, after_id, None, |entry| {
            on_entry(entry)
        })?
        .state,
    )
}
