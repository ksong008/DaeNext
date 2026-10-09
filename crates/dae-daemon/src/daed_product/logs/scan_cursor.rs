use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProductLogScanCursor {
    offset: u64,
    identity: Option<ProductLogFileIdentity>,
    file_index: usize,
}

impl ProductLogScanCursor {
    pub(crate) fn start() -> Self {
        Self::default()
    }

    pub(crate) fn at_end(config_dir: &Path) -> io::Result<Self> {
        let store = product_log_store(config_dir)?;
        let _guard = store.lock()?;
        let path = product_log_file(config_dir);
        match fs::metadata(path) {
            Ok(metadata) => Ok(Self {
                offset: metadata.len(),
                identity: Some(ProductLogFileIdentity::from_metadata(&metadata)),
                file_index: product_log_segments(config_dir)?.len(),
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::start()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductLogScanState {
    pub(crate) cursor: ProductLogScanCursor,
    pub(crate) max_seen_id: u64,
    pub(crate) reset: bool,
}

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

pub(crate) struct ProductLogScanBatch {
    pub(crate) state: ProductLogScanState,
    pub(crate) entries: Vec<ProductLogEntry>,
    pub(crate) reached_eof: bool,
}

pub(crate) fn read_log_entry_batch_from_cursor(
    config_dir: &Path,
    cursor: ProductLogScanCursor,
    after_id: u64,
    max_scanned_lines: usize,
) -> io::Result<ProductLogScanBatch> {
    let max_scanned_lines = max_scanned_lines.max(1);
    let mut entries = Vec::with_capacity(max_scanned_lines);
    let scan = scan_log_entries_from_cursor_limited(
        config_dir,
        cursor,
        after_id,
        Some(max_scanned_lines),
        |entry| {
            entries.push(entry);
            Ok(())
        },
    )?;
    Ok(ProductLogScanBatch {
        state: scan.state,
        entries,
        reached_eof: scan.reached_eof,
    })
}

struct ProductLogControlledScan {
    state: ProductLogScanState,
    reached_eof: bool,
}

fn scan_log_entries_from_cursor_limited(
    config_dir: &Path,
    cursor: ProductLogScanCursor,
    after_id: u64,
    max_scanned_lines: Option<usize>,
    mut on_entry: impl FnMut(ProductLogEntry) -> io::Result<()>,
) -> io::Result<ProductLogControlledScan> {
    // SSE limits each scan batch; no lock survives the return or a network write.
    let store = product_log_store(config_dir)?;
    let _guard = store.lock()?;
    let log_file = product_log_file(config_dir);
    let segments = product_log_segments(config_dir)?;
    let mut files: Vec<_> = segments
        .iter()
        .map(|segment| segment.path.clone())
        .collect();
    files.push(log_file.clone());
    #[cfg(test)]
    observe_log_reader_enumeration();
    let first_visible_id = cached_log_visible_first_id(&log_file)?.unwrap_or(0);
    let mut file_index = cursor.file_index.min(segments.len());
    let mut reset = false;
    let mut next_offset = cursor.offset;
    if cursor == ProductLogScanCursor::start() && !segments.is_empty() {
        file_index = segments
            .iter()
            .position(|segment| segment.last_id > after_id)
            .unwrap_or(segments.len());
    } else if cursor.identity.is_some() {
        let matches_cursor = fs::metadata(&files[file_index])
            .ok()
            .is_some_and(|metadata| {
                cursor.identity == Some(ProductLogFileIdentity::from_metadata(&metadata))
                    && cursor.offset <= metadata.len()
            });
        if !matches_cursor {
            reset = true;
            file_index = segments
                .iter()
                .position(|segment| segment.last_id > after_id)
                .unwrap_or(segments.len());
            next_offset = 0;
        }
    }
    let mut max_seen_id = after_id;
    let mut scanned_lines = 0_usize;
    let mut line = Vec::new();
    while file_index < files.len() {
        let mut file = match fs::File::open(&files[file_index]) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if file_index == segments.len() {
                    break;
                }
                file_index += 1;
                next_offset = 0;
                reset = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        let identity = ProductLogFileIdentity::from_metadata(&metadata);
        if next_offset > 0 {
            file.seek(SeekFrom::Start(next_offset))?;
        }
        let mut reader = io::BufReader::new(file);
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            scanned_lines = scanned_lines.saturating_add(1);
            next_offset = next_offset.saturating_add(read as u64);
            if let Ok(text) = std::str::from_utf8(&line)
                && let Some(entry) = parse_log_entry_line(text)
                && entry.id >= first_visible_id
            {
                if entry.id > max_seen_id {
                    max_seen_id = entry.id;
                }
                if entry.id > after_id {
                    on_entry(entry)?;
                }
            }
            if max_scanned_lines.is_some_and(|limit| scanned_lines >= limit) {
                return Ok(ProductLogControlledScan {
                    state: ProductLogScanState {
                        cursor: ProductLogScanCursor {
                            offset: next_offset,
                            identity: Some(identity),
                            file_index,
                        },
                        max_seen_id,
                        reset,
                    },
                    reached_eof: false,
                });
            }
        }
        if file_index == segments.len() {
            return Ok(ProductLogControlledScan {
                state: ProductLogScanState {
                    cursor: ProductLogScanCursor {
                        offset: next_offset,
                        identity: Some(identity),
                        file_index,
                    },
                    max_seen_id,
                    reset,
                },
                reached_eof: true,
            });
        }
        file_index += 1;
        next_offset = 0;
    }
    Ok(ProductLogControlledScan {
        state: ProductLogScanState {
            cursor: ProductLogScanCursor::start(),
            max_seen_id,
            reset: reset || cursor != ProductLogScanCursor::start(),
        },
        reached_eof: true,
    })
}
