use super::*;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductLogFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    created: Option<SystemTime>,
}

impl ProductLogFileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(not(unix))]
            created: metadata.created().ok(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProductLogScanCursor {
    offset: u64,
    identity: Option<ProductLogFileIdentity>,
}

impl ProductLogScanCursor {
    pub(crate) fn start() -> Self {
        Self::default()
    }

    pub(crate) fn at_end(config_dir: &Path) -> io::Result<Self> {
        let path = product_log_file(config_dir);
        match fs::metadata(path) {
            Ok(metadata) => Ok(Self {
                offset: metadata.len(),
                identity: Some(ProductLogFileIdentity::from_metadata(&metadata)),
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
    let log_file = product_log_file(config_dir);
    let mut file = match fs::File::open(&log_file) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ProductLogControlledScan {
                state: ProductLogScanState {
                    cursor: ProductLogScanCursor::start(),
                    max_seen_id: after_id,
                    reset: cursor != ProductLogScanCursor::start(),
                },
                reached_eof: true,
            });
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    let identity = ProductLogFileIdentity::from_metadata(&metadata);
    let reset = cursor.identity != Some(identity) || cursor.offset > metadata.len();
    let mut next_offset = if reset { 0 } else { cursor.offset };
    if next_offset > 0 {
        file.seek(SeekFrom::Start(next_offset))?;
    }
    let mut reader = io::BufReader::new(file);
    let mut max_seen_id = after_id;
    let mut scanned_lines = 0_usize;
    let mut reached_eof = false;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            reached_eof = true;
            break;
        }
        scanned_lines = scanned_lines.saturating_add(1);
        next_offset = next_offset.saturating_add(read as u64);
        if let Some(entry) = parse_log_entry_line(&line) {
            if entry.id > max_seen_id {
                max_seen_id = entry.id;
            }
            if entry.id > after_id {
                on_entry(entry)?;
            }
        }
        if max_scanned_lines.is_some_and(|limit| scanned_lines >= limit) {
            break;
        }
    }
    Ok(ProductLogControlledScan {
        state: ProductLogScanState {
            cursor: ProductLogScanCursor {
                offset: next_offset,
                identity: Some(identity),
            },
            max_seen_id,
            reset,
        },
        reached_eof,
    })
}
