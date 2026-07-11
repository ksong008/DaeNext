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

pub(crate) fn scan_log_entries_from_cursor(
    config_dir: &Path,
    cursor: ProductLogScanCursor,
    after_id: u64,
    mut on_entry: impl FnMut(ProductLogEntry) -> io::Result<()>,
) -> io::Result<ProductLogScanState> {
    let log_file = product_log_file(config_dir);
    let mut file = match fs::File::open(&log_file) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ProductLogScanState {
                cursor: ProductLogScanCursor::start(),
                max_seen_id: after_id,
                reset: cursor != ProductLogScanCursor::start(),
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
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        next_offset = next_offset.saturating_add(read as u64);
        let Some(entry) = parse_log_entry_line(&line) else {
            continue;
        };
        if entry.id > max_seen_id {
            max_seen_id = entry.id;
        }
        if entry.id > after_id {
            on_entry(entry)?;
        }
    }
    Ok(ProductLogScanState {
        cursor: ProductLogScanCursor {
            offset: next_offset,
            identity: Some(identity),
        },
        max_seen_id,
        reset,
    })
}
