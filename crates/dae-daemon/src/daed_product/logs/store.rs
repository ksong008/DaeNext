use super::*;
use std::time::SystemTime;

type SegmentCache = Option<(ProductLogContentVersion, Arc<[ProductLogSegmentFile]>)>;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProductLogFileIdentity(
    #[cfg(unix)] (u64, u64),
    #[cfg(not(unix))] Option<SystemTime>,
);
impl ProductLogFileIdentity {
    pub(super) fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            Self((metadata.dev(), metadata.ino()))
        }
        #[cfg(not(unix))]
        {
            Self(metadata.created().ok())
        }
    }
}

type LogCount = (ProductLogFileIdentity, u64, i64);

#[derive(Default)]
pub(super) struct ProductLogStore {
    mutation: Mutex<()>,
    scan: Mutex<()>,
    count: Mutex<Option<LogCount>>,
    pub(super) segment_cache: Mutex<SegmentCache>,
    pub(super) parsed_cache: Mutex<super::parsed_cache::ParsedLogCache>,
}

impl ProductLogStore {
    pub(super) fn invalidate_segments(&self) -> io::Result<()> {
        log_lock(&self.segment_cache)?.take();
        Ok(())
    }
    pub(super) fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, ()>> {
        log_lock(&self.mutation)
    }

    pub(super) fn publish_count(
        &self,
        identity: Option<ProductLogFileIdentity>,
        bytes: u64,
        count: usize,
    ) -> io::Result<()> {
        *log_lock(&self.count)? =
            identity.map(|identity| (identity, bytes, count.min(i64::MAX as usize) as i64));
        Ok(())
    }

    pub(super) fn cached_count(&self, metadata: &fs::Metadata) -> io::Result<Option<i64>> {
        let value = log_lock(&self.count)?;
        Ok(value
            .filter(|(identity, bytes, _)| {
                *identity == ProductLogFileIdentity::from_metadata(metadata)
                    && *bytes == metadata.len()
            })
            .map(|(_, _, count)| count))
    }
}

static STORES: OnceLock<Mutex<HashMap<PathBuf, std::sync::Weak<ProductLogStore>>>> =
    OnceLock::new();

pub(super) fn product_log_store(config_dir: &Path) -> io::Result<Arc<ProductLogStore>> {
    let path = product_log_dir(config_dir);
    // Canonicalize existing directories so symlink aliases share one writer lock.
    let key = fs::canonicalize(&path).unwrap_or(path);
    let mut stores = log_lock(STORES.get_or_init(|| Mutex::new(HashMap::new())))?;
    if let Some(store) = stores.get(&key).and_then(std::sync::Weak::upgrade) {
        return Ok(store);
    }
    stores.retain(|_, value| value.strong_count() > 0);
    let store = Arc::new(ProductLogStore::default());
    stores.insert(key, Arc::downgrade(&store));
    Ok(store)
}

// Serialize full scans separately from writers. A reader holds the active file
// plus at most one sealed segment FD. File identity is checked after open;
// structural changes restart the query instead of mixing different generations.
const MAX_SNAPSHOT_FILES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProductLogContentVersion {
    identity: ProductLogFileIdentity,
    bytes: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    changed: (i64, i64),
}
impl ProductLogContentVersion {
    pub(super) fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            identity: ProductLogFileIdentity::from_metadata(metadata),
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

pub(super) fn snapshot_changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "product log snapshot generation changed",
    )
}

pub(super) enum ProductLogSnapshotFile {
    Active(std::io::Take<fs::File>),
    Sealed(ProductLogSegmentFile),
}
impl ProductLogSnapshotFile {
    pub(super) fn sealed_version(&self) -> Option<ProductLogContentVersion> {
        match self {
            Self::Sealed(segment) => Some(segment.version),
            Self::Active(_) => None,
        }
    }
    pub(super) fn open(self) -> io::Result<std::io::Take<fs::File>> {
        match self {
            Self::Active(file) => Ok(file),
            Self::Sealed(segment) => {
                let file = fs::File::open(&segment.path).map_err(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        snapshot_changed()
                    } else {
                        error
                    }
                })?;
                if ProductLogContentVersion::from_metadata(&file.metadata()?) != segment.version {
                    return Err(snapshot_changed());
                }
                Ok(file.take(segment.version.bytes))
            }
        }
    }
}

pub(super) struct ProductLogSnapshotFiles {
    segments: Arc<[ProductLogSegmentFile]>,
    active: Option<std::io::Take<fs::File>>,
    remaining: std::ops::Range<usize>,
}
impl Iterator for ProductLogSnapshotFiles {
    type Item = ProductLogSnapshotFile;
    fn next(&mut self) -> Option<Self::Item> {
        self.remaining
            .next()
            .map(|index| ProductLogSnapshotFile::Sealed(self.segments[index].clone()))
            .or_else(|| self.active.take().map(ProductLogSnapshotFile::Active))
    }
}
impl DoubleEndedIterator for ProductLogSnapshotFiles {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.active
            .take()
            .map(ProductLogSnapshotFile::Active)
            .or_else(|| {
                self.remaining
                    .next_back()
                    .map(|index| ProductLogSnapshotFile::Sealed(self.segments[index].clone()))
            })
    }
}

pub(super) struct ProductLogSnapshot {
    pub(super) first_visible_id: u64,
    pub(super) files: ProductLogSnapshotFiles,
    pub(super) store: Arc<ProductLogStore>,
}

pub(super) fn with_product_log_snapshot<T>(
    config_dir: &Path,
    mut scan: impl FnMut(ProductLogSnapshot) -> io::Result<T>,
) -> io::Result<T> {
    let store = product_log_store(config_dir)?;
    let _reader = log_lock(&store.scan)?;
    for _ in 0..3 {
        let (snapshot, directory_version, active_version) = {
            let _guard = store.lock()?;
            let segments = product_log_segments_shared(config_dir)?;
            if segments.len() >= MAX_SNAPSHOT_FILES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "product log snapshot segment limit exceeded",
                ));
            }
            let mut active_file = None;
            let active = match fs::File::open(product_log_file(config_dir)) {
                Ok(file) => {
                    let metadata = file.metadata()?;
                    let version = ProductLogContentVersion::from_metadata(&metadata);
                    active_file = Some(file.take(metadata.len()));
                    Some(version)
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            let directory_version = content_version(&product_log_dir(config_dir))?;
            let first_visible_id =
                cached_log_visible_first_id(&product_log_file(config_dir))?.unwrap_or(0);
            (
                ProductLogSnapshot {
                    first_visible_id,
                    files: ProductLogSnapshotFiles {
                        remaining: 0..segments.len(),
                        segments,
                        active: active_file,
                    },
                    store: Arc::clone(&store),
                },
                directory_version,
                active,
            )
        };
        let visible = snapshot.first_visible_id;
        #[cfg(test)]
        observe_log_reader_enumeration();
        let result = scan(snapshot);
        let stable = {
            let _guard = store.lock()?;
            content_version(&product_log_dir(config_dir))? == directory_version
                && match (
                    active_version,
                    content_version(&product_log_file(config_dir))?,
                ) {
                    (None, None) => true,
                    (Some(captured), Some(current)) => {
                        current.identity == captured.identity
                            && current.bytes >= captured.bytes
                            && (current.bytes > captured.bytes || current == captured)
                    }
                    _ => false,
                }
                && cached_log_visible_first_id(&product_log_file(config_dir))?.unwrap_or(0)
                    == visible
        };
        if stable
            && !result.as_ref().is_err_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::UnexpectedEof
                )
            })
        {
            return result;
        }
        // Discard any partially parsed result and rebuild the directory inventory.
        *log_lock(&store.segment_cache)? = None;
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "product logs changed during three snapshot attempts",
    ))
}

fn content_version(path: &Path) -> io::Result<Option<ProductLogContentVersion>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(ProductLogContentVersion::from_metadata(&metadata))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn log_lock<T>(mutex: &Mutex<T>) -> io::Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other("product log lock poisoned"))
}
