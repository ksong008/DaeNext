use super::*;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProductLogFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    created: Option<SystemTime>,
}

impl ProductLogFileIdentity {
    pub(super) fn from_metadata(metadata: &fs::Metadata) -> Self {
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

type LogCount = (ProductLogFileIdentity, u64, i64);

#[derive(Default)]
pub(super) struct ProductLogStore {
    mutation: Mutex<()>,
    count: Mutex<Option<LogCount>>,
}

impl ProductLogStore {
    pub(super) fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, ()>> {
        self.mutation
            .lock()
            .map_err(|_| io::Error::other("product log store lock poisoned"))
    }

    pub(super) fn publish_count(
        &self,
        identity: Option<ProductLogFileIdentity>,
        bytes: u64,
        count: usize,
    ) -> io::Result<()> {
        *self
            .count
            .lock()
            .map_err(|_| io::Error::other("product log count lock poisoned"))? =
            identity.map(|identity| (identity, bytes, count.min(i64::MAX as usize) as i64));
        Ok(())
    }

    pub(super) fn cached_count(&self, metadata: &fs::Metadata) -> io::Result<Option<i64>> {
        let value = self
            .count
            .lock()
            .map_err(|_| io::Error::other("product log count lock poisoned"))?;
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
    let mut stores = STORES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| io::Error::other("product log store registry poisoned"))?;
    if let Some(store) = stores.get(&key).and_then(std::sync::Weak::upgrade) {
        return Ok(store);
    }
    stores.retain(|_, value| value.strong_count() > 0);
    let store = Arc::new(ProductLogStore::default());
    stores.insert(key, Arc::downgrade(&store));
    Ok(store)
}

// Serialize full scans separately from writers. One snapshot retains at most
// the bounded store plus one generation of unlinked files, never 200 MiB in RAM.
// 2048 handles cover 200 MiB / 128 KiB byte segments plus 50k / 512 row segments.
static SNAPSHOT_SCAN: Mutex<()> = Mutex::new(());
const MAX_SNAPSHOT_FILES: usize = 2048;

pub(super) struct ProductLogSnapshot {
    pub(super) first_visible_id: u64,
    pub(super) files: Vec<std::io::Take<fs::File>>,
}

pub(super) fn with_product_log_snapshot<T>(
    config_dir: &Path,
    scan: impl FnOnce(ProductLogSnapshot) -> io::Result<T>,
) -> io::Result<T> {
    let _reader = SNAPSHOT_SCAN
        .lock()
        .map_err(|_| io::Error::other("product log snapshot lock poisoned"))?;
    let store = product_log_store(config_dir)?;
    let snapshot = {
        let _guard = store.lock()?;
        let paths = product_log_files(config_dir)?;
        if paths.len() > MAX_SNAPSHOT_FILES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "product log snapshot segment limit exceeded",
            ));
        }
        let first_visible_id =
            cached_log_visible_first_id(&product_log_file(config_dir))?.unwrap_or(0);
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            match fs::File::open(path) {
                Ok(file) => {
                    let bytes = file.metadata()?.len();
                    files.push(file.take(bytes));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        ProductLogSnapshot {
            first_visible_id,
            files,
        }
    };
    #[cfg(test)]
    observe_log_reader_enumeration();
    scan(snapshot)
}
