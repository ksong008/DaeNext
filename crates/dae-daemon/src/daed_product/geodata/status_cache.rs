use super::*;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const GEODATA_VERSION_IDENTITY_MAX_BYTES: u64 = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
enum GeodataFileIdentity {
    Missing,
    Present {
        len: u64,
        modified: Option<SystemTime>,
        #[cfg(unix)]
        device: u64,
        #[cfg(unix)]
        inode: u64,
        #[cfg(unix)]
        changed_seconds: i64,
        #[cfg(unix)]
        changed_nanoseconds: i64,
        content: Option<Box<[u8]>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GeodataResourceIdentity {
    data: GeodataFileIdentity,
    version: GeodataFileIdentity,
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct GeodataStatusCacheEntry {
    identity: GeodataResourceIdentity,
    value: Value,
}

impl GeodataStatusCacheEntry {
    pub(super) fn capture(dir: &Path, kind: GeodataKind, value: Value) -> io::Result<Self> {
        Ok(Self::new(
            GeodataResourceIdentity::capture(dir, kind)?,
            value,
        ))
    }

    pub(super) fn new(identity: GeodataResourceIdentity, value: Value) -> Self {
        Self { identity, value }
    }

    pub(super) fn matches(&self, identity: &GeodataResourceIdentity) -> bool {
        self.identity == *identity
    }

    pub(super) fn value(&self) -> &Value {
        &self.value
    }
}

impl GeodataResourceIdentity {
    pub(super) fn capture(dir: &Path, kind: GeodataKind) -> io::Result<Self> {
        Ok(Self {
            data: GeodataFileIdentity::capture(&dir.join(kind.file_name()), false)?,
            version: GeodataFileIdentity::capture(&dir.join(kind.version_file_name()), true)?,
        })
    }
}

impl GeodataFileIdentity {
    fn capture(path: &Path, include_bounded_content: bool) -> io::Result<Self> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::Missing),
            Err(error) => return Err(error),
        };
        let content =
            if include_bounded_content && metadata.len() <= GEODATA_VERSION_IDENTITY_MAX_BYTES {
                Some(fs::read(path)?.into_boxed_slice())
            } else {
                None
            };
        Ok(Self::Present {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
            content,
        })
    }
}
