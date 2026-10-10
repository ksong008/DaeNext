use super::*;
use std::collections::VecDeque;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FileVersion {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64, u32),
}

fn version(path: &Path) -> io::Result<Option<FileVersion>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(FileVersion {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
                metadata.mode(),
            )
        },
    }))
}

pub(super) type DatabaseVersion = [Option<FileVersion>; 2];

pub(super) fn database_version(path: &Path) -> io::Result<DatabaseVersion> {
    Ok([
        version(path)?,
        version(&connection::state_sidecar_path(path, "-wal"))?,
    ])
}

struct CachedConnection {
    path: PathBuf,
    connection: Connection,
    validated: DatabaseVersion,
    data_version: i64,
}

static POOL: OnceLock<Mutex<VecDeque<CachedConnection>>> = OnceLock::new();

/// The generation is the physical database/WAL identity plus SQLite's own
/// external-commit counter. Changed or replaced files always take the full
/// read-only integrity/version/migration path before the connection is reused.
pub(super) fn with_initialized_connection<T>(
    path: &Path,
    action: impl FnOnce(&mut Connection) -> io::Result<T>,
) -> io::Result<T> {
    let path = std::path::absolute(path)?;
    let pool = POOL.get_or_init(|| Mutex::new(VecDeque::new()));
    let cached = {
        let mut pool = pool
            .lock()
            .map_err(|_| io::Error::other("state connection pool poisoned"))?;
        pool.iter()
            .position(|entry| entry.path == path)
            .and_then(|index| pool.remove(index))
    };
    let current = database_version(&path)?;
    let reusable = cached.as_ref().is_some_and(|entry| {
        entry.validated == current
            && sqlite_data_version(&entry.connection).ok() == Some(entry.data_version)
    });
    let inspected = if !reusable && path.exists() {
        match open_state_connection_read_only(&path)
            .and_then(|conn| inspect_state_connection_read_only(&conn, false))
        {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                // Keep an existing WAL handle alive on rejection; closing it can
                // checkpoint/delete sidecars before a newer schema is rejected.
                if let Some(entry) = cached {
                    pool.lock()
                        .map_err(|_| io::Error::other("state connection pool poisoned"))?
                        .push_back(entry);
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    let mut connection = match cached {
        Some(entry) if reusable => entry.connection,
        Some(entry)
            if same_database_file(&entry.validated, &current)
                && inspected
                    .as_ref()
                    .is_some_and(|snapshot| !snapshot.migration_required) =>
        {
            entry
                .connection
                .execute_batch("PRAGMA shrink_memory;")
                .map_err(sqlite_io_error)?;
            entry.connection
        }
        entry => {
            drop(entry);
            open_initialized_state_connection(&path)?
        }
    };
    if let Some(parent) = path.parent().filter(|parent| parent.exists()) {
        set_private_state_dir_permissions(parent)?;
    }
    if path.exists() {
        set_private_db_permissions(&path)?;
    }
    let validated = database_version(&path)?;
    let data_version = sqlite_data_version(&connection)?;
    let result = action(&mut connection);
    // Writes keep the connection but invalidate its prior fingerprint; the next
    // checkout verifies the changed generation with an independent readonly handle.
    if result.is_ok() && connection.is_autocommit() {
        let retired = {
            let mut pool = pool
                .lock()
                .map_err(|_| io::Error::other("state connection pool poisoned"))?;
            let retired = if pool.len() >= 16 {
                pool.pop_front()
            } else {
                None
            };
            if pool.iter().filter(|entry| entry.path == path).count() < 2 {
                pool.push_back(CachedConnection {
                    path,
                    connection,
                    validated,
                    data_version,
                });
            }
            retired
        };
        drop(retired);
    }

    result
}

fn same_database_file(previous: &DatabaseVersion, current: &DatabaseVersion) -> bool {
    match (&previous[0], &current[0]) {
        #[cfg(unix)]
        (Some(a), Some(b)) => a.identity.0 == b.identity.0 && a.identity.1 == b.identity.1,
        _ => false,
    }
}

fn sqlite_data_version(connection: &Connection) -> io::Result<i64> {
    connection
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .map_err(sqlite_io_error)
}

#[cfg(test)]
mod tests;
