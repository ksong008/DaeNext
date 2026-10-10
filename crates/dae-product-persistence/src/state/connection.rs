use super::*;

pub fn open_state_connection(path: &Path) -> io::Result<Connection> {
    if let Some(parent) = path.parent()
        && parent.exists()
    {
        set_private_state_dir_permissions(parent)?;
    }
    let conn = open_state_connection_read_write_unchecked(path)?;
    set_private_db_permissions(path)?;
    Ok(conn)
}

/// A private DB/WAL copy prevents read marks, sidecar creation and checkpoints
/// from changing the source during explicit read-only validation.
pub struct ReadOnlyStateConnection {
    connection: Option<Connection>,
    directory: PathBuf,
}
impl std::ops::Deref for ReadOnlyStateConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.connection.as_ref().expect("live state snapshot")
    }
}
impl Drop for ReadOnlyStateConnection {
    fn drop(&mut self) {
        self.connection.take();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub fn open_state_connection_read_only(path: &Path) -> io::Result<ReadOnlyStateConnection> {
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("state database does not exist: {}", path_string(path)),
        ));
    }
    let directory = std::env::temp_dir().join(format!(
        "daed-state-read-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::create_dir(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let mut snapshot = ReadOnlyStateConnection {
        connection: None,
        directory,
    };
    let copy = snapshot.directory.join("state.db");
    for _ in 0..3 {
        let before = pool::database_version(path)?;
        fs::copy(path, &copy)?;
        let source_wal = state_sidecar_path(path, "-wal");
        let copy_wal = state_sidecar_path(&copy, "-wal");
        match fs::copy(source_wal, &copy_wal) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let _ = fs::remove_file(&copy_wal);
            }
            Err(error) => return Err(error),
        }
        if before != pool::database_version(path)? {
            continue;
        }
        let conn = Connection::open_with_flags(&copy, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(sqlite_io_error)?;
        conn.busy_timeout(STATE_DB_BUSY_TIMEOUT)
            .map_err(sqlite_io_error)?;
        snapshot.connection = Some(conn);
        return Ok(snapshot);
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "state changed during three read-only snapshot attempts",
    ))
}

pub(super) fn state_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

pub fn open_state_connection_read_write_unchecked(path: &Path) -> io::Result<Connection> {
    let conn = Connection::open(path).map_err(sqlite_io_error)?;
    conn.busy_timeout(STATE_DB_BUSY_TIMEOUT)
        .map_err(sqlite_io_error)?;
    conn.execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sqlite_io_error)?;
    Ok(conn)
}

pub fn set_private_state_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o7777 != 0o750 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
