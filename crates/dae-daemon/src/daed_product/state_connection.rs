use super::*;

pub(super) fn open_state_connection(path: &Path) -> io::Result<Connection> {
    if let Some(parent) = path.parent()
        && parent.exists()
    {
        set_private_state_dir_permissions(parent)?;
    }
    let conn = open_state_connection_read_write_unchecked(path)?;
    set_private_db_permissions(path)?;
    Ok(conn)
}

pub(super) fn open_state_connection_read_only(path: &Path) -> io::Result<Connection> {
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("state database does not exist: {}", path_string(path)),
        ));
    }
    let wal = state_sidecar_path(path, "-wal");
    let shm = state_sidecar_path(path, "-shm");
    let conn = if wal.exists() || shm.exists() {
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    } else {
        let uri = immutable_state_uri(path)?;
        Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
    }
    .map_err(sqlite_io_error)?;
    conn.busy_timeout(STATE_DB_BUSY_TIMEOUT)
        .map_err(sqlite_io_error)?;
    Ok(conn)
}

fn state_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

fn immutable_state_uri(path: &Path) -> io::Result<String> {
    let path = fs::canonicalize(path)?;
    let escaped = path
        .to_string_lossy()
        .replace('%', "%25")
        .replace('?', "%3F")
        .replace('#', "%23");
    Ok(format!("file:{escaped}?mode=ro&immutable=1"))
}

pub(super) fn open_state_connection_read_write_unchecked(path: &Path) -> io::Result<Connection> {
    let conn = Connection::open(path).map_err(sqlite_io_error)?;
    conn.busy_timeout(STATE_DB_BUSY_TIMEOUT)
        .map_err(sqlite_io_error)?;
    conn.execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sqlite_io_error)?;
    Ok(conn)
}

pub(super) fn set_private_state_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
