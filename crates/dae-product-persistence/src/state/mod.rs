use dae_config::DEFAULT_LOG_LEVEL;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const STATE_DB_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub const STATE_SCHEMA_VERSION: i64 = 2;
const DEFAULT_RUNTIME_LOG_LEVEL: &str = DEFAULT_LOG_LEVEL;
pub const RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY: &str = "runtime_external_input_version";
const LEGACY_GEODATA_RELOAD_PENDING_METADATA_KEY: &str = "geodata_reload_pending";
const LEGACY_IMPORT_STATE_STORE: &str = "/etc/daed/wing.db";

mod connection;
mod input_versions;
mod integrity;
mod metadata;
mod migration;
mod schema;
mod selected_resources;

pub use connection::*;
pub use input_versions::*;
pub use integrity::*;
pub use metadata::*;
pub use migration::*;
pub use schema::*;
pub use selected_resources::*;

fn sqlite_io_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error)
}

fn list_tables(connection: &Connection) -> io::Result<Vec<String>> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(sqlite_io_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_io_error)?;
    rows.map(|row| row.map_err(sqlite_io_error)).collect()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn set_private_db_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
