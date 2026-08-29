use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};

use url::Url;

use crate::SUBSCRIPTION_MAX_BYTES;

const SUBSCRIPTION_PERSIST_DIR: &str = "persist.d";

pub struct FetchedSubscriptionContent {
    pub content: String,
    pub persist_path: Option<PathBuf>,
}

impl FetchedSubscriptionContent {
    pub fn without_persist(content: String) -> Self {
        Self {
            content,
            persist_path: None,
        }
    }
}

pub fn subscription_url_with_scheme(url: &Url, scheme: &str) -> io::Result<Url> {
    let prefix = format!("{}:", url.scheme());
    let rest = url.as_str().strip_prefix(&prefix).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid subscription scheme prefix",
        )
    })?;
    Url::parse(&format!("{scheme}:{rest}"))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

pub fn subscription_file_path(config_dir: &Path, url: &Url) -> io::Result<PathBuf> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not support absolute path"))?;
    let mut path = confined_config_path(config_dir, host)?;
    push_confined_relative(&mut path, url.path().trim_start_matches('/'))?;
    Ok(path)
}

pub fn persist_subscription_path(config_dir: &Path, tag: Option<&str>) -> io::Result<PathBuf> {
    let tag = tag
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription tag is required for http-file/https-file subscription",
            )
        })?;
    if tag == "." || tag == ".." || tag.contains('/') || tag.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("subscription tag {tag:?} cannot be used as a persist filename"),
        ));
    }
    let mut path = confined_config_path(config_dir, SUBSCRIPTION_PERSIST_DIR)?;
    push_confined_relative(&mut path, &format!("{tag}.sub"))?;
    Ok(path)
}

pub fn read_subscription_file(path: &Path) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "subscription file cannot be a directory: {}",
                path.display()
            ),
        ));
    }
    reject_open_subscription_file_permissions(path, &metadata)?;
    let mut reader = io::BufReader::new(file);
    let buffer = reader.fill_buf()?;
    if buffer.first() == Some(&b'@') {
        let mut instruction = String::new();
        reader.read_line(&mut instruction)?;
    }
    let bytes = read_all_limited(&mut reader, SUBSCRIPTION_MAX_BYTES)?;
    Ok(String::from_utf8_lossy(bytes.trim_ascii()).into_owned())
}

pub fn write_persisted_subscription(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "persisted subscription path has no parent",
        ));
    };
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn confined_config_path(config_dir: &Path, first: &str) -> io::Result<PathBuf> {
    let mut path = config_dir.to_path_buf();
    push_confined_relative(&mut path, first)?;
    Ok(path)
}

fn push_confined_relative(path: &mut PathBuf, relative: &str) -> io::Result<()> {
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "subscription path escapes config directory",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn reject_open_subscription_file_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o037 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "permissions {mode:04o} for '{}' are too open; requires the file is not group-writable and not accessible by others; suggest 0640 or 0600",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_open_subscription_file_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> io::Result<()> {
    Ok(())
}

fn read_all_limited<R: Read>(reader: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let next_len = out.len().checked_add(read).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "subscription size overflow")
        })?;
        if next_len > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription exceeds {limit} bytes"),
            ));
        }
        out.extend_from_slice(&buffer[..read]);
    }
    Ok(out)
}
