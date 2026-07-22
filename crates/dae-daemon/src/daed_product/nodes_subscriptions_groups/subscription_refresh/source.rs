use super::http::fetch_http_url_with_proxy_config;
use super::*;

const SUBSCRIPTION_PERSIST_DIR: &str = "persist.d";

pub(super) struct FetchedSubscriptionContent {
    pub(super) content: String,
    pub(super) persist_path: Option<PathBuf>,
}

#[cfg(test)]
pub(crate) fn fetch_subscription_content(
    config_dir: &Path,
    tag: Option<&str>,
    link: &str,
) -> io::Result<String> {
    let control_runtime = product_test_control_runtime();
    fetch_subscription_content_with_proxy_config(&control_runtime, config_dir, tag, link, None)
        .map(|fetched| fetched.content)
}

pub(super) fn fetch_subscription_content_with_proxy_config(
    control_runtime: &ProductControlRuntime,
    config_dir: &Path,
    tag: Option<&str>,
    link: &str,
    proxy_config: Option<&Config>,
) -> io::Result<FetchedSubscriptionContent> {
    let url = url::Url::parse(link)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    match url.scheme() {
        "http" => fetch_http_url_with_proxy_config(control_runtime, &url, false, proxy_config)
            .map(FetchedSubscriptionContent::without_persist),
        "https" => fetch_http_url_with_proxy_config(control_runtime, &url, true, proxy_config)
            .map(FetchedSubscriptionContent::without_persist),
        "file" => read_subscription_file(&subscription_file_path(config_dir, &url)?)
            .map(FetchedSubscriptionContent::without_persist),
        "http-file" | "https-file" => {
            let persist_path = persist_subscription_path(config_dir, tag)?;
            let fetch_url = url_with_scheme(&url, url.scheme().trim_end_matches("-file"))?;
            let fetched = match fetch_url.scheme() {
                "http" => fetch_http_url_with_proxy_config(
                    control_runtime,
                    &fetch_url,
                    false,
                    proxy_config,
                ),
                "https" => fetch_http_url_with_proxy_config(
                    control_runtime,
                    &fetch_url,
                    true,
                    proxy_config,
                ),
                scheme => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported subscription scheme: {scheme}"),
                )),
            };
            match fetched {
                Ok(content) => Ok(FetchedSubscriptionContent {
                    content,
                    persist_path: Some(persist_path),
                }),
                Err(fetch_err) => read_subscription_file(&persist_path)
                    .map(FetchedSubscriptionContent::without_persist)
                    .map_err(|read_err| {
                        io::Error::new(
                            read_err.kind(),
                            format!(
                                "fetch failed: {}; persisted subscription fallback failed: {}",
                                fetch_err, read_err
                            ),
                        )
                    }),
            }
        }
        scheme => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported subscription scheme: {scheme}"),
        )),
    }
}

impl FetchedSubscriptionContent {
    fn without_persist(content: String) -> Self {
        Self {
            content,
            persist_path: None,
        }
    }
}

fn url_with_scheme(url: &url::Url, scheme: &str) -> io::Result<url::Url> {
    let prefix = format!("{}:", url.scheme());
    let rest = url.as_str().strip_prefix(&prefix).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid subscription scheme prefix",
        )
    })?;
    url::Url::parse(&format!("{scheme}:{rest}"))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

pub(crate) fn subscription_file_path(config_dir: &Path, url: &url::Url) -> io::Result<PathBuf> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not support absolute path"))?;
    let mut path = confined_config_path(config_dir, host)?;
    push_confined_relative(&mut path, url.path().trim_start_matches('/'))?;
    Ok(path)
}

fn persist_subscription_path(config_dir: &Path, tag: Option<&str>) -> io::Result<PathBuf> {
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

fn read_subscription_file(path: &Path) -> io::Result<String> {
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
    let bytes = read_all_limited(&mut reader, subscription_http_body_limit())?;
    Ok(String::from_utf8_lossy(bytes.trim_ascii()).into_owned())
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

pub(super) fn write_persisted_subscription(path: &Path, bytes: &[u8]) -> io::Result<()> {
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

fn read_all_limited<R: Read>(reader: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
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
        out.extend_from_slice(&buf[..read]);
    }
    Ok(out)
}
