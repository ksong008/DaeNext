use super::*;
use std::os::fd::AsRawFd;

const GEOSITE_FILE: &str = "geosite.dat";
const GEOIP_FILE: &str = "geoip.dat";
const GEOSITE_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest";
const GEOIP_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Loyalsoldier/geoip/releases/latest";
const GEODATA_HTTP_HEADER_LIMIT: usize = 64 * 1024;
const GEODATA_HTTP_BODY_LIMIT: usize = 64 * 1024 * 1024;
const GEODATA_REDIRECT_LIMIT: usize = 5;

struct GeodataRelease {
    version: String,
    download_url: url::Url,
}

struct GeodataFileDownload {
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum GeodataKind {
    Geosite,
    Geoip,
}

impl GeodataKind {
    fn file_name(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_FILE,
            Self::Geoip => GEOIP_FILE,
        }
    }

    fn release_api_url(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_RELEASE_API_URL,
            Self::Geoip => GEOIP_RELEASE_API_URL,
        }
    }

    fn version_file_name(self) -> String {
        format!("{}.version", self.file_name())
    }

    fn response_key(self) -> &'static str {
        match self {
            Self::Geosite => "geosite",
            Self::Geoip => "geoip",
        }
    }

    fn summarize(
        self,
        data: &[u8],
    ) -> Result<dae_geodata::GeoDataSummary, dae_geodata::GeoDataError> {
        match self {
            Self::Geosite => dae_geodata::summarize_geosite_bytes(data),
            Self::Geoip => dae_geodata::summarize_geoip_bytes(data),
        }
    }
}

pub(in crate::daed_product) fn api_geodata_status(app: &AppState) -> HttpResponse {
    match geodata_status(app) {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_update_geodata(
    app: &AppState,
    kind: GeodataKind,
) -> HttpResponse {
    match update_geodata(app, kind) {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => HttpResponse::json(
            500,
            json!({
                "error": err.to_string(),
                "kind": kind.response_key(),
            }),
        ),
    }
}

pub(in crate::daed_product) fn geodata_status(app: &AppState) -> io::Result<Value> {
    let dir = geodata_dir(app);
    Ok(json!({
        "geosite": geodata_resource_status_cached(app, &dir, GeodataKind::Geosite),
        "geoip": geodata_resource_status_cached(app, &dir, GeodataKind::Geoip),
    }))
}

#[cfg(test)]
fn geodata_status_for_dir(dir: &Path) -> io::Result<Value> {
    Ok(json!({
        "geosite": geodata_resource_status(dir, GeodataKind::Geosite),
        "geoip": geodata_resource_status(dir, GeodataKind::Geoip),
    }))
}

fn update_geodata(app: &AppState, kind: GeodataKind) -> io::Result<Value> {
    let dir = geodata_dir(app);
    fs::create_dir_all(&dir)?;
    let release = fetch_geodata_latest_release(kind)?;
    let path = dir.join(kind.file_name());
    let tmp_path = dir.join(format!(
        ".{}.tmp.{}.{}",
        kind.file_name(),
        std::process::id(),
        unix_now()
    ));
    let download = match fetch_geodata_url_to_file(&release.download_url, &tmp_path) {
        Ok(download) => download,
        Err(err) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
    };
    let summary = match summarize_geodata_file(kind, &tmp_path) {
        Ok(summary) => summary,
        Err(err) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
    };
    if summary.category_count == 0 || summary.item_count == 0 {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded geodata is empty",
        ));
    }
    if download.bytes == 0 {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded geodata is empty",
        ));
    }
    fs::rename(&tmp_path, &path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        err
    })?;
    write_geodata_release_version(&dir, kind, &release.version)?;
    let _ = advise_file_dontneed(&path);
    let status = geodata_resource_status_from_parts(&dir, kind, summary, download.sha256)?;
    update_geodata_resource_status_cache(app, kind, status.clone());
    let runtime_reload_required = mark_geodata_reload_pending_if_running(app)?;
    let mut response_object = serde_json::Map::new();
    response_object.insert(kind.response_key().to_owned(), status);
    response_object.insert("updated".to_owned(), json!(kind.response_key()));
    if runtime_reload_required {
        response_object.insert("runtimeReloadRequired".to_owned(), json!(true));
    }
    Ok(Value::Object(response_object))
}

fn geodata_dir(app: &AppState) -> PathBuf {
    app.web_root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| app.web_root.clone())
}

fn geodata_resource_status(dir: &Path, kind: GeodataKind) -> Value {
    match geodata_resource_status_result(dir, kind) {
        Ok(value) => value,
        Err(err) => geodata_resource_unavailable_status(kind, err),
    }
}

fn geodata_resource_status_cached(app: &AppState, dir: &Path, kind: GeodataKind) -> Value {
    let Ok(mut cache) = app.geodata_status_cache.lock() else {
        return geodata_resource_status(dir, kind);
    };
    let slot = match kind {
        GeodataKind::Geosite => &mut cache.geosite,
        GeodataKind::Geoip => &mut cache.geoip,
    };
    if let Some(value) = slot.as_ref() {
        return value.clone();
    }

    let value = geodata_resource_status(dir, kind);
    *slot = Some(value.clone());
    value
}

fn geodata_resource_unavailable_status(kind: GeodataKind, err: io::Error) -> Value {
    let mut value = json!({
    "available": false,
    "version": "",
    "categoryCount": 0,
    "fileSize": 0,
    "sha256": null,
    "updatedAt": null,
    "lastError": err.to_string(),
    });
    if let Some(object) = value.as_object_mut() {
        match kind {
            GeodataKind::Geosite => {
                object.insert("ruleCount".to_owned(), json!(0));
            }
            GeodataKind::Geoip => {
                object.insert("cidrCount".to_owned(), json!(0));
            }
        }
    }
    value
}

fn geodata_resource_status_result(dir: &Path, kind: GeodataKind) -> io::Result<Value> {
    let path = dir.join(kind.file_name());
    let summary = summarize_geodata_file(kind, &path)?;
    let sha256 = sha256_file(&path)?;
    let _ = advise_file_dontneed(&path);
    geodata_resource_status_from_parts(dir, kind, summary, sha256)
}

fn geodata_resource_status_from_parts(
    dir: &Path,
    kind: GeodataKind,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
) -> io::Result<Value> {
    let path = dir.join(kind.file_name());
    let metadata = fs::metadata(&path)?;

    Ok(geodata_resource_status_value(
        dir, kind, &metadata, summary, sha256,
    ))
}

fn geodata_resource_status_value(
    dir: &Path,
    kind: GeodataKind,
    metadata: &fs::Metadata,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
) -> Value {
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let updated_at = system_time_iso8601(modified);
    let version =
        read_geodata_release_version(dir, kind).unwrap_or_else(|| system_time_date(modified));

    let mut value = json!({
        "available": true,
        "version": version,
        "categoryCount": summary.category_count,
        "fileSize": metadata.len(),
        "sha256": sha256,
        "updatedAt": updated_at,
        "lastError": null,
    });
    if let Some(object) = value.as_object_mut() {
        match kind {
            GeodataKind::Geosite => {
                object.insert("ruleCount".to_owned(), json!(summary.item_count));
            }
            GeodataKind::Geoip => {
                object.insert("cidrCount".to_owned(), json!(summary.item_count));
            }
        }
    }
    value
}

fn read_geodata_release_version(dir: &Path, kind: GeodataKind) -> Option<String> {
    let value = fs::read_to_string(dir.join(kind.version_file_name())).ok()?;
    let value = value.trim();
    if is_valid_geodata_release_version(value) {
        Some(value.to_owned())
    } else {
        None
    }
}

fn write_geodata_release_version(dir: &Path, kind: GeodataKind, version: &str) -> io::Result<()> {
    if !is_valid_geodata_release_version(version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata release version: {version}"),
        ));
    }
    let path = dir.join(kind.version_file_name());
    let tmp_path = dir.join(format!(
        ".{}.version.tmp.{}.{}",
        kind.file_name(),
        std::process::id(),
        unix_now()
    ));
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(version.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        err
    })
}

fn is_valid_geodata_release_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn set_geodata_resource_status_cache(app: &AppState, kind: GeodataKind, value: Value) {
    let Ok(mut cache) = app.geodata_status_cache.lock() else {
        return;
    };
    match kind {
        GeodataKind::Geosite => cache.geosite = Some(value),
        GeodataKind::Geoip => cache.geoip = Some(value),
    }
}

fn update_geodata_resource_status_cache(app: &AppState, kind: GeodataKind, value: Value) {
    set_geodata_resource_status_cache(app, kind, value);
}

fn mark_geodata_reload_pending_if_running(app: &AppState) -> io::Result<bool> {
    let running = app
        .runtime
        .inner
        .lock()
        .map(|inner| inner.runtime.is_some())
        .unwrap_or(false);
    if running {
        mark_geodata_reload_pending(&app.state)?;
    }
    Ok(running)
}

fn fetch_geodata_url(url: &url::Url) -> io::Result<Vec<u8>> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_once(&current)? {
            GeodataHttpResult::Body(body) => return Ok(body),
            GeodataHttpResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

fn fetch_geodata_url_to_file(
    url: &url::Url,
    output_path: &Path,
) -> io::Result<GeodataFileDownload> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_to_file_once(&current, output_path)? {
            GeodataHttpFileResult::Body(download) => return Ok(download),
            GeodataHttpFileResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

fn fetch_geodata_latest_release(kind: GeodataKind) -> io::Result<GeodataRelease> {
    let api_url = url::Url::parse(kind.release_api_url()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid geodata release api url {}: {err}",
                kind.release_api_url()
            ),
        )
    })?;
    let body = fetch_geodata_url(&api_url)?;
    let release: Value = serde_json::from_slice(&body).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse geodata release metadata: {err}"),
        )
    })?;
    let version = release
        .get("tag_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| is_valid_geodata_release_version(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing geodata release tag"))?
        .to_owned();
    let asset_name = kind.file_name();
    let download_url = release
        .get("assets")
        .and_then(Value::as_array)
        .and_then(|assets| {
            assets.iter().find_map(|asset| {
                let name = asset.get("name").and_then(Value::as_str)?;
                if name == asset_name {
                    asset.get("browser_download_url").and_then(Value::as_str)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing geodata release asset: {asset_name}"),
            )
        })?;
    let download_url = url::Url::parse(download_url).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata release asset url: {err}"),
        )
    })?;
    Ok(GeodataRelease {
        version,
        download_url,
    })
}

enum GeodataHttpResult {
    Body(Vec<u8>),
    Redirect(url::Url),
}

enum GeodataHttpFileResult {
    Body(GeodataFileDownload),
    Redirect(url::Url),
}

fn fetch_geodata_url_once(url: &url::Url) -> io::Result<GeodataHttpResult> {
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        scheme => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported geodata url scheme: {scheme}"),
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url port"))?;
    let request = geodata_http_request(url)?;
    let stream = connect_tcp_endpoint(host, port, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(90)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let response = if tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from(host.to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid geodata tls server name: {err}"),
            )
        })?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(|err| io::Error::other(format!("geodata tls connect: {err}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        read_geodata_http_response(&mut tls_stream)?
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        read_geodata_http_response(&mut stream)?
    };

    geodata_http_body(url, response)
}

fn fetch_geodata_url_to_file_once(
    url: &url::Url,
    output_path: &Path,
) -> io::Result<GeodataHttpFileResult> {
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        scheme => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported geodata url scheme: {scheme}"),
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url port"))?;
    let request = geodata_http_request(url)?;
    let stream = connect_tcp_endpoint(host, port, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(90)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    if tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from(host.to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid geodata tls server name: {err}"),
            )
        })?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(|err| io::Error::other(format!("geodata tls connect: {err}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        read_geodata_http_response_to_file(url, &mut tls_stream, output_path)
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        read_geodata_http_response_to_file(url, &mut stream, output_path)
    }
}

fn geodata_http_request(url: &url::Url) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url host"))?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok(format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: dae/{}\r\nAccept: application/octet-stream, */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    ))
}

fn read_geodata_http_response<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let response_limit = GEODATA_HTTP_HEADER_LIMIT
        .checked_add(GEODATA_HTTP_BODY_LIMIT)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "geodata response limit overflow",
            )
        })?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof && !response.is_empty() => {
                break;
            }
            Err(err) => return Err(err),
        };
        if read == 0 {
            break;
        }
        let next_len = response.len().checked_add(read).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "geodata response size overflow")
        })?;
        if next_len > response_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata response exceeds {response_limit} bytes"),
            ));
        }
        response.extend_from_slice(&buffer[..read]);
    }
    Ok(response)
}

fn read_geodata_http_response_to_file<R: Read>(
    base_url: &url::Url,
    reader: &mut R,
    output_path: &Path,
) -> io::Result<GeodataHttpFileResult> {
    let (headers, initial_body) = read_geodata_http_headers(reader)?;
    geodata_http_body_to_file(base_url, &headers, initial_body, reader, output_path)
}

fn read_geodata_http_headers<R: Read>(reader: &mut R) -> io::Result<(String, Vec<u8>)> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof && !response.is_empty() => {
                break;
            }
            Err(err) => return Err(err),
        };
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        let split = find_subsequence(&response, b"\r\n\r\n")
            .or_else(|| find_subsequence(&response, b"\n\n"));
        if let Some(split) = split {
            if split > GEODATA_HTTP_HEADER_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("geodata response headers exceed {GEODATA_HTTP_HEADER_LIMIT} bytes"),
                ));
            }
            let header_end = if response.get(split..split + 4) == Some(b"\r\n\r\n") {
                split + 4
            } else {
                split + 2
            };
            let headers = String::from_utf8_lossy(&response[..split]).into_owned();
            let initial_body = response[header_end..].to_vec();
            return Ok((headers, initial_body));
        }
        if response.len() > GEODATA_HTTP_HEADER_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata response headers exceed {GEODATA_HTTP_HEADER_LIMIT} bytes"),
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing geodata http headers",
    ))
}

fn geodata_http_body(base_url: &url::Url, mut response: Vec<u8>) -> io::Result<GeodataHttpResult> {
    let split = find_subsequence(&response, b"\r\n\r\n")
        .or_else(|| find_subsequence(&response, b"\n\n"))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing geodata http headers")
        })?;
    if split > GEODATA_HTTP_HEADER_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata response headers exceed {GEODATA_HTTP_HEADER_LIMIT} bytes"),
        ));
    }
    let header_end = if response.get(split..split + 4) == Some(b"\r\n\r\n") {
        split + 4
    } else {
        split + 2
    };
    let headers = String::from_utf8_lossy(&response[..split]).into_owned();
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if (300..400).contains(&status) {
        let location = header_value(&headers, "location").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata fetch returned HTTP {status} without Location"),
            )
        })?;
        let next = base_url.join(location.trim()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid geodata redirect location: {err}"),
            )
        })?;
        return Ok(GeodataHttpResult::Redirect(next));
    }
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "geodata fetch returned HTTP {status}"
        )));
    }

    let body_len = response.len().saturating_sub(header_end);
    if body_len > GEODATA_HTTP_BODY_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata response body exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
        ));
    }
    response.drain(..header_end);
    let mut body = response;
    if header_values(&headers, "transfer-encoding")
        .iter()
        .any(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
    {
        body = decode_geodata_chunked_body(&body)?;
    }
    Ok(GeodataHttpResult::Body(body))
}

fn geodata_http_body_to_file<R: Read>(
    base_url: &url::Url,
    headers: &str,
    initial_body: Vec<u8>,
    reader: &mut R,
    output_path: &Path,
) -> io::Result<GeodataHttpFileResult> {
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if (300..400).contains(&status) {
        let location = header_value(headers, "location").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata fetch returned HTTP {status} without Location"),
            )
        })?;
        let next = base_url.join(location.trim()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid geodata redirect location: {err}"),
            )
        })?;
        return Ok(GeodataHttpFileResult::Redirect(next));
    }
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "geodata fetch returned HTTP {status}"
        )));
    }

    let mut file = fs::File::create(output_path)?;
    let mut hasher = Sha256::new();
    let bytes = if header_values(headers, "transfer-encoding")
        .iter()
        .any(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        }) {
        copy_chunked_body_to_file(reader, initial_body, &mut file, &mut hasher)?
    } else if let Some(content_length) = geodata_content_length(headers)? {
        copy_fixed_body_to_file(reader, initial_body, content_length, &mut file, &mut hasher)?
    } else {
        copy_body_to_file_until_eof(reader, initial_body, &mut file, &mut hasher)?
    };
    file.sync_all()?;
    Ok(GeodataHttpFileResult::Body(GeodataFileDownload {
        bytes,
        sha256: hex_encode(&hasher.finalize()),
    }))
}

fn geodata_content_length(headers: &str) -> io::Result<Option<u64>> {
    let Some(value) = header_value(headers, "content-length") else {
        return Ok(None);
    };
    let value = value.trim().parse::<u64>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata content-length: {err}"),
        )
    })?;
    if value > GEODATA_HTTP_BODY_LIMIT as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata response body exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
        ));
    }
    Ok(Some(value))
}

fn copy_body_to_file_until_eof<R: Read>(
    reader: &mut R,
    initial_body: Vec<u8>,
    file: &mut fs::File,
    hasher: &mut Sha256,
) -> io::Result<u64> {
    let mut written = 0_u64;
    write_geodata_body_part(file, hasher, &initial_body, &mut written)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        };
        if read == 0 {
            break;
        }
        write_geodata_body_part(file, hasher, &buffer[..read], &mut written)?;
    }
    Ok(written)
}

fn copy_fixed_body_to_file<R: Read>(
    reader: &mut R,
    initial_body: Vec<u8>,
    content_length: u64,
    file: &mut fs::File,
    hasher: &mut Sha256,
) -> io::Result<u64> {
    if initial_body.len() as u64 > content_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "geodata response body exceeded content-length",
        ));
    }
    let mut written = 0_u64;
    write_geodata_body_part(file, hasher, &initial_body, &mut written)?;
    let mut buffer = [0_u8; 64 * 1024];
    while written < content_length {
        let remaining = content_length - written;
        let read_limit = buffer.len().min(remaining as usize);
        let read = reader.read(&mut buffer[..read_limit])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated geodata response body",
            ));
        }
        write_geodata_body_part(file, hasher, &buffer[..read], &mut written)?;
    }
    Ok(written)
}

fn copy_chunked_body_to_file<R: Read>(
    reader: &mut R,
    initial_body: Vec<u8>,
    file: &mut fs::File,
    hasher: &mut Sha256,
) -> io::Result<u64> {
    let chain = io::Cursor::new(initial_body).chain(reader);
    let mut reader = io::BufReader::new(chain);
    let mut written = 0_u64;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated geodata chunked body",
            ));
        }
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid geodata chunk size: {err}"),
            )
        })?;
        if size == 0 {
            break;
        }
        let mut remaining = size;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let read_limit = buffer.len().min(remaining);
            reader.read_exact(&mut buffer[..read_limit])?;
            write_geodata_body_part(file, hasher, &buffer[..read_limit], &mut written)?;
            remaining -= read_limit;
        }
        let mut crlf = [0_u8; 2];
        reader.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "geodata chunk missing trailing CRLF",
            ));
        }
    }
    Ok(written)
}

fn write_geodata_body_part(
    file: &mut fs::File,
    hasher: &mut Sha256,
    data: &[u8],
    written: &mut u64,
) -> io::Result<()> {
    let next = written
        .checked_add(data.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "geodata body size overflow"))?;
    if next > GEODATA_HTTP_BODY_LIMIT as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata response body exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
        ));
    }
    file.write_all(data)?;
    sha2::Digest::update(hasher, data);
    *written = next;
    Ok(())
}

fn decode_geodata_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut index = 0;
    let mut out = Vec::new();
    while index < body.len() {
        let Some(line_end) = find_subsequence(&body[index..], b"\r\n") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid geodata chunked body",
            ));
        };
        let size_text = String::from_utf8_lossy(&body[index..index + line_end]);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid geodata chunk size: {err}"),
            )
        })?;
        let next_len = out.len().checked_add(size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "geodata chunked body size overflow",
            )
        })?;
        if next_len > GEODATA_HTTP_BODY_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded geodata body exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
            ));
        }
        index += line_end + 2;
        if size == 0 {
            break;
        }
        if index + size > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated geodata chunked body",
            ));
        }
        out.extend_from_slice(&body[index..index + size]);
        let data_end = index + size;
        if body.get(data_end..data_end + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "geodata chunk missing trailing CRLF",
            ));
        }
        index = data_end + 2;
    }
    Ok(out)
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    header_values(headers, name).into_iter().next()
}

fn header_values<'a>(headers: &'a str, name: &str) -> Vec<&'a str> {
    let mut values = Vec::new();
    for line in headers.lines().skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(name) {
            values.push(value.trim());
        }
    }
    values
}

fn summarize_geodata_file(
    kind: GeodataKind,
    path: &Path,
) -> io::Result<dae_geodata::GeoDataSummary> {
    validate_geodata_file_size(path)?;
    match MappedGeodataFile::open(path) {
        Ok(mapped) => kind.summarize(mapped.as_slice()).map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidData, format!("parse geodata: {err}"))
        }),
        Err(_) => {
            let data = fs::read(path)?;
            kind.summarize(&data).map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, format!("parse geodata: {err}"))
            })
        }
    }
}

fn sha256_file(path: &Path) -> io::Result<String> {
    validate_geodata_file_size(path)?;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buffer[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn validate_geodata_file_size(path: &Path) -> io::Result<()> {
    let len = fs::metadata(path)?.len();
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata asset {} is empty", path.display()),
        ));
    }
    if len > GEODATA_HTTP_BODY_LIMIT as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata asset exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
        ));
    }
    Ok(())
}

fn advise_file_dontneed(path: &Path) -> io::Result<()> {
    let file = fs::File::open(path)?;
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
    }
    Ok(())
}

struct MappedGeodataFile {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
}

impl MappedGeodataFile {
    fn open(path: &Path) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        let len_u64 = file.metadata()?.len();
        let len = usize::try_from(len_u64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset {} is too large to map", path.display()),
            )
        })?;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset {} is empty", path.display()),
            ));
        }
        if len_u64 > GEODATA_HTTP_BODY_LIMIT as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
            ));
        }
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = std::ptr::NonNull::new(mapped.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned a null pointer"))?;
        Ok(Self { ptr, len })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for MappedGeodataFile {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

fn system_time_iso8601(time: SystemTime) -> String {
    let timestamp = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    iso8601_utc(timestamp)
}

fn system_time_date(time: SystemTime) -> String {
    let timestamp = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (timestamp as i64).div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geodata_status_reports_counts_from_actual_files() {
        let dir = std::env::temp_dir().join(format!("daed-product-geodata-{}", fastrand::u64(..)));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(GEOSITE_FILE),
            message([
                field_message(
                    1,
                    message([
                        field_string(1, "geosite:alpha"),
                        field_message(2, message([field_string(2, "example.com")])),
                    ]),
                ),
                field_message(
                    1,
                    message([
                        field_string(1, "geosite:beta"),
                        field_message(2, message([field_string(2, "example.org")])),
                        field_message(2, message([field_string(2, "example.net")])),
                    ]),
                ),
            ]),
        )
        .unwrap();
        fs::write(
            dir.join(GeodataKind::Geosite.version_file_name()),
            "202606222314\n",
        )
        .unwrap();
        fs::write(
            dir.join(GEOIP_FILE),
            message([
                field_message(
                    1,
                    message([
                        field_string(1, "geoip:alpha"),
                        field_message(
                            2,
                            message([field_bytes(1, &[10, 0, 0, 0]), field_varint(2, 8)]),
                        ),
                    ]),
                ),
                field_message(
                    1,
                    message([
                        field_string(1, "geoip:beta"),
                        field_message(
                            2,
                            message([field_bytes(1, &[192, 168, 0, 0]), field_varint(2, 16)]),
                        ),
                        field_message(
                            2,
                            message([field_bytes(1, &[172, 16, 0, 0]), field_varint(2, 12)]),
                        ),
                    ]),
                ),
            ]),
        )
        .unwrap();
        fs::write(
            dir.join(GeodataKind::Geoip.version_file_name()),
            "202606182327\n",
        )
        .unwrap();

        let status = geodata_status_for_dir(&dir).unwrap();
        assert_eq!(status["geosite"]["version"], json!("202606222314"));
        assert_eq!(status["geosite"]["categoryCount"], json!(2));
        assert_eq!(status["geosite"]["ruleCount"], json!(3));
        assert_eq!(status["geoip"]["version"], json!("202606182327"));
        assert_eq!(status["geoip"]["categoryCount"], json!(2));
        assert_eq!(status["geoip"]["cidrCount"], json!(3));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn geodata_status_reuses_cached_values_after_first_read() {
        let dir =
            std::env::temp_dir().join(format!("daed-product-geodata-cache-{}", fastrand::u64(..)));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(GEOSITE_FILE),
            message([field_message(
                1,
                message([
                    field_string(1, "geosite:cached"),
                    field_message(2, message([field_string(2, "cached.example")])),
                ]),
            )]),
        )
        .unwrap();
        fs::write(
            dir.join(GEOIP_FILE),
            message([field_message(
                1,
                message([
                    field_string(1, "geoip:cached"),
                    field_message(
                        2,
                        message([field_bytes(1, &[10, 0, 0, 0]), field_varint(2, 8)]),
                    ),
                ]),
            )]),
        )
        .unwrap();
        let app = AppState {
            config_dir: dir.clone(),
            state: dir.join("daed.db"),
            web_root: dir.join("web"),
            api_only: true,
            runtime: Arc::new(ProductRuntimeManager::new()),
            latency_jobs: Arc::new(LatencyJobManager::default()),
            http_metrics: Arc::new(ProductHttpMetrics::default()),
            geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        };

        let first = geodata_status(&app).unwrap();
        assert_eq!(first["geosite"]["ruleCount"], json!(1));
        assert_eq!(first["geoip"]["cidrCount"], json!(1));

        fs::remove_file(dir.join(GEOSITE_FILE)).unwrap();
        fs::remove_file(dir.join(GEOIP_FILE)).unwrap();

        let cached = geodata_status(&app).unwrap();
        assert_eq!(cached["geosite"]["available"], json!(true));
        assert_eq!(cached["geosite"]["ruleCount"], json!(1));
        assert_eq!(cached["geoip"]["available"], json!(true));
        assert_eq!(cached["geoip"]["cidrCount"], json!(1));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn geodata_status_keeps_missing_resources_unavailable() {
        let dir = std::env::temp_dir().join(format!(
            "daed-product-geodata-missing-{}",
            fastrand::u64(..)
        ));
        fs::create_dir_all(&dir).unwrap();

        let status = geodata_status_for_dir(&dir).unwrap();
        assert_eq!(status["geosite"]["available"], json!(false));
        assert_eq!(status["geosite"]["categoryCount"], json!(0));
        assert_eq!(status["geoip"]["available"], json!(false));
        assert_eq!(status["geoip"]["categoryCount"], json!(0));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn geodata_http_reader_accepts_unexpected_eof_after_response_bytes() {
        let mut reader = UnexpectedEofAfterData {
            data: b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest".as_slice(),
            eof_sent: false,
        };

        let response = read_geodata_http_response(&mut reader).unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest"
        );
    }

    #[test]
    fn geodata_http_reader_streams_response_body_to_file() {
        let dir =
            std::env::temp_dir().join(format!("daed-product-geodata-stream-{}", fastrand::u64(..)));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("geosite.dat");
        let mut reader = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest".as_slice();
        let base_url = url::Url::parse("https://example.com/geosite.dat").unwrap();

        let result = read_geodata_http_response_to_file(&base_url, &mut reader, &path).unwrap();
        let GeodataHttpFileResult::Body(download) = result else {
            panic!("expected streamed body");
        };
        assert_eq!(download.bytes, 4);
        assert_eq!(download.sha256, hex_encode(&Sha256::digest(b"test")));
        assert_eq!(fs::read(&path).unwrap(), b"test");

        let _ = fs::remove_dir_all(&dir);
    }

    struct UnexpectedEofAfterData<'a> {
        data: &'a [u8],
        eof_sent: bool,
    }

    impl Read for UnexpectedEofAfterData<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.data.is_empty() {
                if self.eof_sent {
                    return Ok(0);
                }
                self.eof_sent = true;
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing close_notify",
                ));
            }
            let len = self.data.len().min(buf.len());
            buf[..len].copy_from_slice(&self.data[..len]);
            self.data = &self.data[len..];
            Ok(len)
        }
    }

    fn message(fields: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        fields.into_iter().flatten().collect()
    }

    fn field_string(field: u64, value: &str) -> Vec<u8> {
        field_bytes(field, value.as_bytes())
    }

    fn field_message(field: u64, value: Vec<u8>) -> Vec<u8> {
        field_bytes(field, &value)
    }

    fn field_bytes(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = encode_varint((field << 3) | 2);
        out.extend(encode_varint(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    fn field_varint(field: u64, value: u64) -> Vec<u8> {
        let mut out = encode_varint(field << 3);
        out.extend(encode_varint(value));
        out
    }

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }
}
