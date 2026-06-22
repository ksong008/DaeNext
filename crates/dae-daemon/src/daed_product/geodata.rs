use super::*;

const GEOSITE_FILE: &str = "geosite.dat";
const GEOIP_FILE: &str = "geoip.dat";
const GEOSITE_URL: &str =
    "https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
const GEOIP_URL: &str = "https://fastly.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat";
const GEODATA_HTTP_HEADER_LIMIT: usize = 64 * 1024;
const GEODATA_HTTP_BODY_LIMIT: usize = 64 * 1024 * 1024;
const GEODATA_REDIRECT_LIMIT: usize = 5;

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

    fn url(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_URL,
            Self::Geoip => GEOIP_URL,
        }
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
    let url = url::Url::parse(kind.url()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid geodata url {}: {err}", kind.url()),
        )
    })?;
    let data = fetch_geodata_url(&url)?;
    let summary = kind.summarize(&data).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("parse geodata: {err}"))
    })?;
    if summary.category_count == 0 || summary.item_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded geodata is empty",
        ));
    }

    let path = dir.join(kind.file_name());
    let tmp_path = dir.join(format!(
        ".{}.tmp.{}.{}",
        kind.file_name(),
        std::process::id(),
        unix_now()
    ));
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        err
    })?;
    let status = geodata_resource_status_from_data(&dir, kind, &data, summary)?;
    update_geodata_resource_status_cache(app, kind, status.clone());
    let reload = reload_runtime_after_geodata_update(app).map_err(io::Error::other)?;
    let mut response_object = serde_json::Map::new();
    response_object.insert(kind.response_key().to_owned(), status);
    response_object.insert("updated".to_owned(), json!(kind.response_key()));
    let mut response = Value::Object(response_object);
    if let Some(object) = response.as_object_mut() {
        match reload {
            Some(report) => {
                object.insert("runtimeReloadRequired".to_owned(), json!(true));
                object.insert("runtimeReloaded".to_owned(), json!(true));
                if let Some(report) = report.as_object() {
                    if let Some(source) = report.get("source") {
                        object.insert("runtimeReloadSource".to_owned(), source.clone());
                    }
                    if let Some(elapsed) = report.get("elapsed") {
                        object.insert("runtimeReloadElapsed".to_owned(), elapsed.clone());
                    }
                    if let Some(status) = report.get("status") {
                        object.insert("runtimeReloadStatus".to_owned(), status.clone());
                    }
                    if let Some(message) = report.get("message") {
                        object.insert("runtimeReloadMessage".to_owned(), message.clone());
                    }
                }
            }
            None => {}
        }
    }
    Ok(response)
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
    let data = fs::read(&path)?;
    let metadata = fs::metadata(&path)?;
    let summary = kind
        .summarize(&data)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let sha256 = hex_encode(&Sha256::digest(&data));

    Ok(geodata_resource_status_value(
        kind, &metadata, summary, sha256,
    ))
}

fn geodata_resource_status_from_data(
    dir: &Path,
    kind: GeodataKind,
    data: &[u8],
    summary: dae_geodata::GeoDataSummary,
) -> io::Result<Value> {
    let path = dir.join(kind.file_name());
    let metadata = fs::metadata(&path)?;
    let sha256 = hex_encode(&Sha256::digest(data));

    Ok(geodata_resource_status_value(
        kind, &metadata, summary, sha256,
    ))
}

fn geodata_resource_status_value(
    kind: GeodataKind,
    metadata: &fs::Metadata,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
) -> Value {
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let updated_at = system_time_iso8601(modified);
    let version = system_time_date(modified);

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

fn reload_runtime_after_geodata_update(app: &AppState) -> Result<Option<Value>, String> {
    let (config, config_content) = {
        let inner = app
            .runtime
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        if inner.runtime.is_none() {
            return Ok(None);
        }
        let Some(config) = inner.config.clone() else {
            return Ok(None);
        };
        (config, inner.config_content.clone())
    };
    let started_at = Instant::now();
    let outcome =
        app.runtime
            .reload_with_config_content(config, config_content, "geodata-update")?;
    let mut report = json!({
        "source": "geodata-update",
        "elapsed": format!("{:?}", started_at.elapsed()),
    });
    if let Some(object) = report.as_object_mut() {
        if let Some(status) = outcome.report.get("status") {
            object.insert("status".to_owned(), status.clone());
        }
        if let Some(message) = outcome.report.get("message") {
            object.insert("message".to_owned(), message.clone());
        }
    }
    Ok(Some(report))
}

enum GeodataHttpResult {
    Body(Vec<u8>),
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

        let status = geodata_status_for_dir(&dir).unwrap();
        assert_eq!(status["geosite"]["categoryCount"], json!(2));
        assert_eq!(status["geosite"]["ruleCount"], json!(3));
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
