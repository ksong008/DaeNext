use super::status::is_valid_geodata_release_version;
use super::types::{
    GEODATA_HTTP_BODY_LIMIT, GEODATA_HTTP_HEADER_LIMIT, GEODATA_REDIRECT_LIMIT,
    GeodataFileDownload, GeodataKind, GeodataRelease,
};
use super::*;

pub(super) fn fetch_geodata_url(url: &url::Url) -> io::Result<Vec<u8>> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_once(&current)? {
            GeodataHttpResult::Body(body) => return Ok(body),
            GeodataHttpResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

pub(super) fn fetch_geodata_url_to_file(
    url: &url::Url,
    output_path: &Path,
    proxy_config: Option<&Config>,
) -> io::Result<GeodataFileDownload> {
    if let Some(config) = proxy_config {
        return fetch_geodata_url_to_file_via_default_proxy(url, output_path, config);
    }
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_to_file_once(&current, output_path)? {
            GeodataHttpFileResult::Body(download) => return Ok(download),
            GeodataHttpFileResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

pub(super) fn fetch_geodata_latest_release(
    kind: GeodataKind,
    api_url: &url::Url,
    proxy_config: Option<&Config>,
) -> io::Result<GeodataRelease> {
    let body = fetch_geodata_url_with_proxy_config(api_url, proxy_config)?;
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

fn fetch_geodata_url_with_proxy_config(
    url: &url::Url,
    proxy_config: Option<&Config>,
) -> io::Result<Vec<u8>> {
    if let Some(config) = proxy_config {
        return fetch_geodata_url_via_default_proxy(url, config);
    }
    fetch_geodata_url(url)
}

fn fetch_geodata_url_via_default_proxy(url: &url::Url, config: &Config) -> io::Result<Vec<u8>> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_once_via_default_proxy(&current, config)? {
            GeodataHttpResult::Body(body) => return Ok(body),
            GeodataHttpResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

fn fetch_geodata_url_to_file_via_default_proxy(
    url: &url::Url,
    output_path: &Path,
    config: &Config,
) -> io::Result<GeodataFileDownload> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_to_file_once_via_default_proxy(&current, output_path, config)? {
            GeodataHttpFileResult::Body(download) => return Ok(download),
            GeodataHttpFileResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

enum GeodataHttpResult {
    Body(Vec<u8>),
    Redirect(url::Url),
}

pub(super) enum GeodataHttpFileResult {
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
    let stream = connect_tcp_endpoint(host, port, Duration::from_secs(10)).map_err(|err| {
        io::Error::new(err.kind(), format!("connect geodata {host}:{port}: {err}"))
    })?;
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

fn fetch_geodata_url_once_via_default_proxy(
    url: &url::Url,
    config: &Config,
) -> io::Result<GeodataHttpResult> {
    let request = geodata_http_request(url)?;
    let response = fetch_geodata_http_response_via_default_proxy(url, config, request.as_bytes())?;
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
    let stream = connect_tcp_endpoint(host, port, Duration::from_secs(10)).map_err(|err| {
        io::Error::new(err.kind(), format!("connect geodata {host}:{port}: {err}"))
    })?;
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

fn fetch_geodata_url_to_file_once_via_default_proxy(
    url: &url::Url,
    output_path: &Path,
    config: &Config,
) -> io::Result<GeodataHttpFileResult> {
    let request = geodata_http_request(url)?;
    let response = fetch_geodata_http_response_via_default_proxy(url, config, request.as_bytes())?;
    geodata_http_response_to_file_from_bytes(url, response, output_path)
}

fn fetch_geodata_http_response_via_default_proxy(
    url: &url::Url,
    config: &Config,
    request: &[u8],
) -> io::Result<Vec<u8>> {
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
    crate::production_runtime_owner::fetch_http_url_via_default_proxy(
        config,
        url,
        tls,
        request,
        geodata_http_response_limit()?,
    )
    .map_err(|err| io::Error::other(format!("geodata proxy fetch {host}: {err}")))
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

fn geodata_http_response_limit() -> io::Result<usize> {
    GEODATA_HTTP_HEADER_LIMIT
        .checked_add(GEODATA_HTTP_BODY_LIMIT)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "geodata response limit overflow",
            )
        })
}

pub(super) fn read_geodata_http_response<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let response_limit = geodata_http_response_limit()?;
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

pub(super) fn read_geodata_http_response_to_file<R: Read>(
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

fn geodata_http_response_to_file_from_bytes(
    base_url: &url::Url,
    response: Vec<u8>,
    output_path: &Path,
) -> io::Result<GeodataHttpFileResult> {
    match geodata_http_body(base_url, response)? {
        GeodataHttpResult::Redirect(next) => Ok(GeodataHttpFileResult::Redirect(next)),
        GeodataHttpResult::Body(body) => {
            let mut file = fs::File::create(output_path)?;
            file.write_all(&body)?;
            file.sync_all()?;
            Ok(GeodataHttpFileResult::Body(GeodataFileDownload {
                bytes: body.len() as u64,
                sha256: hex_encode(&Sha256::digest(&body)),
            }))
        }
    }
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
