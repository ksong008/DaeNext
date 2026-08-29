use super::*;
const STATIC_FILE_CHUNK_BYTES: usize = 16 * 1024;
const STATIC_ASSET_HASH_SUFFIX_BYTES: usize = 8;
const STATIC_INDEX_CACHE_CONTROL: &str = "no-cache";
const STATIC_HASHED_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

pub(super) fn write_static_file_response(
    stream: &mut TcpStream,
    web_root: &Path,
    request: &HttpRequest,
    head_only: bool,
) -> io::Result<()> {
    if request.method != "GET" && request.method != "HEAD" {
        let response = HttpResponse::json(405, json!({"error": "method should be GET or HEAD"}));
        return write_http_response_for_request(stream, request, &response, head_only);
    }
    let mut path = match safe_static_path(web_root, &request.path) {
        Some(path) => path,
        None => {
            let response = HttpResponse::json(400, json!({"error": "invalid static path"}));
            return write_http_response_for_request(stream, request, &response, head_only);
        }
    };
    if path.is_dir() {
        path = path.join("index.html");
    }
    if !path.is_file() {
        path = web_root.join("index.html");
    }
    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            let response = HttpResponse::json(404, json!({"error": error.to_string()}));
            return write_http_response_for_request(stream, request, &response, head_only);
        }
    };
    let content_length = file.metadata()?.len();
    let deadline = Instant::now()
        .checked_add(PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut head = Vec::with_capacity(256);
    let cache_control = static_cache_control(web_root, &path);
    write!(
        head,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: {}\r\n\r\n",
        mime_for_path(&path),
        content_length,
        cache_control,
    )?;
    write_all_with_deadline(stream, &head, deadline)?;
    if !head_only {
        let mut chunk = [0_u8; STATIC_FILE_CHUNK_BYTES];
        loop {
            let read = match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            write_all_with_deadline(stream, &chunk[..read], deadline)?;
        }
    }
    stream.set_write_timeout(Some(socket_timeout_until(
        deadline,
        "HTTP response write deadline exceeded",
    )?))?;
    stream.flush()
}

pub(super) fn serve_static_file(web_root: &Path, request: &HttpRequest) -> HttpResponse {
    if request.method != "GET" && request.method != "HEAD" {
        return HttpResponse::json(405, json!({"error": "method should be GET or HEAD"}));
    }
    let mut path = match safe_static_path(web_root, &request.path) {
        Some(path) => path,
        None => return HttpResponse::json(400, json!({"error": "invalid static path"})),
    };
    if path.is_dir() {
        path = path.join("index.html");
    }
    if !path.is_file() {
        path = web_root.join("index.html");
    }
    match fs::read(&path) {
        Ok(body) => {
            let mut response = HttpResponse::text(200, mime_for_path(&path), body);
            response.extra_headers.push((
                "Cache-Control".to_owned(),
                static_cache_control(web_root, &path).to_owned(),
            ));
            response
        }
        Err(err) => HttpResponse::json(404, json!({"error": err.to_string()})),
    }
}

fn static_cache_control(web_root: &Path, path: &Path) -> &'static str {
    if is_content_hashed_asset(web_root, path) {
        STATIC_HASHED_ASSET_CACHE_CONTROL
    } else {
        STATIC_INDEX_CACHE_CONTROL
    }
}

fn is_content_hashed_asset(web_root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(web_root) else {
        return false;
    };
    if relative
        .components()
        .next()
        .is_none_or(|component| component.as_os_str() != "assets")
    {
        return false;
    }
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };
    let bytes = stem.as_bytes();
    let Some(hash_start) = bytes.len().checked_sub(STATIC_ASSET_HASH_SUFFIX_BYTES) else {
        return false;
    };
    bytes[..hash_start].contains(&b'-')
        && bytes[hash_start..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(super) fn safe_static_path(web_root: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(request_path);
    let trimmed = decoded.trim_start_matches('/');
    let mut path = PathBuf::from(web_root);
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(path)
}

pub(super) fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

pub(super) fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
    head_only: bool,
) -> io::Result<()> {
    write_http_response_with_origin_and_timeout(
        stream,
        None,
        response,
        head_only,
        PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT,
    )
}

pub(in crate::daed_product) fn write_http_response_with_timeout(
    stream: &mut TcpStream,
    response: &HttpResponse,
    head_only: bool,
    timeout: Duration,
) -> io::Result<()> {
    write_http_response_with_origin_and_timeout(stream, None, response, head_only, timeout)
}

pub(super) fn write_http_response_for_request(
    stream: &mut TcpStream,
    request: &HttpRequest,
    response: &HttpResponse,
    head_only: bool,
) -> io::Result<()> {
    write_http_response_with_origin_and_timeout(
        stream,
        request.headers.get("origin").map(String::as_str),
        response,
        head_only,
        PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT,
    )
}

fn write_http_response_with_origin_and_timeout(
    stream: &mut TcpStream,
    origin: Option<&str>,
    response: &HttpResponse,
    head_only: bool,
    timeout: Duration,
) -> io::Result<()> {
    let mut head = Vec::with_capacity(512);
    let reason = status_reason(response.status);
    write!(
        head,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    )?;
    if let Some(origin) = origin.and_then(allowed_cors_origin_value) {
        write!(
            head,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, X-Daed-Page-Id\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\nAccess-Control-Max-Age: 300\r\n",
        )?;
    }
    for (key, value) in &response.extra_headers {
        write!(head, "{key}: {value}\r\n")?;
    }
    write!(head, "\r\n")?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    write_all_with_deadline(stream, &head, deadline)?;
    if !head_only {
        write_all_with_deadline(stream, &response.body, deadline)?;
    }
    stream.set_write_timeout(Some(socket_timeout_until(
        deadline,
        "HTTP response write deadline exceeded",
    )?))?;
    stream.flush()
}

fn write_all_with_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(socket_timeout_until(
            deadline,
            "HTTP response write deadline exceeded",
        )?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write HTTP response",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if is_socket_timeout(&error) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP response write deadline exceeded",
                ));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(in crate::daed_product) fn allowed_cors_origin(request: &HttpRequest) -> Option<&str> {
    request
        .headers
        .get("origin")
        .and_then(|origin| allowed_cors_origin_value(origin))
}

pub(in crate::daed_product) fn allowed_cors_origin_value(origin: &str) -> Option<&str> {
    let origin = origin.trim();
    if origin.is_empty() || origin.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return None;
    }
    let parsed = url::Url::parse(origin).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_matches(['[', ']']);
    if is_local_origin_host(host) {
        Some(origin)
    } else {
        None
    }
}

fn is_local_origin_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    ip.is_loopback() || local_interface_ips().contains(&ip)
}

struct IfAddrs {
    head: *mut libc::ifaddrs,
}

impl IfAddrs {
    fn load() -> io::Result<Self> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs initializes `head` on success. The pointer is
        // owned by IfAddrs and released with freeifaddrs in Drop.
        let status = unsafe { libc::getifaddrs(&mut head) };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { head })
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: `head` came from a successful getifaddrs call and has
            // not been freed elsewhere because IfAddrs owns it.
            unsafe { libc::freeifaddrs(self.head) };
        }
    }
}

fn local_interface_ips() -> Vec<std::net::IpAddr> {
    let mut addrs = Vec::new();
    let Ok(ifaddrs) = IfAddrs::load() else {
        return addrs;
    };
    let mut cursor = ifaddrs.head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is either the head returned by getifaddrs or an
        // ifa_next pointer from the same list, and the list stays alive for
        // this loop through the IfAddrs owner.
        let addr = unsafe { (*cursor).ifa_addr };
        if !addr.is_null() {
            // SAFETY: `addr` is non-null and points to a sockaddr whose family
            // field can be read before casting to the matching concrete type.
            match unsafe { (*addr).sa_family as i32 } {
                libc::AF_INET => {
                    // SAFETY: sa_family reported AF_INET, so sockaddr_in is
                    // the layout for this address entry.
                    let sockaddr = unsafe { *(addr.cast::<libc::sockaddr_in>()) };
                    addrs.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                        sockaddr.sin_addr.s_addr.to_ne_bytes(),
                    )));
                }
                libc::AF_INET6 => {
                    // SAFETY: sa_family reported AF_INET6, so sockaddr_in6 is
                    // the layout for this address entry.
                    let sockaddr = unsafe { *(addr.cast::<libc::sockaddr_in6>()) };
                    addrs.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        sockaddr.sin6_addr.s6_addr,
                    )));
                }
                _ => {}
            }
        }
        // SAFETY: `cursor` is a valid ifaddrs node from the live list.
        cursor = unsafe { (*cursor).ifa_next };
    }
    addrs
}

pub(super) fn set_private_runtime_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(super) fn sqlite_io_error(err: rusqlite::Error) -> io::Error {
    io::Error::other(err)
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(super) fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown Status",
    }
}

pub(super) fn help_text() -> String {
    r#"daed Rust native product commands:
  daed --version
  daed run -c /etc/daed --listen 0.0.0.0:2023 [--api-only] [--web-root PATH] [--control PATH]
  daed reload [--control PATH] [--timeout 60s] [--json]
  daed wait-ready [--control PATH] [--timeout 60s] [--json]
  daed validate -c /etc/daed/|/etc/dae/config.dae [--state /etc/daed/daed.db] [--runtime] [--json]
  daed service-contract [--json]
  daed package-info [--json]
  daed resident-adapter-matrix -c /etc/dae/config.dae [--json]
  daed resident-adapter-udp-live -c /etc/dae/config.dae --target HOST:PORT [--payload TEXT|--payload-hex HEX] [--json]
  daed state check --state /etc/daed/daed.db
  daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db [--force]
  daed export openapi|flatdesc|outline|package-manifest|admission-report|webui-route-audit|systemd-unit|docker-entrypoint
  daed resetpass -c /etc/daed [--json]
"#
    .to_owned()
}

#[cfg(test)]
mod static_response_tests {
    use super::*;

    #[test]
    fn static_response_streams_the_complete_file_with_bounded_chunks() {
        let root = std::env::temp_dir().join(format!("daed-static-response-{}", fastrand::u64(..)));
        fs::create_dir_all(&root).unwrap();
        let body = vec![0x5a; STATIC_FILE_CHUNK_BYTES * 3 + 17];
        fs::write(root.join("asset.bin"), &body).unwrap();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let request = HttpRequest {
            method: "GET".to_owned(),
            path: "/asset.bin".to_owned(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let writer = thread::spawn(move || {
            write_static_file_response(&mut server, &root, &request, false).unwrap();
            fs::remove_dir_all(root).unwrap();
        });
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        writer.join().unwrap();
        let body_start = find_subsequence(&response, b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&response[body_start..], body.as_slice());
        assert!(
            String::from_utf8_lossy(&response[..body_start])
                .contains(&format!("Content-Length: {}", body.len()))
        );
    }

    #[test]
    fn hashed_assets_are_immutable_while_index_stays_revalidated() {
        let root = std::env::temp_dir().join(format!("daed-static-cache-{}", fastrand::u64(..)));
        let assets = root.join("assets");
        fs::create_dir_all(&assets).unwrap();
        let index = root.join("index.html");
        let asset = assets.join("index-AbCd1234.js");
        let unhashed_asset = assets.join("runtime.js");
        fs::write(&index, b"index").unwrap();
        fs::write(&asset, b"asset").unwrap();
        fs::write(&unhashed_asset, b"runtime").unwrap();

        assert_eq!(
            static_cache_control(&root, &index),
            STATIC_INDEX_CACHE_CONTROL
        );
        assert_eq!(
            static_cache_control(&root, &asset),
            STATIC_HASHED_ASSET_CACHE_CONTROL
        );
        assert_eq!(
            static_cache_control(&root, &unhashed_asset),
            STATIC_INDEX_CACHE_CONTROL
        );

        fs::remove_dir_all(root).unwrap();
    }
}
