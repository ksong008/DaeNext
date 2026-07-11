use super::*;
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
            response
                .extra_headers
                .push(("Cache-Control".to_owned(), "no-cache".to_owned()));
            response
        }
        Err(err) => HttpResponse::json(404, json!({"error": err.to_string()})),
    }
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

pub(in crate::daed_product) fn write_cors_headers(
    stream: &mut TcpStream,
    request: &HttpRequest,
) -> io::Result<()> {
    if let Some(origin) = allowed_cors_origin(request) {
        write!(
            stream,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\nAccess-Control-Max-Age: 300\r\n",
        )?;
    }
    Ok(())
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
        if head_only { 0 } else { response.body.len() }
    )?;
    if let Some(origin) = origin.and_then(allowed_cors_origin_value) {
        write!(
            head,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\nAccess-Control-Max-Age: 300\r\n",
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

pub(super) fn split_path_query(raw: &str) -> (String, HashMap<String, Vec<String>>) {
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let mut out = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.entry(percent_decode(key))
            .or_insert_with(Vec::new)
            .push(percent_decode(value));
    }
    (percent_decode(path), out)
}

pub(super) fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
                {
                    out.push((high << 4) | low);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub(super) fn json_body(request: &HttpRequest) -> Result<Value, String> {
    if request.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&request.body).map_err(|err| format!("invalid json body: {err}"))
}

pub(super) fn required_str<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

pub(super) fn string_array(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn list_tables(conn: &Connection) -> io::Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_io_error)?;
    let mut tables = Vec::new();
    for row in rows {
        tables.push(row.map_err(sqlite_io_error)?);
    }
    Ok(tables)
}

pub(super) fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buf[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

pub(super) fn set_private_db_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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
  daed validate -c /etc/daed/|/etc/dae/config.dae [--runtime] [--json]
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
