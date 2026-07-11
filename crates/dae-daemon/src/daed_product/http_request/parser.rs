use super::*;

const HTTP_REQUEST_READ_BUFFER_BYTES: usize = 4 * 1024;

pub(in crate::daed_product) fn read_http_request(
    stream: &mut TcpStream,
) -> io::Result<HttpRequest> {
    read_http_request_with_policy(stream, HttpRequestReadPolicy::production())
}

pub(in crate::daed_product) fn read_http_request_with_policy(
    stream: &mut TcpStream,
    policy: HttpRequestReadPolicy,
) -> io::Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; HTTP_REQUEST_READ_BUFFER_BYTES];
    let header_end = read_request_headers(stream, policy, &mut buffer, &mut temp)?;
    let (method, raw_path, headers) = parse_request_head(&buffer[..header_end - 4])?;
    let content_length = parse_content_length(&headers)?;
    let body_limit = request_body_limit(&method, &raw_path);
    if content_length > body_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "body is too large",
        ));
    }
    read_request_body(
        stream,
        policy.body_idle_timeout,
        policy.body_timeout_for(&method, &raw_path),
        &mut buffer,
        &mut temp,
        header_end,
        content_length,
    )?;
    stream.set_read_timeout(None)?;

    let body = buffer[header_end..header_end + content_length].to_vec();
    let (path, query) = split_path_query(&raw_path);
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn read_request_headers(
    stream: &mut TcpStream,
    policy: HttpRequestReadPolicy,
    buffer: &mut Vec<u8>,
    temp: &mut [u8; HTTP_REQUEST_READ_BUFFER_BYTES],
) -> io::Result<usize> {
    let started_at = Instant::now();
    loop {
        let deadline = policy.header_deadline(started_at, buffer.len());
        stream.set_read_timeout(Some(socket_timeout_until(
            deadline,
            "request header read deadline exceeded",
        )?))?;
        let read = match stream.read(temp) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if is_socket_timeout(&error) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request header read deadline exceeded",
                ));
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while reading request headers",
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
        if let Some(index) = find_subsequence(buffer, b"\r\n\r\n") {
            let header_end = index + 4;
            if header_end > MAX_HTTP_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request headers are too large",
                ));
            }
            return Ok(header_end);
        }
        if buffer.len() > MAX_HTTP_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers are too large",
            ));
        }
    }
}

fn parse_request_head(raw: &[u8]) -> io::Result<(String, String, HashMap<String, String>)> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers are not valid UTF-8",
        )
    })?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let (method, raw_path) = parse_request_line(request_line)?;
    let mut headers = HashMap::<String, String>::new();
    for (index, line) in lines.enumerate() {
        if index >= MAX_HTTP_HEADER_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many request headers",
            ));
        }
        let (raw_name, raw_value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed request header")
        })?;
        if raw_name.is_empty() || !raw_name.bytes().all(is_http_token_byte) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed request header name",
            ));
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed request header value",
            ));
        }
        let name = raw_name.to_ascii_lowercase();
        if name == "content-length" && headers.contains_key(&name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate content-length header",
            ));
        }
        headers
            .entry(name)
            .and_modify(|current| {
                current.push_str(", ");
                current.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transfer-encoding request bodies are not supported",
        ));
    }
    Ok((method, raw_path, headers))
}

fn parse_request_line(line: &str) -> io::Result<(String, String)> {
    if line.bytes().any(|byte| byte < b' ' || byte == 0x7f) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }
    let mut parts = line.split(' ');
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?;
    let raw_path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?;
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP version"))?;
    if parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(is_http_token_byte)
        || raw_path.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }
    Ok((method.to_owned(), raw_path.to_owned()))
}

fn parse_content_length(headers: &HashMap<String, String>) -> io::Result<usize> {
    let Some(value) = headers.get("content-length") else {
        return Ok(0);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid content-length header",
        ));
    }
    value.parse::<usize>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "content-length header is too large",
        )
    })
}

fn read_request_body(
    stream: &mut TcpStream,
    idle_timeout: Duration,
    absolute_timeout: Duration,
    buffer: &mut Vec<u8>,
    temp: &mut [u8; HTTP_REQUEST_READ_BUFFER_BYTES],
    header_end: usize,
    content_length: usize,
) -> io::Result<()> {
    if buffer.len() >= header_end + content_length {
        return Ok(());
    }
    let deadline = Instant::now()
        .checked_add(absolute_timeout)
        .unwrap_or_else(Instant::now);
    while buffer.len() < header_end + content_length {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request body read deadline exceeded",
            ));
        }
        stream.set_read_timeout(Some(
            idle_timeout.min(remaining).max(Duration::from_millis(1)),
        ))?;
        let read = match stream.read(temp) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if is_socket_timeout(&error) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request body read deadline exceeded",
                ));
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request body is truncated",
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
    }
    Ok(())
}

fn request_body_limit(method: &str, raw_path: &str) -> usize {
    if is_bundle_import_request(method, raw_path) {
        MAX_BUNDLE_BODY_BYTES
    } else {
        MAX_BODY_BYTES
    }
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
