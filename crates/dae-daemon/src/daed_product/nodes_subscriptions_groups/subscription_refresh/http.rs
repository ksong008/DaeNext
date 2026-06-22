use super::*;

pub(super) fn fetch_http_url(url: &url::Url, tls: bool) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port for subscription")
    })?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let user_agent = subscription_user_agent();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: text/plain, application/octet-stream, */*\r\nConnection: close\r\n\r\n"
    );
    let stream = connect_tcp_endpoint(host, port, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
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
                format!("invalid tls server name: {err}"),
            )
        })?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(|err| io::Error::other(format!("tls connect: {err}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        read_subscription_http_response(&mut tls_stream)?
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        read_subscription_http_response(&mut stream)?
    };
    http_response_body(&response)
}

fn subscription_user_agent() -> String {
    format!(
        "dae/{} (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)",
        env!("CARGO_PKG_VERSION")
    )
}

fn read_subscription_http_response<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    read_subscription_http_response_with_limit(reader, subscription_http_body_limit())
}

pub(crate) fn read_subscription_http_response_with_limit<R: Read>(
    reader: &mut R,
    body_limit: usize,
) -> io::Result<Vec<u8>> {
    let response_limit = subscription_http_response_limit(body_limit)?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let next_len = response.len().checked_add(read).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "subscription response size overflow",
            )
        })?;
        if next_len > response_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription response exceeds {response_limit} bytes"),
            ));
        }
        response.extend_from_slice(&buf[..read]);
    }
    Ok(response)
}

pub(crate) fn http_response_body(response: &[u8]) -> io::Result<String> {
    http_response_body_with_limit(response, subscription_http_body_limit())
}

pub(crate) fn http_response_body_with_limit(
    response: &[u8],
    body_limit: usize,
) -> io::Result<String> {
    let split = find_subsequence(response, b"\r\n\r\n")
        .or_else(|| find_subsequence(response, b"\n\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing http headers"))?;
    if split > SUBSCRIPTION_HTTP_HEADER_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "subscription response headers exceed {} bytes",
                SUBSCRIPTION_HTTP_HEADER_LIMIT
            ),
        ));
    }
    let header_end = if response.get(split..split + 4) == Some(b"\r\n\r\n") {
        split + 4
    } else {
        split + 2
    };
    let headers = String::from_utf8_lossy(&response[..split]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "subscription fetch returned HTTP {status}"
        )));
    }
    let mut body = response[header_end..].to_vec();
    if body.len() > body_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription response body exceeds {body_limit} bytes"),
        ));
    }
    if headers
        .lines()
        .any(|line| line.to_ascii_lowercase().trim() == "transfer-encoding: chunked")
    {
        body = decode_chunked_body_with_limit(&body, body_limit)?;
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
pub(crate) fn decode_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    decode_chunked_body_with_limit(body, subscription_http_body_limit())
}

pub(crate) fn decode_chunked_body_with_limit(
    body: &[u8],
    body_limit: usize,
) -> io::Result<Vec<u8>> {
    let mut index = 0;
    let mut out = Vec::new();
    while index < body.len() {
        let Some(line_end) = find_subsequence(&body[index..], b"\r\n") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunked body",
            ));
        };
        let size_text = String::from_utf8_lossy(&body[index..index + line_end]);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {err}"),
            )
        })?;
        let next_len = out.len().checked_add(size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded chunked body size overflow",
            )
        })?;
        if next_len > body_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded subscription body exceeds {body_limit} bytes"),
            ));
        }
        index += line_end + 2;
        if size == 0 {
            break;
        }
        if index + size > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated chunked body",
            ));
        }
        out.extend_from_slice(&body[index..index + size]);
        let data_end = index + size;
        if body.get(data_end..data_end + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body chunk missing trailing CRLF",
            ));
        }
        index = data_end + 2;
    }
    Ok(out)
}

fn subscription_http_response_limit(body_limit: usize) -> io::Result<usize> {
    SUBSCRIPTION_HTTP_HEADER_LIMIT
        .checked_add(body_limit)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription response limit overflow",
            )
        })
}
