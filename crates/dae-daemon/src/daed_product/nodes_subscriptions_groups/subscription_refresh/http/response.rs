use super::*;

pub(super) struct SubscriptionHttpResponse {
    pub(super) status: u16,
    pub(super) headers: BTreeMap<String, Vec<String>>,
    pub(super) body: Vec<u8>,
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn http_response_body_with_limit(
    response: &[u8],
    body_limit: usize,
) -> io::Result<String> {
    let response = parse_subscription_http_response(response, body_limit)?;
    if !(200..300).contains(&response.status) {
        return Err(io::Error::other(format!(
            "subscription fetch returned HTTP {}",
            response.status
        )));
    }
    String::from_utf8(response.body).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription response is not UTF-8: {err}"),
        )
    })
}

pub(super) fn parse_subscription_http_response(
    response: &[u8],
    body_limit: usize,
) -> io::Result<SubscriptionHttpResponse> {
    let (header_text, header_end) = response_headers(response)?;
    let (status, headers) = parse_response_headers(header_text)?;
    let body = decode_response_body(&response[header_end..], &headers, body_limit)?;
    Ok(SubscriptionHttpResponse {
        status,
        headers,
        body,
    })
}

fn response_headers(response: &[u8]) -> io::Result<(&str, usize)> {
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
    let header_text = std::str::from_utf8(&response[..split]).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription response headers are not UTF-8: {err}"),
        )
    })?;
    Ok((header_text, header_end))
}

fn parse_response_headers(header_text: &str) -> io::Result<(u16, BTreeMap<String, Vec<String>>)> {
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status line"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?
        .parse::<u16>()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HTTP status: {err}"),
            )
        })?;
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "folded subscription response headers are not supported",
            ));
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed subscription response header",
            )
        })?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty subscription response header name",
            ));
        }
        headers
            .entry(name)
            .or_default()
            .push(value.trim().to_owned());
    }
    Ok((status, headers))
}

fn decode_response_body(
    encoded: &[u8],
    headers: &BTreeMap<String, Vec<String>>,
    body_limit: usize,
) -> io::Result<Vec<u8>> {
    if encoded.len() > body_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription response body exceeds {body_limit} bytes"),
        ));
    }
    let transfer_codings = header_tokens(headers, "transfer-encoding");
    let mut body = if let Some(chunked_position) =
        transfer_codings.iter().position(|value| value == "chunked")
    {
        if chunked_position + 1 != transfer_codings.len()
            || transfer_codings
                .iter()
                .any(|value| value != "chunked" && value != "identity")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported subscription Transfer-Encoding",
            ));
        }
        decode_chunked_body_with_limit(encoded, body_limit)?
    } else {
        if !transfer_codings.iter().all(|value| value == "identity") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported subscription Transfer-Encoding",
            ));
        }
        validate_content_length(encoded, headers, body_limit)?;
        encoded.to_vec()
    };
    for encoding in header_tokens(headers, "content-encoding").into_iter().rev() {
        body = decode_content_encoding(body, &encoding, body_limit)?;
    }
    Ok(body)
}

fn validate_content_length(
    body: &[u8],
    headers: &BTreeMap<String, Vec<String>>,
    body_limit: usize,
) -> io::Result<()> {
    let Some(content_length) = first_header(headers, "content-length") else {
        return Ok(());
    };
    let content_length = content_length.parse::<usize>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid subscription Content-Length: {err}"),
        )
    })?;
    if content_length > body_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription response body exceeds {body_limit} bytes"),
        ));
    }
    if body.len() != content_length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "subscription response body length mismatch: expected {content_length}, got {}",
                body.len()
            ),
        ));
    }
    Ok(())
}

fn decode_content_encoding(body: Vec<u8>, encoding: &str, limit: usize) -> io::Result<Vec<u8>> {
    match encoding {
        "identity" => Ok(body),
        "gzip" | "x-gzip" => {
            read_decoded_limited(flate2::read::GzDecoder::new(body.as_slice()), limit, "gzip")
        }
        "br" => read_decoded_limited(
            brotli::Decompressor::new(body.as_slice(), 8192),
            limit,
            "brotli",
        ),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported subscription Content-Encoding: {encoding}"),
        )),
    }
}

pub(super) fn first_header<'a>(
    headers: &'a BTreeMap<String, Vec<String>>,
    name: &str,
) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn header_tokens(headers: &BTreeMap<String, Vec<String>>, name: &str) -> Vec<String> {
    headers
        .get(name)
        .into_iter()
        .flatten()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

pub(super) fn is_subscription_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn read_decoded_limited<R: Read>(
    mut reader: R,
    limit: usize,
    encoding: &str,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decode subscription {encoding} body: {err}"),
            )
        })?;
        if read == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(read) > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded subscription body exceeds {limit} bytes"),
            ));
        }
        out.extend_from_slice(&buffer[..read]);
    }
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
            return Ok(out);
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
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "chunked body is missing the terminating chunk",
    ))
}

pub(super) fn subscription_http_response_limit(body_limit: usize) -> io::Result<usize> {
    SUBSCRIPTION_HTTP_HEADER_LIMIT
        .checked_add(body_limit)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription response limit overflow",
            )
        })
}
