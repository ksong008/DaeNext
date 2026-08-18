use std::fmt;

#[derive(Debug, Eq, PartialEq)]
pub enum HttpChunkedDecodeError {
    Incomplete(&'static str),
    Invalid(String),
}

impl HttpChunkedDecodeError {
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete(_))
    }
}

impl fmt::Display for HttpChunkedDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete(message) => formatter.write_str(message),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

pub fn decode_http_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    decode_http_chunked_body_with_consumed(raw)
        .map(|(body, _)| body)
        .map_err(|err| err.to_string())
}

pub fn decode_http_chunked_body_with_consumed(
    raw: &[u8],
) -> Result<(Vec<u8>, usize), HttpChunkedDecodeError> {
    let mut offset = 0_usize;
    let mut out = Vec::new();
    loop {
        let line_end = find_crlf(raw, offset).ok_or(HttpChunkedDecodeError::Incomplete(
            "chunked DoH body has no chunk-size line end",
        ))?;
        let line = std::str::from_utf8(&raw[offset..line_end]).map_err(|err| {
            HttpChunkedDecodeError::Invalid(format!("chunked DoH size line is not UTF-8: {err}"))
        })?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|err| {
            HttpChunkedDecodeError::Invalid(format!("parse chunked DoH size {size_hex:?}: {err}"))
        })?;
        offset = line_end.checked_add(2).ok_or_else(|| {
            HttpChunkedDecodeError::Invalid("chunked DoH offset overflow".to_owned())
        })?;
        if size == 0 {
            return consume_trailers(raw, offset, out);
        }
        let end = offset.checked_add(size).ok_or_else(|| {
            HttpChunkedDecodeError::Invalid("chunked DoH body size overflow".to_owned())
        })?;
        let chunk_end = end.checked_add(2).ok_or_else(|| {
            HttpChunkedDecodeError::Invalid("chunked DoH chunk boundary overflow".to_owned())
        })?;
        if raw.len() < chunk_end {
            return Err(HttpChunkedDecodeError::Incomplete(
                "chunked DoH body is truncated",
            ));
        }
        out.extend_from_slice(&raw[offset..end]);
        if &raw[end..chunk_end] != b"\r\n" {
            return Err(HttpChunkedDecodeError::Invalid(
                "chunked DoH chunk missing trailing CRLF".to_owned(),
            ));
        }
        offset = chunk_end;
    }
}

fn consume_trailers(
    raw: &[u8],
    mut offset: usize,
    body: Vec<u8>,
) -> Result<(Vec<u8>, usize), HttpChunkedDecodeError> {
    loop {
        let line_end = find_crlf(raw, offset).ok_or(HttpChunkedDecodeError::Incomplete(
            "chunked DoH trailers are incomplete",
        ))?;
        if line_end == offset {
            return Ok((body, line_end + 2));
        }
        let trailer = &raw[offset..line_end];
        let Some(separator) = trailer.iter().position(|byte| *byte == b':') else {
            return Err(HttpChunkedDecodeError::Invalid(
                "chunked DoH trailer is malformed".to_owned(),
            ));
        };
        if separator == 0 {
            return Err(HttpChunkedDecodeError::Invalid(
                "chunked DoH trailer name is empty".to_owned(),
            ));
        }
        offset = line_end + 2;
    }
}

fn find_crlf(raw: &[u8], offset: usize) -> Option<usize> {
    raw.get(offset..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| offset + index)
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
mod tests;
