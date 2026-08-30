use std::io::Read;

use dae_outbound_core::error::OutboundError;

pub fn read_http_head(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let (mut head, leftover) =
        read_http_head_with_leftover(stream, 8192, OutboundError::BadSharedTransport)?;
    head.extend_from_slice(&leftover);
    Ok(head)
}

pub fn read_http_head_with_leftover(
    stream: &mut impl Read,
    max_bytes: usize,
    error: impl Fn(String) -> OutboundError,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 256];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|err| error(err.to_string()))?;
        if read == 0 {
            return Err(error("incomplete http response header".to_owned()));
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let head_end = index + 4;
            if head_end > max_bytes {
                return Err(error("http response header too large".to_owned()));
            }
            let leftover = response.split_off(head_end);
            return Ok((response, leftover));
        }
        if response.len() > max_bytes {
            return Err(error("http response header too large".to_owned()));
        }
    }
}

pub fn read_http_message<S: Read>(
    stream: &mut S,
    context: &str,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let (head, mut body) = read_http_head_with_leftover(stream, 8192, |message| {
        OutboundError::BadSharedTransport(format!("{context}: {message}"))
    })?;
    let content_length =
        super::bounded_http_message_body_length(http_content_length(&head)?, context)?;
    while body.len() < content_length {
        let mut buffer = [0_u8; 8192];
        let wanted = (content_length - body.len()).min(buffer.len());
        let read = stream
            .read(&mut buffer[..wanted])
            .map_err(|error| OutboundError::BadSharedTransport(error.to_string()))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..read]);
    }
    if body.len() < content_length {
        return Err(OutboundError::BadSharedTransport(format!(
            "incomplete {context} body"
        )));
    }
    body.truncate(content_length);
    Ok((head, body))
}

pub fn http_content_length(head: &[u8]) -> Result<usize, OutboundError> {
    let text = std::str::from_utf8(head)
        .map_err(|error| OutboundError::BadSharedTransport(error.to_string()))?;
    http_header_value(text, "content-length")
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|error| OutboundError::BadSharedTransport(error.to_string()))
}

pub fn http_header_value<'a>(head: &'a str, key: &str) -> Option<&'a str> {
    for line in head.split("\r\n") {
        let Some((got_key, value)) = line.split_once(':') else {
            continue;
        };
        if got_key.eq_ignore_ascii_case(key) {
            return Some(value.trim());
        }
    }
    None
}
