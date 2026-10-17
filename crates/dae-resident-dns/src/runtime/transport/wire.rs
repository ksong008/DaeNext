use super::super::*;

mod chunked;
use self::chunked::{decode_http_chunked_body, decode_http_chunked_body_with_consumed};

pub async fn open_dns_tcp_stream_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    mark: u32,
) -> Result<TokioTcpStream, String> {
    let connected = open_direct_tcp_connection_async(target.to_string(), mark, false)
        .await
        .map_err(|err| {
            format!(
                "connect DNS upstream {} {}: {err}",
                upstream.tag, upstream.target.authority
            )
        })?;
    TokioTcpStream::from_std(connected.stream).map_err(|err| format!("adopt DNS TCP stream: {err}"))
}

pub async fn forward_dns_framed_stream_async<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_dns_tcp_message_async(stream, payload).await?;
    read_dns_tcp_message_async(stream).await
}

pub async fn forward_dns_framed_stream_with_reader_async<S>(
    reader: &mut DnsTcpFrameReader,
    stream: &mut S,
    payload: &[u8],
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_dns_tcp_message_async(stream, payload).await?;
    reader
        .read_frame(stream)
        .await?
        .ok_or_else(|| "read DNS framed response: early eof".to_owned())
}

pub async fn write_dns_tcp_message_async<S>(stream: &mut S, payload: &[u8]) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    super::super::write_dns_tcp_payload_async(stream, payload)
        .await
        .map_err(|err| err.replace("DNS response", "DNS request"))
}

pub async fn read_dns_tcp_message_async<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|err| format!("read DNS TCP response length: {err}"))?;
    let len = u16::from_be_bytes(len) as usize;
    let mut response = vec![0_u8; len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|err| format!("read DNS TCP response payload: {err}"))?;
    Ok(response)
}

pub fn resident_dns_quic_client_config(
    alpn: &str,
    session_cache: dae_outbound_quic::boring_quic::BoringQuicSessionCache,
) -> Result<quinn::ClientConfig, String> {
    let policy = dae_outbound_quic::boring_quic::BoringQuicClientPolicy::new([alpn.as_bytes()])
        .map_err(|err| format!("build DNS BoringSSL QUIC policy: {err}"))?;
    dae_outbound_quic::boring_quic::build_boring_quic_client_config_with_session_cache(
        &policy,
        Arc::new(quinn::TransportConfig::default()),
        Some(session_cache),
    )
    .map_err(|err| format!("build DNS BoringSSL QUIC client config: {err}"))
}

pub fn http1_doh_request_bytes(doh: &dae_dns::DohRequest, target: &str) -> Vec<u8> {
    http1_doh_request_bytes_with_connection(doh, target, HTTP_CONNECTION_CLOSE)
}

pub fn http1_doh_keep_alive_request_bytes(doh: &dae_dns::DohRequest, target: &str) -> Vec<u8> {
    http1_doh_request_bytes_with_connection(doh, target, HTTP_CONNECTION_KEEP_ALIVE)
}

const HTTP_CONNECTION_CLOSE: &[u8] = b"close";
const HTTP_CONNECTION_KEEP_ALIVE: &[u8] = b"keep-alive";

fn http1_doh_request_bytes_with_connection(
    doh: &dae_dns::DohRequest,
    target: &str,
    connection: &[u8],
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(doh.method.as_bytes());
    request.extend_from_slice(b" ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(doh.host.as_bytes());
    request.extend_from_slice(b"\r\nAccept: ");
    request.extend_from_slice(doh.accept.as_bytes());
    request.extend_from_slice(b"\r\nConnection: ");
    request.extend_from_slice(connection);
    request.extend_from_slice(b"\r\n");
    if !doh.content_type.is_empty() {
        request.extend_from_slice(b"Content-Type: ");
        request.extend_from_slice(doh.content_type.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    if !doh.body.is_empty() {
        request.extend_from_slice(b"Content-Length: ");
        request.extend_from_slice(doh.body.len().to_string().as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&doh.body);
    request
}

pub fn doh_request_target(path: &str, dns_query: Option<&str>) -> String {
    match dns_query {
        Some(query) if path.contains('?') => format!("{path}&dns={query}"),
        Some(query) => format!("{path}?dns={query}"),
        None => path.to_owned(),
    }
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
pub async fn read_to_end_capped_async<S>(stream: &mut S, limit: usize) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = match stream.read(&mut buf).await {
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof && !out.is_empty() => {
                return Ok(out);
            }
            Err(err) => return Err(format!("read HTTP response: {err}")),
        };
        if read == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(read) > limit {
            return Err(format!("HTTP response exceeds read limit {limit}"));
        }
        out.extend_from_slice(&buf[..read]);
    }
}

pub async fn read_http1_response_message_capped_async<S>(
    stream: &mut S,
    limit: usize,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    read_http1_response_inner(stream, limit, false).await
}

pub async fn read_doh_http1_close_response_async<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    read_http1_response_inner(stream, DNS_DOH_HTTP_READ_LIMIT, true).await
}

async fn read_http1_response_inner<S>(
    stream: &mut S,
    limit: usize,
    allow_close: bool,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut raw = Vec::new();
    let mut buf = [0_u8; 8192];
    let header_end = loop {
        if let Some(header_end) = find_http_header_end(&raw) {
            if header_end + 4 > DNS_DOH_HEADER_READ_LIMIT {
                return Err("DoH headers exceed read limit".to_owned());
            }
            break header_end;
        }
        if raw.len() > DNS_DOH_HEADER_READ_LIMIT {
            return Err("DoH headers exceed read limit".to_owned());
        }
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|err| format!("read HTTP response: {err}"))?;
        if read == 0 {
            return Ok(raw);
        }
        append_http_response_bytes(&mut raw, &buf[..read], limit)?;
    };
    let body_start = header_end + 4;
    let boundary = http1_response_body_boundary(&raw[..header_end])?;
    match boundary {
        Http1ResponseBodyBoundary::ContentLength(len) => {
            let expected = body_start
                .checked_add(len)
                .ok_or_else(|| "HTTP response content-length overflow".to_owned())?;
            while raw.len() < expected {
                let read = stream
                    .read(&mut buf)
                    .await
                    .map_err(|err| format!("read HTTP response body: {err}"))?;
                if read == 0 {
                    break;
                }
                append_http_response_bytes(&mut raw, &buf[..read], limit)?;
            }
            if raw.len() < expected {
                return Err(format!(
                    "HTTP response body shorter than content-length: {} < {len}",
                    raw.len().saturating_sub(body_start)
                ));
            }
            raw.truncate(expected);
            Ok(raw)
        }
        Http1ResponseBodyBoundary::Chunked => {
            let consumed = loop {
                match decode_http_chunked_body_with_consumed(&raw[body_start..]) {
                    Ok((_, consumed)) => break consumed,
                    Err(err) if err.is_incomplete() => {
                        let read = stream
                            .read(&mut buf)
                            .await
                            .map_err(|err| format!("read chunked HTTP response body: {err}"))?;
                        if read == 0 {
                            return Err(err.to_string());
                        }
                        append_http_response_bytes(&mut raw, &buf[..read], limit)?;
                    }
                    Err(err) => return Err(err.to_string()),
                }
            };
            raw.truncate(body_start + consumed);
            Ok(raw)
        }
        Http1ResponseBodyBoundary::CloseDelimited => {
            if !allow_close {
                return Err("HTTP response has no reusable body boundary".to_owned());
            }
            loop {
                if raw.len().saturating_sub(body_start) > DNS_DOH_RESPONSE_READ_LIMIT {
                    return Err("decoded DoH body exceeds DNS wire limit".to_owned());
                }
                let read = match stream.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                    Err(e) => return Err(format!("read DoH response body: {e}")),
                };
                if read == 0 {
                    return Ok(raw);
                }
                if raw.len().saturating_sub(body_start).saturating_add(read)
                    > DNS_DOH_RESPONSE_READ_LIMIT
                {
                    return Err("decoded DoH body exceeds DNS wire limit".to_owned());
                }
                append_http_response_bytes(&mut raw, &buf[..read], limit)?;
            }
        }
    }
}

fn append_http_response_bytes(raw: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), String> {
    if raw.len().saturating_add(bytes.len()) > limit {
        return Err(format!("HTTP response exceeds read limit {limit}"));
    }
    raw.extend_from_slice(bytes);
    Ok(())
}

enum Http1ResponseBodyBoundary {
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

fn http1_response_body_boundary(headers: &[u8]) -> Result<Http1ResponseBodyBoundary, String> {
    let header_text = std::str::from_utf8(headers)
        .map_err(|err| format!("HTTP response headers are not UTF-8: {err}"))?;
    let mut chunked = false;
    let mut content_length = None;
    for line in header_text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                let length = value
                    .parse::<usize>()
                    .map_err(|err| format!("parse HTTP content-length: {err}"))?;
                if length > DNS_DOH_RESPONSE_READ_LIMIT {
                    return Err("DoH content-length exceeds DNS wire limit".to_owned());
                }
                if content_length
                    .replace(length)
                    .is_some_and(|old| old != length)
                {
                    return Err("conflicting DoH content-length headers".to_owned());
                }
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            _ => {}
        }
    }
    if chunked && content_length.is_some() {
        return Err("DoH response has both transfer-encoding and content-length".to_owned());
    }
    if chunked {
        Ok(Http1ResponseBodyBoundary::Chunked)
    } else if let Some(content_length) = content_length {
        Ok(Http1ResponseBodyBoundary::ContentLength(content_length))
    } else {
        Ok(Http1ResponseBodyBoundary::CloseDelimited)
    }
}

pub fn parse_doh_http_response(request: &[u8], raw: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = find_http_header_end(raw).ok_or("DoH response has no header end")?;
    if header_end + 4 > DNS_DOH_HEADER_READ_LIMIT {
        return Err("DoH headers exceed read limit".to_owned());
    }
    let headers = &raw[..header_end];
    let header_text =
        std::str::from_utf8(headers).map_err(|e| format!("invalid DoH headers: {e}"))?;
    let mut lines = header_text.split("\r\n");
    let status = lines.next().ok_or("DoH response has no status line")?;
    let status_code = status
        .split_whitespace()
        .nth(1)
        .ok_or("malformed DoH status")?
        .parse::<u16>()
        .map_err(|e| format!("invalid DoH status: {e}"))?;
    let content_type = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.trim())
        .unwrap_or("");
    validate_doh_response(status_code, status, content_type.as_bytes())
        .map_err(|e| e.to_string())?;
    let encoded = &raw[header_end + 4..];
    let body = match http1_response_body_boundary(headers)? {
        Http1ResponseBodyBoundary::Chunked => decode_http_chunked_body(encoded)?,
        Http1ResponseBodyBoundary::ContentLength(length) => encoded
            .get(..length)
            .ok_or("DoH body shorter than content-length")?
            .to_vec(),
        Http1ResponseBodyBoundary::CloseDelimited => {
            if encoded.len() > DNS_DOH_RESPONSE_READ_LIMIT {
                return Err("decoded DoH body exceeds DNS wire limit".to_owned());
            }
            encoded.to_vec()
        }
    };
    restore_dns_response_id(request, &body)
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

pub fn restore_dns_response_id(request: &[u8], response: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() < 2 {
        return Err("DNS request is too short to restore response id".to_owned());
    }
    let request_id = u16::from_be_bytes([request[0], request[1]]);
    restore_packed_response_request_id(response, request_id)
        .ok_or_else(|| "DNS response is too short to restore request id".to_owned())
}

pub fn dns_response_truncated(response: &[u8]) -> bool {
    response
        .get(2..4)
        .map(|flags| u16::from_be_bytes([flags[0], flags[1]]) & 0x0200 != 0)
        .unwrap_or(false)
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::ReadBuf;

    const CHUNKED_TRAILER_TEST_PENDING_WINDOW: Duration = Duration::from_millis(25);

    struct UnexpectedEofReader {
        bytes: &'static [u8],
        offset: usize,
    }

    impl UnexpectedEofReader {
        fn new(bytes: &'static [u8]) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl AsyncRead for UnexpectedEofReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset >= self.bytes.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing TLS close_notify",
                )));
            }
            let remaining = &self.bytes[self.offset..];
            let len = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..len]);
            self.offset += len;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn read_to_end_capped_accepts_unexpected_eof_after_bytes() {
        let mut reader = UnexpectedEofReader::new(b"HTTP/1.1 200 OK\r\n\r\nbody");

        let response = read_to_end_capped_async(&mut reader, 1024).await.unwrap();

        assert_eq!(response, b"HTTP/1.1 200 OK\r\n\r\nbody");
    }

    #[tokio::test]
    async fn read_to_end_capped_rejects_unexpected_eof_before_bytes() {
        let mut reader = UnexpectedEofReader::new(b"");

        let err = read_to_end_capped_async(&mut reader, 1024)
            .await
            .unwrap_err();

        assert!(err.contains("missing TLS close_notify"));
    }

    #[tokio::test]
    async fn reusable_http1_reader_waits_for_complete_chunk_trailers() {
        let (mut reader, mut writer) = tokio::io::duplex(1024);
        let mut read_task = tokio::spawn(async move {
            read_http1_response_message_capped_async(&mut reader, 1024).await
        });
        let response_prefix =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ndns\r\n0\r\n";
        writer.write_all(response_prefix).await.unwrap();

        assert!(
            time::timeout(CHUNKED_TRAILER_TEST_PENDING_WINDOW, &mut read_task)
                .await
                .is_err(),
            "reader returned before the chunked trailer section was terminated"
        );

        let trailers = b"X-Fixture: complete\r\n\r\n";
        writer.write_all(trailers).await.unwrap();
        let response = read_task.await.unwrap().unwrap();
        let mut expected = response_prefix.to_vec();
        expected.extend_from_slice(trailers);
        assert_eq!(response, expected);
    }
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
mod doh_limit_tests {
    use super::*;
    fn response(size: usize, chunked: bool) -> Vec<u8> {
        let mut raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nX-Padding: ".to_vec();
        raw.extend(vec![b'x'; 8192]);
        if chunked {
            raw.extend_from_slice(b"\r\nTransfer-Encoding: chunked\r\n\r\n");
            for n in [size / 2, size - size / 2] {
                raw.extend(format!("{n:x}\r\n").as_bytes());
                raw.extend(vec![0; n]);
                raw.extend_from_slice(b"\r\n");
            }
            raw.extend_from_slice(b"0\r\n\r\n");
        } else {
            raw.extend(format!("\r\nContent-Length: {size}\r\n\r\n").as_bytes());
            raw.extend(vec![0; size]);
        }
        raw
    }
    #[tokio::test]
    async fn doh_http1_limits_decoded_body_separately_from_headers_and_chunks() {
        for size in [65535, 65536] {
            for chunked in [false, true] {
                let raw = response(size, chunked);
                assert_eq!(
                    parse_doh_http_response(&[0x12, 0x34], &raw).is_ok(),
                    size == 65535
                );
                let mut source = raw.as_slice();
                assert_eq!(
                    read_http1_response_message_capped_async(&mut source, DNS_DOH_HTTP_READ_LIMIT)
                        .await
                        .is_ok(),
                    size == 65535
                );
                let mut source = raw.as_slice();
                assert_eq!(
                    read_doh_http1_close_response_async(&mut source)
                        .await
                        .is_ok(),
                    size == 65535
                );
            }
        }
        for headers in [
            "Content-Length: 65536",
            "Content-Length: 2\r\nContent-Length: 3",
            "Content-Length: 2\r\nTransfer-Encoding: chunked",
        ] {
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n{headers}\r\n\r\n"
            );
            let mut source = raw.as_bytes();
            assert!(
                read_doh_http1_close_response_async(&mut source)
                    .await
                    .is_err()
            );
        }
        let prefix = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n";
        let mut raw = prefix.to_vec();
        raw.extend(vec![0; 65536]);
        assert!(
            read_doh_http1_close_response_async(&mut raw.as_slice())
                .await
                .is_err()
        );
    }
}
