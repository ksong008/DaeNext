use super::super::*;

mod chunked;
use self::chunked::{decode_http_chunked_body, decode_http_chunked_body_with_consumed};

pub(super) async fn open_dns_tcp_stream_async(
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

pub(super) async fn forward_dns_framed_stream_async<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_dns_tcp_message_async(stream, payload).await?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush DNS framed request: {err}"))?;
    read_dns_tcp_message_async(stream).await
}

pub(super) async fn write_dns_tcp_message_async<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS request exceeds TCP frame limit: {}", payload.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| format!("write DNS TCP frame length: {err}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| format!("write DNS TCP frame payload: {err}"))
}

pub(super) async fn read_dns_tcp_message_async<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|err| format!("read DNS TCP response length: {err}"))?;
    let len = u16::from_be_bytes(len) as usize;
    if len > DNS_TCP_MESSAGE_READ_LIMIT {
        return Err(format!("DNS TCP response length {len} exceeds read limit"));
    }
    let mut response = vec![0_u8; len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|err| format!("read DNS TCP response payload: {err}"))?;
    Ok(response)
}

pub(super) fn resident_dns_tls_client_config(alpn: &[&str]) -> Result<Arc<ClientConfig>, String> {
    let roots = dae_outbound::shared_transport::system_ca_snapshot()
        .map_err(|err| format!("load DNS system CA bundle: {err}"))?
        .rustls_roots();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

pub(super) fn resident_dns_quic_client_config(alpn: &str) -> Result<quinn::ClientConfig, String> {
    if cfg!(feature = "test-boringssl-quic") {
        let policy = dae_outbound::shared_transport::boring_quic::BoringQuicClientPolicy::new([
            alpn.as_bytes(),
        ])
        .map_err(|err| format!("build DNS BoringSSL QUIC policy: {err}"))?;
        return dae_outbound::shared_transport::boring_quic::build_boring_quic_client_config(
            &policy,
            Arc::new(quinn::TransportConfig::default()),
        )
        .map_err(|err| format!("build DNS BoringSSL QUIC client config: {err}"));
    }
    let roots = dae_outbound::shared_transport::system_ca_snapshot()
        .map_err(|err| format!("load DNS QUIC system CA bundle: {err}"))?
        .rustls_roots();
    let mut crypto = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| format!("build DNS QUIC client TLS config: {err}"))?,
    )))
}

pub(super) fn http1_doh_request_bytes(doh: &dae_dns::DohRequest, target: &str) -> Vec<u8> {
    http1_doh_request_bytes_with_connection(doh, target, HTTP_CONNECTION_CLOSE)
}

pub(super) fn http1_doh_keep_alive_request_bytes(
    doh: &dae_dns::DohRequest,
    target: &str,
) -> Vec<u8> {
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

pub(super) fn doh_request_target(path: &str, dns_query: Option<&str>) -> String {
    match dns_query {
        Some(query) if path.contains('?') => format!("{path}&dns={query}"),
        Some(query) => format!("{path}?dns={query}"),
        None => path.to_owned(),
    }
}

pub(super) async fn read_to_end_capped_async<S>(
    stream: &mut S,
    limit: usize,
) -> Result<Vec<u8>, String>
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

pub(super) async fn read_http1_response_message_capped_async<S>(
    stream: &mut S,
    limit: usize,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut raw = Vec::new();
    let mut buf = [0_u8; 8192];
    let header_end = loop {
        if let Some(header_end) = find_http_header_end(&raw) {
            break header_end;
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
            Err("HTTP response has no reusable body boundary".to_owned())
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
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("parse HTTP content-length: {err}"))?,
                );
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            _ => {}
        }
    }
    if chunked {
        Ok(Http1ResponseBodyBoundary::Chunked)
    } else if let Some(content_length) = content_length {
        Ok(Http1ResponseBodyBoundary::ContentLength(content_length))
    } else {
        Ok(Http1ResponseBodyBoundary::CloseDelimited)
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) fn parse_doh_http_response(
    request: &[u8],
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    let header_end = find_http_header_end(raw).ok_or("DoH response has no header end")?;
    let headers = &raw[..header_end];
    let mut body = raw[header_end + 4..].to_vec();
    let header_text = std::str::from_utf8(headers)
        .map_err(|err| format!("DoH response headers are not UTF-8: {err}"))?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| "DoH response has no status line".to_owned())?;
    let status_code = status
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("DoH response status line is malformed: {status}"))?
        .parse::<u16>()
        .map_err(|err| format!("parse DoH response status code: {err}"))?;
    let mut content_type = Vec::new();
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-type" => content_type = value.as_bytes().to_vec(),
            "content-length" => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("parse DoH content-length: {err}"))?,
                );
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => chunked = true,
            _ => {}
        }
    }
    validate_doh_response(status_code, status, &content_type).map_err(|err| err.to_string())?;
    if chunked {
        body = decode_http_chunked_body(&body)?;
    } else if let Some(len) = content_length {
        if body.len() < len {
            return Err(format!(
                "DoH response body shorter than content-length: {} < {len}",
                body.len()
            ));
        }
        body.truncate(len);
    }
    restore_dns_response_id(request, &body)
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

pub(super) fn restore_dns_response_id(request: &[u8], response: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() < 2 {
        return Err("DNS request is too short to restore response id".to_owned());
    }
    let request_id = u16::from_be_bytes([request[0], request[1]]);
    restore_packed_response_request_id(response, request_id)
        .ok_or_else(|| "DNS response is too short to restore request id".to_owned())
}

pub(super) fn dns_response_truncated(response: &[u8]) -> bool {
    response
        .get(2..4)
        .map(|flags| u16::from_be_bytes([flags[0], flags[1]]) & 0x0200 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
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
