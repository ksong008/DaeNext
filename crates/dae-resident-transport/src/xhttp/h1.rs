// H1 xHTTP stream state stores mutually exclusive full clients or split halves inline.
#![allow(clippy::large_enum_variant)]

use super::request::{
    write_xhttp_h1_chunk, xhttp_h1_packet_up_request_bytes, xhttp_h1_request_bytes,
    xhttp_session_path_suffix,
};
use super::*;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub struct XhttpH1ChunkedWriter {
    writer: XhttpH1ChunkedWriterInner,
    finished: bool,
}

enum XhttpH1ChunkedWriterInner {
    Client(AsyncResidentTlsClient),
    WriteHalf(tokio::io::WriteHalf<AsyncResidentTlsClient>),
}

pub struct XhttpH1DownloadBody {
    reader: XhttpH1BodyReader,
    buffer: VecDeque<u8>,
    state: XhttpH1BodyState,
}

const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;

enum XhttpH1BodyReader {
    Client(AsyncResidentTlsClient),
    ReadHalf(tokio::io::ReadHalf<AsyncResidentTlsClient>),
}

#[derive(Debug)]
enum XhttpH1BodyState {
    ChunkSize,
    ChunkData(usize),
    ChunkCrlf,
    Trailer,
    Identity,
    Done,
}

pub async fn open_xhttp_h1_download_stream(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
    mptcp: bool,
    session_id: &str,
    separate_endpoint: bool,
) -> Result<XhttpH1DownloadBody, String> {
    let client = if separate_endpoint {
        open_async_xhttp_endpoint_tls_client(endpoint, binding.effective_socket_mark(), mptcp)
            .await?
    } else {
        open_async_resident_tls_client_with_binding(binding, mptcp).await?
    };
    open_xhttp_h1_download_stream_with_client(client, endpoint, session_id).await
}

async fn open_xhttp_h1_download_stream_with_client(
    mut client: AsyncResidentTlsClient,
    endpoint: &ResidentXhttpEndpointPlan,
    session_id: &str,
) -> Result<XhttpH1DownloadBody, String> {
    let request = xhttp_h1_request_bytes(
        http::Method::GET,
        endpoint,
        &xhttp_session_path_suffix(session_id, None),
        None,
    );
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.write_all(&request))
        .await
        .map_err(|_| "xHTTP HTTP/1.1 download request timeout".to_owned())?
        .map_err(|err| format!("write xHTTP HTTP/1.1 download request: {err}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.flush())
        .await
        .map_err(|_| "flush xHTTP HTTP/1.1 download request timeout".to_owned())?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 download request: {err}"))?;
    let response = read_xhttp_h1_response_head(&mut client, "download").await?;
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "xHTTP HTTP/1.1 download response status {}",
            response.status
        ));
    }
    Ok(XhttpH1DownloadBody::new(
        client,
        response.headers,
        response.body_prefix,
    ))
}

pub async fn begin_xhttp_h1_packet_up_request(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
    mptcp: bool,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<XhttpPacketUpCompletion, String> {
    let client = open_async_resident_tls_client_with_binding(binding, mptcp).await?;
    let request = xhttp_h1_packet_up_request_bytes(endpoint, session_id, seq, payload)?;
    begin_xhttp_h1_packet_up_request_on_client(client, request).await
}

async fn begin_xhttp_h1_packet_up_request_on_client<T>(
    mut client: T,
    request: Vec<u8>,
) -> Result<XhttpPacketUpCompletion, String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.write_all(&request))
        .await
        .map_err(|_| "xHTTP HTTP/1.1 packet-up request timeout".to_owned())?
        .map_err(|err| format!("write xHTTP HTTP/1.1 packet-up request: {err}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.flush())
        .await
        .map_err(|_| "flush xHTTP HTTP/1.1 packet-up request timeout".to_owned())?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 packet-up request: {err}"))?;
    Ok(Box::pin(async move {
        let response = read_xhttp_h1_response_head(&mut client, "packet-up").await?;
        if !(200..300).contains(&response.status) {
            return Err(format!(
                "xHTTP HTTP/1.1 packet-up response status {}",
                response.status
            ));
        }
        let _ = client.shutdown().await;
        Ok(())
    }))
}

pub struct XhttpH1ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_prefix: Vec<u8>,
}

pub async fn read_xhttp_h1_response_head<T>(
    client: &mut T,
    context: &str,
) -> Result<XhttpH1ResponseHead, String>
where
    T: AsyncRead + Unpin,
{
    const MAX_HEAD_BYTES: usize = 64 * 1024;
    let mut received = Vec::with_capacity(1024);
    let mut buf = [0_u8; 1024];
    loop {
        if let Some(end) = find_header_end(&received) {
            let body_prefix = received.split_off(end + 4);
            let head = &received[..end];
            return parse_xhttp_h1_response_head(head, body_prefix, context);
        }
        if received.len() >= MAX_HEAD_BYTES {
            return Err(format!(
                "xHTTP HTTP/1.1 {context} response headers exceed {MAX_HEAD_BYTES} bytes"
            ));
        }
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read(&mut buf))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} response headers timeout"))?
            .map_err(|err| format!("read xHTTP HTTP/1.1 {context} response headers: {err}"))?;
        if read == 0 {
            return Err(format!(
                "xHTTP HTTP/1.1 {context} response closed before headers"
            ));
        }
        received.extend_from_slice(&buf[..read]);
    }
}

fn parse_xhttp_h1_response_head(
    head: &[u8],
    body_prefix: Vec<u8>,
    context: &str,
) -> Result<XhttpH1ResponseHead, String> {
    let text = std::str::from_utf8(head)
        .map_err(|err| format!("xHTTP HTTP/1.1 {context} response headers utf8: {err}"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| format!("xHTTP HTTP/1.1 {context} response missing status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!(
            "xHTTP HTTP/1.1 {context} response has unsupported version {version}"
        ));
    }
    let status = status_parts
        .next()
        .ok_or_else(|| format!("xHTTP HTTP/1.1 {context} response missing status code"))?
        .parse::<u16>()
        .map_err(|err| format!("parse xHTTP HTTP/1.1 {context} response status: {err}"))?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<Vec<_>>();
    Ok(XhttpH1ResponseHead {
        status,
        headers,
        body_prefix,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

impl XhttpH1ChunkedWriter {
    pub fn from_client(client: AsyncResidentTlsClient) -> Self {
        Self {
            writer: XhttpH1ChunkedWriterInner::Client(client),
            finished: false,
        }
    }

    pub fn from_write_half(writer: tokio::io::WriteHalf<AsyncResidentTlsClient>) -> Self {
        Self {
            writer: XhttpH1ChunkedWriterInner::WriteHalf(writer),
            finished: false,
        }
    }

    pub async fn write_chunk(&mut self, payload: Bytes, end_stream: bool) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        match &mut self.writer {
            XhttpH1ChunkedWriterInner::Client(client) => {
                write_xhttp_h1_chunk(client, &payload, end_stream, "stream").await?;
            }
            XhttpH1ChunkedWriterInner::WriteHalf(writer) => {
                write_xhttp_h1_chunk(writer, &payload, end_stream, "stream").await?;
            }
        }
        self.finished = end_stream;
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        if let XhttpH1ChunkedWriterInner::Client(client) = &mut self.writer {
            let _ = client.shutdown().await;
        }
    }
}

impl XhttpH1DownloadBody {
    fn new(
        client: AsyncResidentTlsClient,
        headers: Vec<(String, String)>,
        body_prefix: Vec<u8>,
    ) -> Self {
        Self::new_with_reader(XhttpH1BodyReader::Client(client), headers, body_prefix)
    }

    pub fn new_with_read_half(
        reader: tokio::io::ReadHalf<AsyncResidentTlsClient>,
        headers: Vec<(String, String)>,
        body_prefix: Vec<u8>,
    ) -> Self {
        Self::new_with_reader(XhttpH1BodyReader::ReadHalf(reader), headers, body_prefix)
    }

    fn new_with_reader(
        reader: XhttpH1BodyReader,
        headers: Vec<(String, String)>,
        body_prefix: Vec<u8>,
    ) -> Self {
        let chunked = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        });
        Self {
            reader,
            buffer: VecDeque::from(body_prefix),
            state: if chunked {
                XhttpH1BodyState::ChunkSize
            } else {
                XhttpH1BodyState::Identity
            },
        }
    }

    pub async fn read_next(&mut self) -> Result<Option<Bytes>, String> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    pub async fn shutdown(&mut self) {
        if let XhttpH1BodyReader::Client(client) = &mut self.reader {
            let _ = client.shutdown().await;
        }
    }

    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, String>> {
        loop {
            match self.state {
                XhttpH1BodyState::ChunkSize => {
                    let Some(line) = self.pop_line()? else {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed before chunk size".to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    };
                    let size_text = line.split_once(';').map_or(line.as_str(), |(size, _)| size);
                    let size = usize::from_str_radix(size_text.trim(), 16)
                        .map_err(|err| format!("parse xHTTP HTTP/1.1 chunk size: {err}"))?;
                    self.state = if size == 0 {
                        XhttpH1BodyState::Trailer
                    } else {
                        XhttpH1BodyState::ChunkData(size)
                    };
                }
                XhttpH1BodyState::ChunkData(remaining) => {
                    if remaining == 0 {
                        self.state = XhttpH1BodyState::ChunkCrlf;
                        continue;
                    }
                    if self.buffer.is_empty() {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed inside chunk data".to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let take = remaining.min(self.buffer.len());
                    let bytes = self.drain_bytes(take);
                    self.state = XhttpH1BodyState::ChunkData(remaining - take);
                    if remaining == take {
                        self.state = XhttpH1BodyState::ChunkCrlf;
                    }
                    return Poll::Ready(Ok(Some(Bytes::from(bytes))));
                }
                XhttpH1BodyState::ChunkCrlf => {
                    if self.buffer.len() < 2 {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed before chunk CRLF".to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let cr = self.buffer.pop_front();
                    let lf = self.buffer.pop_front();
                    if cr != Some(b'\r') || lf != Some(b'\n') {
                        return Poll::Ready(Err(
                            "xHTTP HTTP/1.1 chunk data missing terminating CRLF".to_owned(),
                        ));
                    }
                    self.state = XhttpH1BodyState::ChunkSize;
                }
                XhttpH1BodyState::Trailer => {
                    let Some(line) = self.pop_line()? else {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed before chunk trailer"
                                        .to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    };
                    if line.is_empty() {
                        self.state = XhttpH1BodyState::Done;
                        return Poll::Ready(Ok(None));
                    }
                }
                XhttpH1BodyState::Identity => {
                    if !self.buffer.is_empty() {
                        let bytes = self.drain_bytes(self.buffer.len());
                        return Poll::Ready(Ok(Some(Bytes::from(bytes))));
                    }
                    match self.poll_fill(cx) {
                        Poll::Ready(Ok(0)) => {
                            self.state = XhttpH1BodyState::Done;
                            return Poll::Ready(Ok(None));
                        }
                        Poll::Ready(Ok(_)) => continue,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                XhttpH1BodyState::Done => return Poll::Ready(Ok(None)),
            }
        }
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, String>> {
        let line_state = matches!(
            self.state,
            XhttpH1BodyState::ChunkSize | XhttpH1BodyState::Trailer
        );
        let line_capacity = if line_state {
            if self.find_crlf().is_none() && self.buffer.len() > MAX_CHUNK_LINE_BYTES {
                return Poll::Ready(Err(format!(
                    "xHTTP HTTP/1.1 chunk line exceeds {MAX_CHUNK_LINE_BYTES} bytes"
                )));
            }
            Some(
                MAX_CHUNK_LINE_BYTES
                    .saturating_add(2)
                    .saturating_sub(self.buffer.len()),
            )
        } else {
            None
        };
        let mut scratch = [0_u8; 8192];
        let read_capacity =
            line_capacity.map_or(scratch.len(), |capacity| capacity.min(scratch.len()));
        if read_capacity == 0 {
            return Poll::Ready(Err(format!(
                "xHTTP HTTP/1.1 chunk line exceeds {MAX_CHUNK_LINE_BYTES} bytes"
            )));
        }
        let mut read_buf = ReadBuf::new(&mut scratch[..read_capacity]);
        let poll = match &mut self.reader {
            XhttpH1BodyReader::Client(client) => Pin::new(client).poll_read(cx, &mut read_buf),
            XhttpH1BodyReader::ReadHalf(reader) => Pin::new(reader).poll_read(cx, &mut read_buf),
        };
        match poll {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                let len = filled.len();
                self.buffer.extend(filled);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(err)) => {
                Poll::Ready(Err(format!("read xHTTP HTTP/1.1 download body: {err}")))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn pop_line(&mut self) -> Result<Option<String>, String> {
        let Some(index) = self.find_crlf() else {
            return Ok(None);
        };
        let line = self.drain_bytes(index);
        self.buffer.drain(..2);
        String::from_utf8(line)
            .map(Some)
            .map_err(|err| format!("xHTTP HTTP/1.1 chunk line utf8: {err}"))
    }

    fn find_crlf(&self) -> Option<usize> {
        self.buffer
            .iter()
            .zip(self.buffer.iter().skip(1))
            .position(|(left, right)| *left == b'\r' && *right == b'\n')
    }

    fn drain_bytes(&mut self, len: usize) -> Vec<u8> {
        self.buffer.drain(..len).collect()
    }
}

#[cfg(test)]
#[path = "h1/tests.rs"]
mod tests;
