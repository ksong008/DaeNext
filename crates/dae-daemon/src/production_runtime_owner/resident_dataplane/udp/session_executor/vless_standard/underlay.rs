use super::*;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Clone, Copy)]
pub(super) enum VlessStandardUdpWrapperKind {
    PlainTcp,
    TlsTcp,
    WebSocketPlain,
    WebSocketTls,
    HttpUpgradePlain,
    HttpUpgradeTls,
    GrpcTls,
    H2Tls,
}

pub(super) enum VlessStandardUdpUnderlay {
    PlainTcp {
        stream: tokio::net::TcpStream,
    },
    TlsTcp {
        client: AsyncResidentTlsClient,
        tls_underlay: &'static str,
    },
    WebSocketPlain {
        stream: tokio::net::TcpStream,
        state: AsyncWebSocketPayloadState,
    },
    WebSocketTls {
        client: AsyncResidentTlsClient,
        state: AsyncWebSocketPayloadState,
        tls_underlay: &'static str,
    },
    HttpUpgradePlain {
        stream: tokio::net::TcpStream,
    },
    HttpUpgradeTls {
        client: AsyncResidentTlsClient,
        tls_underlay: &'static str,
    },
    GrpcTls {
        send_stream: h2::SendStream<Bytes>,
        response: GrpcH2Response,
        connection_task: tokio::task::JoinHandle<()>,
        response_buf: GrpcHunkReadBuffer,
        tls_underlay: &'static str,
    },
    H2Tls {
        send_stream: h2::SendStream<Bytes>,
        recv_stream: h2::RecvStream,
        connection_task: tokio::task::JoinHandle<()>,
        tls_underlay: &'static str,
    },
}

impl VlessStandardUdpUnderlay {
    pub(super) async fn open(
        wrapper: VlessStandardUdpWrapperKind,
        proxy: &ResidentProxyPlan,
        initial_packet: &[u8],
    ) -> Result<Self, String> {
        match wrapper {
            VlessStandardUdpWrapperKind::PlainTcp => {
                let mut stream = open_proxy_tcp_stream_async(proxy).await?;
                write_vless_stream_bytes(
                    &mut stream,
                    initial_packet,
                    "write VLESS plain UDP-over-stream first packet",
                )
                .await?;
                Ok(Self::PlainTcp { stream })
            }
            VlessStandardUdpWrapperKind::TlsTcp => {
                let mut client = open_async_resident_tls_client(proxy).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                write_vless_stream_bytes(
                    &mut client,
                    initial_packet,
                    "write VLESS TLS UDP-over-stream first packet",
                )
                .await?;
                Ok(Self::TlsTcp {
                    client,
                    tls_underlay,
                })
            }
            VlessStandardUdpWrapperKind::WebSocketPlain => {
                let mut stream = open_proxy_tcp_stream_async(proxy).await?;
                websocket_handshake_async(
                    &mut stream,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS WebSocket UDP",
                )
                .await?;
                write_vless_websocket_frame(
                    &mut stream,
                    initial_packet,
                    "write VLESS WebSocket UDP first packet",
                )
                .await?;
                Ok(Self::WebSocketPlain {
                    stream,
                    state: AsyncWebSocketPayloadState::default(),
                })
            }
            VlessStandardUdpWrapperKind::WebSocketTls => {
                let mut client = open_async_resident_tls_client(proxy).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                websocket_handshake_async(
                    &mut client,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS TLS WebSocket UDP",
                )
                .await?;
                write_vless_websocket_frame(
                    &mut client,
                    initial_packet,
                    "write VLESS TLS WebSocket UDP first packet",
                )
                .await?;
                Ok(Self::WebSocketTls {
                    client,
                    state: AsyncWebSocketPayloadState::default(),
                    tls_underlay,
                })
            }
            VlessStandardUdpWrapperKind::HttpUpgradePlain => {
                let mut stream = open_proxy_tcp_stream_async(proxy).await?;
                httpupgrade_handshake_async(
                    &mut stream,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS HTTPUpgrade UDP",
                )
                .await?;
                write_vless_stream_bytes(
                    &mut stream,
                    initial_packet,
                    "write VLESS HTTPUpgrade UDP first packet",
                )
                .await?;
                Ok(Self::HttpUpgradePlain { stream })
            }
            VlessStandardUdpWrapperKind::HttpUpgradeTls => {
                let mut client = open_async_resident_tls_client(proxy).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                httpupgrade_handshake_async(
                    &mut client,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS TLS HTTPUpgrade UDP",
                )
                .await?;
                write_vless_stream_bytes(
                    &mut client,
                    initial_packet,
                    "write VLESS TLS HTTPUpgrade UDP first packet",
                )
                .await?;
                Ok(Self::HttpUpgradeTls {
                    client,
                    tls_underlay,
                })
            }
            VlessStandardUdpWrapperKind::GrpcTls => {
                let client = open_async_resident_tls_client(proxy).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                let (send_stream, response, connection_task) =
                    open_grpc_h2_stream(client, proxy, initial_packet).await?;
                Ok(Self::GrpcTls {
                    send_stream,
                    response,
                    connection_task,
                    response_buf: GrpcHunkReadBuffer::default(),
                    tls_underlay,
                })
            }
            VlessStandardUdpWrapperKind::H2Tls => {
                let client = open_async_resident_tls_client(proxy).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                let (send_stream, recv_stream, connection_task) =
                    open_h2_body_stream(client, proxy, initial_packet, "VLESS H2 UDP").await?;
                Ok(Self::H2Tls {
                    send_stream,
                    recv_stream,
                    connection_task,
                    tls_underlay,
                })
            }
        }
    }

    pub(super) async fn write_packet(&mut self, payload: &[u8]) -> Result<(), String> {
        match self {
            Self::PlainTcp { stream } => {
                write_vless_stream_bytes(
                    stream,
                    payload,
                    "write VLESS plain UDP-over-stream packet",
                )
                .await
            }
            Self::TlsTcp { client, .. } => {
                write_vless_stream_bytes(client, payload, "write VLESS TLS UDP-over-stream packet")
                    .await
            }
            Self::WebSocketPlain { stream, .. } => {
                write_vless_websocket_frame(stream, payload, "write VLESS WebSocket UDP packet")
                    .await
            }
            Self::WebSocketTls { client, .. } => {
                write_vless_websocket_frame(client, payload, "write VLESS TLS WebSocket UDP packet")
                    .await
            }
            Self::HttpUpgradePlain { stream } => {
                write_vless_stream_bytes(stream, payload, "write VLESS HTTPUpgrade UDP packet")
                    .await
            }
            Self::HttpUpgradeTls { client, .. } => {
                write_vless_stream_bytes(client, payload, "write VLESS TLS HTTPUpgrade UDP packet")
                    .await
            }
            Self::GrpcTls { send_stream, .. } => send_grpc_hunk(send_stream, payload, false).await,
            Self::H2Tls { send_stream, .. } => {
                send_h2_data_with_context(
                    send_stream,
                    Bytes::copy_from_slice(payload),
                    false,
                    "VLESS H2 UDP",
                )
                .await
            }
        }
    }

    pub(super) async fn poll_response_chunk(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.read_response_chunk(UdpStreamReadMode::ReadyOnly).await
    }

    pub(super) async fn wait_response_chunk(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.read_response_chunk(UdpStreamReadMode::Wait).await
    }

    async fn read_response_chunk(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::GrpcTls { .. } => read_vless_grpc_payload(self, mode).await,
            Self::H2Tls { recv_stream, .. } => read_vless_h2_payload(recv_stream, mode).await,
            _ => read_vless_standard_stream_underlay(self, mode).await,
        }
    }

    pub(super) fn evidence_fields(&self) -> (&'static str, &'static str, Option<&'static str>) {
        match self {
            Self::PlainTcp { .. } => ("tokio-stream-session", "tcp-stream-reused", None),
            Self::TlsTcp { tls_underlay, .. } => (
                "tokio-stream-session",
                "tls-tcp-stream-reused",
                Some(*tls_underlay),
            ),
            Self::WebSocketPlain { .. } => (
                "tokio-wrapper-stream-session",
                "websocket-tunnel-reused",
                None,
            ),
            Self::WebSocketTls { tls_underlay, .. } => (
                "tokio-wrapper-stream-session",
                "tls-websocket-tunnel-reused",
                Some(*tls_underlay),
            ),
            Self::HttpUpgradePlain { .. } => (
                "tokio-wrapper-stream-session",
                "httpupgrade-tunnel-reused",
                None,
            ),
            Self::HttpUpgradeTls { tls_underlay, .. } => (
                "tokio-wrapper-stream-session",
                "tls-httpupgrade-tunnel-reused",
                Some(*tls_underlay),
            ),
            Self::GrpcTls { tls_underlay, .. } => (
                "tokio-h2-wrapper-stream-session",
                "tls-grpc-h2-stream-reused",
                Some(*tls_underlay),
            ),
            Self::H2Tls { tls_underlay, .. } => (
                "tokio-h2-wrapper-stream-session",
                "tls-h2-stream-reused",
                Some(*tls_underlay),
            ),
        }
    }

    pub(super) async fn shutdown(&mut self) {
        match self {
            Self::PlainTcp { stream }
            | Self::WebSocketPlain { stream, .. }
            | Self::HttpUpgradePlain { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::TlsTcp { client, .. }
            | Self::WebSocketTls { client, .. }
            | Self::HttpUpgradeTls { client, .. } => {
                client.shutdown().await;
            }
            Self::GrpcTls {
                send_stream,
                connection_task,
                ..
            } => {
                let _ = send_grpc_hunk(send_stream, &[], true).await;
                connection_task.abort();
            }
            Self::H2Tls {
                send_stream,
                connection_task,
                ..
            } => {
                let _ = send_h2_data_with_context(send_stream, Bytes::new(), true, "VLESS H2 UDP")
                    .await;
                connection_task.abort();
            }
        }
    }
}

async fn read_vless_standard_stream_underlay(
    underlay: &mut VlessStandardUdpUnderlay,
    mode: UdpStreamReadMode,
) -> Result<Option<Vec<u8>>, String> {
    let mut out = [0_u8; 8192];
    let mut read_buf = ReadBuf::new(&mut out);
    poll_fn(|cx| {
        let poll_result = match underlay {
            VlessStandardUdpUnderlay::PlainTcp { stream }
            | VlessStandardUdpUnderlay::HttpUpgradePlain { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::TlsTcp { client, .. }
            | VlessStandardUdpUnderlay::HttpUpgradeTls { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::WebSocketPlain { stream, state } => {
                let mut reader = AsyncWebSocketPayloadReader::new(stream, state);
                Pin::new(&mut reader).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::WebSocketTls { client, state, .. } => {
                let mut reader = AsyncWebSocketPayloadReader::new(client, state);
                Pin::new(&mut reader).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::GrpcTls { .. } | VlessStandardUdpUnderlay::H2Tls { .. } => {
                return Poll::Ready(Err(
                    "VLESS HTTP/2 UDP responses use HTTP/2 data polling".to_owned()
                ));
            }
        };
        map_udp_stream_read_poll(
            mode,
            poll_result,
            read_buf.filled().len(),
            "read VLESS standard UDP underlay",
        )
    })
    .await
    .map(|read| read.map(|read| out[..read].to_vec()))
}

async fn read_vless_grpc_payload(
    underlay: &mut VlessStandardUdpUnderlay,
    mode: UdpStreamReadMode,
) -> Result<Option<Vec<u8>>, String> {
    let VlessStandardUdpUnderlay::GrpcTls {
        response,
        response_buf,
        ..
    } = underlay
    else {
        return Err("VLESS gRPC payload reader received non-gRPC underlay".to_owned());
    };
    loop {
        if let Some(payload) = response_buf.pop_payload()? {
            if payload.is_empty() {
                continue;
            }
            return Ok(Some(payload));
        }
        let data = if mode.waits_for_readiness() {
            Some(response.next_data().await)
        } else {
            poll_future_once(response.next_data()).await
        };
        match data {
            Some(Ok(Some(bytes))) => {
                response_buf.extend_from_slice(&bytes);
            }
            Some(Err(err)) => return Err(err),
            Some(Ok(None)) => return Err("VLESS gRPC response stream closed".to_owned()),
            None => return Ok(None),
        }
    }
}

async fn read_vless_h2_payload(
    recv_stream: &mut h2::RecvStream,
    mode: UdpStreamReadMode,
) -> Result<Option<Vec<u8>>, String> {
    let data = if mode.waits_for_readiness() {
        Some(recv_stream.data().await)
    } else {
        poll_future_once(recv_stream.data()).await
    };
    match data {
        Some(Some(Ok(bytes))) => {
            recv_stream
                .flow_control()
                .release_capacity(bytes.len())
                .map_err(|err| format!("release VLESS H2 UDP response capacity: {err}"))?;
            Ok((!bytes.is_empty()).then(|| bytes.to_vec()))
        }
        Some(Some(Err(err))) => Err(format!("read VLESS H2 UDP response data: {err}")),
        Some(None) => Err("VLESS H2 UDP response stream closed".to_owned()),
        None => Ok(None),
    }
}

async fn websocket_handshake_async<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    label: &str,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let options = HttpUpgradeOptions::new(host, path);
    let request = websocket_client_handshake_request(&options);
    write_vless_stream_bytes(stream, &request, &format!("write {label} handshake")).await?;
    let response = read_http_head_from_async(stream, &format!("read {label} handshake")).await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate {label} upgrade: {err}"))
}

async fn httpupgrade_handshake_async<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    label: &str,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let options = HttpUpgradeOptions::new(host, path);
    let request = http_upgrade_request(&options);
    write_vless_stream_bytes(stream, &request, &format!("write {label} handshake")).await?;
    let response = read_http_head_from_async(stream, &format!("read {label} handshake")).await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate {label} upgrade: {err}"))
}

async fn read_http_head_from_async<S>(stream: &mut S, label: &str) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, stream.read(&mut buf))
            .await
            .map_err(|_| format!("{label}: timeout"))?
            .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
        if response.len() > 16 * 1024 {
            return Err(format!("{label}: response head too large"));
        }
    }
}

async fn write_vless_websocket_frame<S>(
    stream: &mut S,
    payload: &[u8],
    label: &str,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let frame = websocket_client_binary_frame_with_random_mask(payload)
        .map_err(|err| format!("{label}: {err}"))?;
    write_vless_stream_bytes(stream, &frame, label).await
}

async fn write_vless_stream_bytes<S>(
    stream: &mut S,
    payload: &[u8],
    label: &str,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        stream
            .write_all(payload)
            .await
            .map_err(|err| format!("{label}: {err}"))?;
        stream
            .flush()
            .await
            .map_err(|err| format!("flush {label}: {err}"))
    })
    .await
    .map_err(|_| format!("{label} timeout"))?
}
