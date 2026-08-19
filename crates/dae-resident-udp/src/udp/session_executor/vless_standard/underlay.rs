use super::*;
use dae_outbound::vless::VlessEncryptedStream;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

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
    EncryptedPlainTcp {
        stream: VlessEncryptedStream<tokio::net::TcpStream>,
    },
    EncryptedTlsTcp {
        client: VlessEncryptedStream<AsyncResidentTlsClient>,
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
    EncryptedWebSocketPlain {
        stream: VlessEncryptedStream<SpawnedLogicalStream>,
    },
    EncryptedWebSocketTls {
        stream: VlessEncryptedStream<SpawnedLogicalStream>,
        tls_underlay: &'static str,
    },
    HttpUpgradePlain {
        stream: Box<dyn AsyncReadWrite + Unpin + Send>,
    },
    HttpUpgradeTls {
        client: Box<dyn AsyncReadWrite + Unpin + Send>,
        tls_underlay: &'static str,
    },
    EncryptedHttpUpgradePlain {
        stream: VlessEncryptedStream<Box<dyn AsyncReadWrite + Unpin + Send>>,
    },
    EncryptedHttpUpgradeTls {
        client: VlessEncryptedStream<Box<dyn AsyncReadWrite + Unpin + Send>>,
        tls_underlay: &'static str,
    },
    GrpcTls {
        send_stream: h2::SendStream<Bytes>,
        response: GrpcH2Response,
        _carrier_lease: H2CarrierLease,
        response_buf: GrpcHunkReadBuffer,
        tls_underlay: &'static str,
    },
    EncryptedGrpcTls {
        stream: VlessEncryptedStream<SpawnedLogicalStream>,
        tls_underlay: &'static str,
    },
    H2Tls {
        send_stream: h2::SendStream<Bytes>,
        recv_stream: h2::RecvStream,
        _carrier_lease: H2CarrierLease,
        tls_underlay: &'static str,
    },
}

impl VlessStandardUdpUnderlay {
    pub(super) async fn open(
        wrapper: VlessStandardUdpWrapperKind,
        binding: &ResidentProxyBinding,
        initial_packet: &[u8],
    ) -> Result<Self, String> {
        let proxy = binding.plan();
        match wrapper {
            VlessStandardUdpWrapperKind::PlainTcp => {
                let mut stream = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
                if let Some(encryption) = proxy.vless_encryption()? {
                    let mut stream = VlessEncryptedStream::handshake(stream, encryption)
                        .await
                        .map_err(|err| format!("VLESS Encryption UDP handshake: {err}"))?;
                    write_vless_stream_bytes(
                        &mut stream,
                        initial_packet,
                        "write VLESS encrypted plain UDP-over-stream first packet",
                    )
                    .await?;
                    Ok(Self::EncryptedPlainTcp { stream })
                } else {
                    write_vless_stream_bytes(
                        &mut stream,
                        initial_packet,
                        "write VLESS plain UDP-over-stream first packet",
                    )
                    .await?;
                    Ok(Self::PlainTcp { stream })
                }
            }
            VlessStandardUdpWrapperKind::TlsTcp => {
                let mut client =
                    open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                if let Some(encryption) = proxy.vless_encryption()? {
                    let mut client = VlessEncryptedStream::handshake(client, encryption)
                        .await
                        .map_err(|err| format!("VLESS Encryption TLS UDP handshake: {err}"))?;
                    write_vless_stream_bytes(
                        &mut client,
                        initial_packet,
                        "write VLESS encrypted TLS UDP-over-stream first packet",
                    )
                    .await?;
                    Ok(Self::EncryptedTlsTcp {
                        client,
                        tls_underlay,
                    })
                } else {
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
            }
            VlessStandardUdpWrapperKind::WebSocketPlain => {
                let mut stream = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
                let ws_leftover = websocket_handshake_async(
                    &mut stream,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS WebSocket UDP",
                )
                .await?;
                if let Some(encryption) = proxy.vless_encryption()? {
                    let logical = spawn_websocket_payload_stream(stream, ws_leftover);
                    let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                        .await
                        .map_err(|err| {
                            format!("VLESS Encryption WebSocket UDP handshake: {err}")
                        })?;
                    write_vless_stream_bytes(
                        &mut encrypted,
                        initial_packet,
                        "write VLESS encrypted WebSocket UDP first packet",
                    )
                    .await?;
                    Ok(Self::EncryptedWebSocketPlain { stream: encrypted })
                } else {
                    let mut state = AsyncWebSocketPayloadState::default();
                    state.inject_leftover(ws_leftover)?;
                    write_vless_websocket_frame(
                        &mut stream,
                        initial_packet,
                        "write VLESS WebSocket UDP first packet",
                    )
                    .await?;
                    Ok(Self::WebSocketPlain { stream, state })
                }
            }
            VlessStandardUdpWrapperKind::WebSocketTls => {
                let mut client =
                    open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                let ws_leftover = websocket_handshake_async(
                    &mut client,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS TLS WebSocket UDP",
                )
                .await?;
                if let Some(encryption) = proxy.vless_encryption()? {
                    let logical = spawn_websocket_payload_stream(client, ws_leftover);
                    let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                        .await
                        .map_err(|err| {
                            format!("VLESS Encryption TLS WebSocket UDP handshake: {err}")
                        })?;
                    write_vless_stream_bytes(
                        &mut encrypted,
                        initial_packet,
                        "write VLESS encrypted TLS WebSocket UDP first packet",
                    )
                    .await?;
                    Ok(Self::EncryptedWebSocketTls {
                        stream: encrypted,
                        tls_underlay,
                    })
                } else {
                    let mut state = AsyncWebSocketPayloadState::default();
                    state.inject_leftover(ws_leftover)?;
                    write_vless_websocket_frame(
                        &mut client,
                        initial_packet,
                        "write VLESS TLS WebSocket UDP first packet",
                    )
                    .await?;
                    Ok(Self::WebSocketTls {
                        client,
                        state,
                        tls_underlay,
                    })
                }
            }
            VlessStandardUdpWrapperKind::HttpUpgradePlain => {
                let mut stream = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
                let leftover = httpupgrade_handshake_async(
                    &mut stream,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS HTTPUpgrade UDP",
                )
                .await?;
                let mut stream = AsyncPrefixedStream::new(leftover, stream);
                if let Some(encryption) = proxy.vless_encryption()? {
                    let mut encrypted = VlessEncryptedStream::handshake(
                        Box::new(stream) as Box<dyn AsyncReadWrite + Unpin + Send>,
                        encryption,
                    )
                    .await
                    .map_err(|err| format!("VLESS Encryption HTTPUpgrade UDP handshake: {err}"))?;
                    write_vless_stream_bytes(
                        &mut encrypted,
                        initial_packet,
                        "write VLESS encrypted HTTPUpgrade UDP first packet",
                    )
                    .await?;
                    Ok(Self::EncryptedHttpUpgradePlain { stream: encrypted })
                } else {
                    write_vless_stream_bytes(
                        &mut stream,
                        initial_packet,
                        "write VLESS HTTPUpgrade UDP first packet",
                    )
                    .await?;
                    Ok(Self::HttpUpgradePlain {
                        stream: Box::new(stream) as Box<dyn AsyncReadWrite + Unpin + Send>,
                    })
                }
            }
            VlessStandardUdpWrapperKind::HttpUpgradeTls => {
                let mut client =
                    open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                let leftover = httpupgrade_handshake_async(
                    &mut client,
                    &proxy.stream_host,
                    &proxy.stream_path,
                    "VLESS TLS HTTPUpgrade UDP",
                )
                .await?;
                let mut client = AsyncPrefixedStream::new(leftover, client);
                if let Some(encryption) = proxy.vless_encryption()? {
                    let mut encrypted = VlessEncryptedStream::handshake(
                        Box::new(client) as Box<dyn AsyncReadWrite + Unpin + Send>,
                        encryption,
                    )
                    .await
                    .map_err(|err| {
                        format!("VLESS Encryption TLS HTTPUpgrade UDP handshake: {err}")
                    })?;
                    write_vless_stream_bytes(
                        &mut encrypted,
                        initial_packet,
                        "write VLESS encrypted TLS HTTPUpgrade UDP first packet",
                    )
                    .await?;
                    Ok(Self::EncryptedHttpUpgradeTls {
                        client: encrypted,
                        tls_underlay,
                    })
                } else {
                    write_vless_stream_bytes(
                        &mut client,
                        initial_packet,
                        "write VLESS TLS HTTPUpgrade UDP first packet",
                    )
                    .await?;
                    Ok(Self::HttpUpgradeTls {
                        client: Box::new(client) as Box<dyn AsyncReadWrite + Unpin + Send>,
                        tls_underlay,
                    })
                }
            }
            VlessStandardUdpWrapperKind::GrpcTls => {
                let (send_stream, response, carrier_lease) = open_grpc_h2_stream(
                    binding,
                    if proxy.vless_encryption()?.is_some() {
                        &[]
                    } else {
                        initial_packet
                    },
                )
                .await?;
                let tls_underlay = carrier_lease.tls_underlay();
                if let Some(encryption) = proxy.vless_encryption()? {
                    let logical =
                        spawn_grpc_h2_payload_stream(send_stream, response, carrier_lease);
                    let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                        .await
                        .map_err(|err| format!("VLESS Encryption gRPC UDP handshake: {err}"))?;
                    write_vless_stream_bytes(
                        &mut encrypted,
                        initial_packet,
                        "write VLESS encrypted gRPC UDP first packet",
                    )
                    .await?;
                    Ok(Self::EncryptedGrpcTls {
                        stream: encrypted,
                        tls_underlay,
                    })
                } else {
                    let grpc_mode = response.grpc_mode();
                    Ok(Self::GrpcTls {
                        send_stream,
                        response,
                        _carrier_lease: carrier_lease,
                        response_buf: GrpcHunkReadBuffer::with_mode(grpc_mode),
                        tls_underlay,
                    })
                }
            }
            VlessStandardUdpWrapperKind::H2Tls => {
                let (send_stream, recv_stream, carrier_lease) =
                    open_h2_body_stream(binding, initial_packet, "VLESS H2 UDP").await?;
                let tls_underlay = carrier_lease.tls_underlay();
                Ok(Self::H2Tls {
                    send_stream,
                    recv_stream,
                    _carrier_lease: carrier_lease,
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
            Self::EncryptedPlainTcp { stream } => {
                write_vless_stream_bytes(
                    stream,
                    payload,
                    "write VLESS encrypted plain UDP-over-stream packet",
                )
                .await
            }
            Self::EncryptedTlsTcp { client, .. } => {
                write_vless_stream_bytes(
                    client,
                    payload,
                    "write VLESS encrypted TLS UDP-over-stream packet",
                )
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
            Self::EncryptedWebSocketPlain { stream } => {
                write_vless_stream_bytes(
                    stream,
                    payload,
                    "write VLESS encrypted WebSocket UDP packet",
                )
                .await
            }
            Self::EncryptedWebSocketTls { stream, .. } => {
                write_vless_stream_bytes(
                    stream,
                    payload,
                    "write VLESS encrypted TLS WebSocket UDP packet",
                )
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
            Self::EncryptedHttpUpgradePlain { stream } => {
                write_vless_stream_bytes(
                    stream,
                    payload,
                    "write VLESS encrypted HTTPUpgrade UDP packet",
                )
                .await
            }
            Self::EncryptedHttpUpgradeTls { client, .. } => {
                write_vless_stream_bytes(
                    client,
                    payload,
                    "write VLESS encrypted TLS HTTPUpgrade UDP packet",
                )
                .await
            }
            Self::GrpcTls {
                send_stream,
                response,
                ..
            } => send_grpc_data(send_stream, payload, false, response.grpc_mode()).await,
            Self::EncryptedGrpcTls { stream, .. } => {
                write_vless_stream_bytes(stream, payload, "write VLESS encrypted gRPC UDP packet")
                    .await
            }
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
            Self::EncryptedPlainTcp { .. } => (
                "tokio-encrypted-stream-session",
                "vless-encryption-tcp-stream-reused",
                None,
            ),
            Self::EncryptedTlsTcp { tls_underlay, .. } => (
                "tokio-encrypted-stream-session",
                "vless-encryption-tls-stream-reused",
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
            Self::EncryptedWebSocketPlain { .. } => (
                "tokio-encrypted-websocket-stream-session",
                "vless-encryption-websocket-tunnel-reused",
                None,
            ),
            Self::EncryptedWebSocketTls { tls_underlay, .. } => (
                "tokio-encrypted-websocket-stream-session",
                "vless-encryption-tls-websocket-tunnel-reused",
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
            Self::EncryptedHttpUpgradePlain { .. } => (
                "tokio-encrypted-httpupgrade-stream-session",
                "vless-encryption-httpupgrade-tunnel-reused",
                None,
            ),
            Self::EncryptedHttpUpgradeTls { tls_underlay, .. } => (
                "tokio-encrypted-httpupgrade-stream-session",
                "vless-encryption-tls-httpupgrade-tunnel-reused",
                Some(*tls_underlay),
            ),
            Self::GrpcTls { tls_underlay, .. } => (
                "tokio-h2-wrapper-stream-session",
                "tls-grpc-h2-stream-reused",
                Some(*tls_underlay),
            ),
            Self::EncryptedGrpcTls { tls_underlay, .. } => (
                "tokio-encrypted-grpc-h2-stream-session",
                "vless-encryption-tls-grpc-h2-stream-reused",
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
            Self::PlainTcp { stream } | Self::WebSocketPlain { stream, .. } => {
                let _ = stream.shutdown().await;
            }
            Self::HttpUpgradePlain { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::TlsTcp { client, .. } | Self::WebSocketTls { client, .. } => {
                client.shutdown().await;
            }
            Self::HttpUpgradeTls { client, .. } => {
                let _ = client.shutdown().await;
            }
            Self::EncryptedPlainTcp { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::EncryptedTlsTcp { client, .. } => {
                let _ = client.shutdown().await;
            }
            Self::EncryptedWebSocketPlain { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::EncryptedHttpUpgradePlain { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::EncryptedWebSocketTls { stream, .. } => {
                let _ = stream.shutdown().await;
            }
            Self::EncryptedGrpcTls { stream, .. } => {
                let _ = stream.shutdown().await;
            }
            Self::EncryptedHttpUpgradeTls { client, .. } => {
                let _ = client.shutdown().await;
            }
            Self::GrpcTls {
                send_stream,
                response,
                ..
            } => {
                let _ = send_grpc_data(send_stream, &[], true, response.grpc_mode()).await;
            }
            Self::H2Tls { send_stream, .. } => {
                let _ = send_h2_data_with_context(send_stream, Bytes::new(), true, "VLESS H2 UDP")
                    .await;
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
            VlessStandardUdpUnderlay::PlainTcp { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::HttpUpgradePlain { stream } => {
                Pin::new(stream.as_mut()).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::TlsTcp { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::HttpUpgradeTls { client, .. } => {
                Pin::new(client.as_mut()).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::EncryptedPlainTcp { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::EncryptedTlsTcp { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::EncryptedWebSocketPlain { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::EncryptedHttpUpgradePlain { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::EncryptedWebSocketTls { stream, .. } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::EncryptedHttpUpgradeTls { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::EncryptedGrpcTls { stream, .. } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
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
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let options = HttpUpgradeOptions::new(host, path);
    let handshake = websocket_client_handshake(&options)
        .map_err(|err| format!("build {label} handshake: {err}"))?;
    write_vless_stream_bytes(
        stream,
        &handshake.request,
        &format!("write {label} handshake"),
    )
    .await?;
    let (response, leftover) =
        read_http_head_from_async(stream, &format!("read {label} handshake")).await?;
    validate_websocket_handshake_response(&response, &handshake.expected_accept)
        .map_err(|err| format!("validate {label} upgrade: {err}"))?;
    Ok(leftover)
}

async fn httpupgrade_handshake_async<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    label: &str,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let options = HttpUpgradeOptions::new(host, path);
    let request =
        http_upgrade_request(&options).map_err(|err| format!("build {label} handshake: {err}"))?;
    write_vless_stream_bytes(stream, &request, &format!("write {label} handshake")).await?;
    let (response, leftover) =
        read_http_head_from_async(stream, &format!("read {label} handshake")).await?;
    validate_http_status(&response, 101)
        .map_err(|err| format!("validate {label} upgrade: {err}"))?;
    Ok(leftover)
}

pub(super) trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

async fn read_http_head_from_async<S>(
    stream: &mut S,
    label: &str,
) -> Result<(Vec<u8>, Vec<u8>), String>
where
    S: AsyncRead + Unpin,
{
    let response = read_http_head(
        stream,
        HttpHeadReadOptions {
            max_bytes: 16 * 1024,
            read_timeout: Some(RESIDENT_UDP_RESPONSE_TIMEOUT),
        },
    )
    .await
    .map_err(|error| format!("{label}: {error}"))?;
    Ok((response.head, response.leftover))
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

#[cfg(test)]
mod tests {
    use dae_outbound::shared_transport::websocket_accept_for_key;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn websocket_handshake_preserves_first_frame_from_response_read() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let request = read_http_head(
                &mut server,
                HttpHeadReadOptions {
                    max_bytes: 4096,
                    read_timeout: None,
                },
            )
            .await
            .unwrap();
            let request = std::str::from_utf8(&request.head).unwrap();
            let key = request
                .lines()
                .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap();
            let accept = websocket_accept_for_key(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            response.extend_from_slice(&[0x82, 5]);
            response.extend_from_slice(b"first");
            server.write_all(&response).await.unwrap();
        });

        let leftover = websocket_handshake_async(
            &mut client,
            "fixture.example",
            "/ws",
            "VLESS fixture WebSocket UDP",
        )
        .await
        .unwrap();
        server_task.await.unwrap();
        let mut state = AsyncWebSocketPayloadState::default();
        state.inject_leftover(leftover).unwrap();
        let mut reader = AsyncWebSocketPayloadReader::new(&mut client, &mut state);
        let mut payload = [0_u8; 5];
        reader.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"first");
    }

    #[tokio::test]
    async fn httpupgrade_handshake_preserves_first_tunnel_payload() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let _request = read_http_head(
                &mut server,
                HttpHeadReadOptions {
                    max_bytes: 4096,
                    read_timeout: None,
                },
            )
            .await
            .unwrap();
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nfirst")
                .await
                .unwrap();
        });

        let leftover = httpupgrade_handshake_async(
            &mut client,
            "fixture.example",
            "/upgrade",
            "VLESS fixture HTTPUpgrade UDP",
        )
        .await
        .unwrap();
        server_task.await.unwrap();
        let mut stream = AsyncPrefixedStream::new(leftover, client);
        let mut payload = [0_u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"first");
    }
}
