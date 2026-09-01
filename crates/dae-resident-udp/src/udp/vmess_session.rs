use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::*;

#[derive(Clone, Copy)]
pub(super) enum VmessAeadUdpWrapperKind {
    PlainTcp,
    TlsTcp,
    TcpHttpHeaderPlain,
    TcpHttpHeaderTls,
    WebSocketPlain,
    WebSocketTls,
    HttpUpgradePlain,
    HttpUpgradeTls,
    GrpcTls,
}

pub(super) struct VmessAeadUdpOverTcpSession {
    id: String,
    body_security: vmess::VMessBodySecurity,
    wrapper: VmessAeadUdpWrapperKind,
    underlay: Option<VmessAeadUdpUnderlay>,
    upload: Option<vmess::VMessAeadTcpUploadCodec>,
    upload_buffer: Vec<u8>,
    upload_payload_offset: usize,
    request: Option<vmess::VMessAeadTcpRequest>,
    response: Option<vmess::VMessAeadTcpResponseReader>,
    response_plaintext: Vec<u8>,
    response_plaintext_cursor: usize,
    response_read_buffer: Vec<u8>,
    fixed_target: UdpSessionFixedTarget,
}

impl VmessAeadUdpOverTcpSession {
    pub(super) fn plain(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::PlainTcp)
    }

    pub(super) fn tls(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::TlsTcp)
    }

    pub(super) fn tcp_http_header_plain(
        id: String,
        body_security: vmess::VMessBodySecurity,
    ) -> Self {
        Self::new(
            id,
            body_security,
            VmessAeadUdpWrapperKind::TcpHttpHeaderPlain,
        )
    }

    pub(super) fn tcp_http_header_tls(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::TcpHttpHeaderTls)
    }

    pub(super) fn websocket_plain(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::WebSocketPlain)
    }

    pub(super) fn websocket_tls(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::WebSocketTls)
    }

    pub(super) fn httpupgrade_plain(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::HttpUpgradePlain)
    }

    pub(super) fn httpupgrade_tls(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::HttpUpgradeTls)
    }

    pub(super) fn grpc_tls(id: String, body_security: vmess::VMessBodySecurity) -> Self {
        Self::new(id, body_security, VmessAeadUdpWrapperKind::GrpcTls)
    }

    fn new(
        id: String,
        body_security: vmess::VMessBodySecurity,
        wrapper: VmessAeadUdpWrapperKind,
    ) -> Self {
        Self {
            id,
            body_security,
            wrapper,
            underlay: None,
            upload: None,
            upload_buffer: Vec::new(),
            upload_payload_offset: 0,
            request: None,
            response: None,
            response_plaintext: Vec::new(),
            response_plaintext_cursor: 0,
            response_read_buffer: Vec::new(),
            fixed_target: UdpSessionFixedTarget::default(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.fixed_target
            .bind(original_dst, "VMess AEAD UDP-over-TCP session")?;
        let result = if self.underlay.is_some() {
            self.exchange_next(payload).await
        } else {
            self.exchange_first(binding, original_dst, payload).await
        };
        if result.is_err() {
            self.shutdown().await;
        }
        result
    }

    async fn exchange_first(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        let start = vmess::aead_udp_over_tcp_client_session_start_with_security(
            &self.id,
            &original_dst.to_string(),
            payload,
            self.body_security,
        )
        .map_err(|err| format!("start VMess AEAD UDP-over-TCP session: {err}"))?;
        let mut underlay = open_vmess_underlay(self.wrapper, binding, &start.first_write).await?;
        if underlay.is_grpc() {
            start_vmess_grpc_response_reader(&mut underlay, start.request.clone())?;
        } else {
            self.response = None;
            self.response_plaintext.clear();
            self.response_plaintext_cursor = 0;
        }
        self.upload_buffer = start.upload.new_owned_chunk_buffer(0);
        self.upload_payload_offset = self.upload_buffer.len();
        self.underlay = Some(underlay);
        self.upload = Some(start.upload);
        self.request = Some(start.request);
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    async fn exchange_next(&mut self, payload: &[u8]) -> Result<UdpExchangeResult, String> {
        self.upload_buffer.truncate(self.upload_payload_offset);
        self.upload_buffer.extend_from_slice(payload);
        let chunk_len = self
            .upload
            .as_mut()
            .ok_or_else(|| "VMess AEAD UDP-over-TCP upload codec is not initialized".to_owned())?
            .seal_owned_chunk_in_place(&mut self.upload_buffer, 0, payload.len())
            .map_err(|err| format!("seal VMess AEAD UDP-over-TCP session packet: {err}"))?;
        {
            let underlay = self
                .underlay
                .as_mut()
                .ok_or_else(|| "VMess AEAD UDP-over-TCP underlay is not initialized".to_owned())?;
            write_vmess_wrapped_bytes(underlay, &self.upload_buffer[..chunk_len]).await?;
        }
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::ReadyOnly).await
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::Wait).await
    }

    async fn read_response(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        if self.underlay.is_none() && mode.waits_for_readiness() {
            return std::future::pending().await;
        }
        let Some(underlay) = self.underlay.as_mut() else {
            return Ok(None);
        };
        if underlay.is_grpc() {
            return read_vmess_grpc_payload(underlay, mode)
                .await
                .map(|payload| payload.map(|payload| self.response_result(payload)));
        }
        self.response_read_buffer.resize(8192, 0);
        let read_buffer = &mut self.response_read_buffer;
        let Some(read) = read_vmess_underlay_plaintext(underlay, read_buffer, mode).await? else {
            return Ok(None);
        };
        compact_vmess_response_buffer(
            &mut self.response_plaintext,
            &mut self.response_plaintext_cursor,
        );
        self.response_plaintext
            .extend_from_slice(&read_buffer[..read]);
        self.try_pop_response_payload()
            .map(|payload| payload.map(|payload| self.response_result(payload)))
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.response.is_none() {
            let Some(request) = self.request.as_ref() else {
                return Ok(None);
            };
            match vmess::aead_tcp_response_reader_from_buffer(&mut self.response_plaintext, request)
                .map_err(|err| format!("read VMess wrapped UDP response header: {err}"))?
            {
                Some(response) => self.response = Some(response),
                None => return Ok(None),
            }
        }
        let response = self.response.as_mut().ok_or_else(|| {
            "VMess AEAD UDP-over-TCP response reader is not initialized".to_owned()
        })?;
        let payload = response
            .try_read_chunk_in_place_from_buffer(
                &mut self.response_plaintext,
                &mut self.response_plaintext_cursor,
            )
            .map(|payload| payload.map(<[u8]>::to_vec))
            .map_err(|err| format!("read VMess wrapped UDP session packet: {err}"))?;
        compact_vmess_response_buffer(
            &mut self.response_plaintext,
            &mut self.response_plaintext_cursor,
        );
        Ok(payload)
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        let (session_executor, underlay_reuse, tls_underlay) = self
            .underlay
            .as_ref()
            .map(VmessAeadUdpUnderlay::evidence_fields)
            .unwrap_or(("tokio-stream-session", "stream-reused", None));
        vmess_udp_session_result(
            payload,
            session_executor,
            underlay_reuse,
            tls_underlay,
            self.fixed_target,
        )
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        let (session_executor, underlay_reuse, tls_underlay) = self
            .underlay
            .as_ref()
            .map(VmessAeadUdpUnderlay::evidence_fields)
            .unwrap_or(("tokio-stream-session", "stream-reused", None));
        vmess_udp_pending_session_result(session_executor, underlay_reuse, tls_underlay)
    }
}

async fn open_vmess_underlay(
    wrapper: VmessAeadUdpWrapperKind,
    binding: &ResidentProxyBinding,
    first_write: &[u8],
) -> Result<VmessAeadUdpUnderlay, String> {
    let proxy = binding.plan();
    match wrapper {
        VmessAeadUdpWrapperKind::PlainTcp => {
            let mut stream = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
            write_vmess_stream_bytes(
                &mut stream,
                first_write,
                "write VMess AEAD UDP-over-TCP session first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::PlainTcp { stream })
        }
        VmessAeadUdpWrapperKind::TlsTcp => {
            let mut client =
                open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
            let tls_underlay = async_resident_tls_underlay_name(&client);
            write_vmess_stream_bytes(
                &mut client,
                first_write,
                "write VMess TLS AEAD UDP-over-TCP session first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::TlsTcp {
                client,
                tls_underlay,
            })
        }
        VmessAeadUdpWrapperKind::TcpHttpHeaderPlain => {
            let stream = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
            let mut stream =
                open_vmess_http_header_stream(stream, &proxy.stream_host, &proxy.stream_path)
                    .await?;
            write_vmess_stream_bytes(
                &mut stream,
                first_write,
                "write VMess TCP HTTP header UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::TcpHttpHeaderPlain { stream })
        }
        VmessAeadUdpWrapperKind::TcpHttpHeaderTls => {
            let client = open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
            let tls_underlay = async_resident_tls_underlay_name(&client);
            let mut client =
                open_vmess_http_header_stream(client, &proxy.stream_host, &proxy.stream_path)
                    .await?;
            write_vmess_stream_bytes(
                &mut client,
                first_write,
                "write VMess TLS TCP HTTP header UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::TcpHttpHeaderTls {
                client,
                tls_underlay,
            })
        }
        VmessAeadUdpWrapperKind::WebSocketPlain => {
            let mut stream = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
            let leftover = websocket_handshake_async(
                &mut stream,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess WebSocket UDP",
            )
            .await?;
            let mut state = AsyncWebSocketPayloadState::default();
            state.inject_leftover(leftover)?;
            write_vmess_websocket_frame(
                &mut stream,
                first_write,
                "write VMess WebSocket UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::WebSocketPlain { stream, state })
        }
        VmessAeadUdpWrapperKind::WebSocketTls => {
            let mut client =
                open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
            let tls_underlay = async_resident_tls_underlay_name(&client);
            let leftover = websocket_handshake_async(
                &mut client,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess TLS WebSocket UDP",
            )
            .await?;
            let mut state = AsyncWebSocketPayloadState::default();
            state.inject_leftover(leftover)?;
            write_vmess_websocket_frame(
                &mut client,
                first_write,
                "write VMess TLS WebSocket UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::WebSocketTls {
                client,
                state,
                tls_underlay,
            })
        }
        VmessAeadUdpWrapperKind::HttpUpgradePlain => {
            let mut stream = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
            let leftover = httpupgrade_handshake_async(
                &mut stream,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess HTTPUpgrade UDP",
            )
            .await?;
            let mut stream = AsyncPrefixedStream::new(leftover, stream);
            write_vmess_stream_bytes(
                &mut stream,
                first_write,
                "write VMess HTTPUpgrade UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::HttpUpgradePlain { stream })
        }
        VmessAeadUdpWrapperKind::HttpUpgradeTls => {
            let mut client =
                open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
            let tls_underlay = async_resident_tls_underlay_name(&client);
            let leftover = httpupgrade_handshake_async(
                &mut client,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess TLS HTTPUpgrade UDP",
            )
            .await?;
            let mut client = AsyncPrefixedStream::new(leftover, client);
            write_vmess_stream_bytes(
                &mut client,
                first_write,
                "write VMess TLS HTTPUpgrade UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::HttpUpgradeTls {
                client,
                tls_underlay,
            })
        }
        VmessAeadUdpWrapperKind::GrpcTls => {
            let (send_stream, response, carrier_lease) =
                open_grpc_h2_stream(binding, first_write).await?;
            let tls_underlay = carrier_lease.tls_underlay();
            let grpc_mode = response.grpc_mode();
            Ok(VmessAeadUdpUnderlay::GrpcTls {
                send_stream,
                grpc_mode,
                response: Some(response),
                _carrier_lease: carrier_lease,
                response_rx: None,
                response_reader: None,
                tls_underlay,
            })
        }
    }
}

impl VmessAeadUdpOverTcpSession {
    pub(super) async fn shutdown(&mut self) {
        self.upload = None;
        self.upload_buffer.clear();
        self.upload_payload_offset = 0;
        self.request = None;
        self.response = None;
        self.response_plaintext.clear();
        self.response_plaintext_cursor = 0;
        if let Some(mut underlay) = self.underlay.take() {
            underlay.shutdown().await;
        }
        self.fixed_target.clear();
    }
}

async fn read_vmess_underlay_plaintext(
    underlay: &mut VmessAeadUdpUnderlay,
    out: &mut [u8],
    mode: UdpStreamReadMode,
) -> Result<Option<usize>, String> {
    let mut read_buf = ReadBuf::new(out);
    poll_fn(|cx| {
        let poll_result = match underlay {
            VmessAeadUdpUnderlay::PlainTcp { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::HttpUpgradePlain { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::TlsTcp { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::HttpUpgradeTls { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::TcpHttpHeaderPlain { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::TcpHttpHeaderTls { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::WebSocketPlain { stream, state } => {
                let mut reader = AsyncWebSocketPayloadReader::new(stream, state);
                Pin::new(&mut reader).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::WebSocketTls { client, state, .. } => {
                let mut reader = AsyncWebSocketPayloadReader::new(client, state);
                Pin::new(&mut reader).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::GrpcTls { .. } => {
                return Poll::Ready(Err(
                    "VMess gRPC UDP responses use the hunk decoder".to_owned()
                ));
            }
        };
        map_udp_stream_read_poll(
            mode,
            poll_result,
            read_buf.filled().len(),
            "read VMess UDP underlay",
        )
    })
    .await
}

enum VmessAeadUdpUnderlay {
    PlainTcp {
        stream: tokio::net::TcpStream,
    },
    TlsTcp {
        client: AsyncResidentTlsClient,
        tls_underlay: &'static str,
    },
    TcpHttpHeaderPlain {
        stream: VmessHttpHeaderStream<tokio::net::TcpStream>,
    },
    TcpHttpHeaderTls {
        client: VmessHttpHeaderStream<AsyncResidentTlsClient>,
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
        stream: AsyncPrefixedStream<tokio::net::TcpStream>,
    },
    HttpUpgradeTls {
        client: AsyncPrefixedStream<AsyncResidentTlsClient>,
        tls_underlay: &'static str,
    },
    GrpcTls {
        send_stream: h2::SendStream<Bytes>,
        grpc_mode: GrpcMode,
        response: Option<GrpcH2Response>,
        _carrier_lease: H2CarrierLease,
        response_rx: Option<tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>>,
        response_reader: Option<tokio::task::JoinHandle<()>>,
        tls_underlay: &'static str,
    },
}

impl VmessAeadUdpUnderlay {
    fn is_grpc(&self) -> bool {
        matches!(self, Self::GrpcTls { .. })
    }

    fn evidence_fields(&self) -> (&'static str, &'static str, Option<&'static str>) {
        match self {
            Self::PlainTcp { .. } => ("tokio-stream-session", "tcp-stream-reused", None),
            Self::TlsTcp { tls_underlay, .. } => (
                "tokio-stream-session",
                "tls-tcp-stream-reused",
                Some(*tls_underlay),
            ),
            Self::TcpHttpHeaderPlain { .. } => (
                "tokio-wrapper-stream-session",
                "tcp-http-header-tunnel-reused",
                None,
            ),
            Self::TcpHttpHeaderTls { tls_underlay, .. } => (
                "tokio-wrapper-stream-session",
                "tls-tcp-http-header-tunnel-reused",
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
        }
    }

    async fn shutdown(&mut self) {
        match self {
            Self::PlainTcp { stream } | Self::WebSocketPlain { stream, .. } => {
                let _ = stream.shutdown().await;
            }
            Self::HttpUpgradePlain { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::TcpHttpHeaderPlain { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::TlsTcp { client, .. } | Self::WebSocketTls { client, .. } => {
                client.shutdown().await;
            }
            Self::HttpUpgradeTls { client, .. } => {
                let _ = client.shutdown().await;
            }
            Self::TcpHttpHeaderTls { client, .. } => {
                let _ = client.shutdown().await;
            }
            Self::GrpcTls {
                send_stream,
                grpc_mode,
                response_rx,
                response_reader,
                ..
            } => {
                let _ = send_grpc_data(send_stream, &[], true, *grpc_mode).await;
                response_rx.take();
                if let Some(reader) = response_reader.take() {
                    reader.abort();
                    let _ = reader.await;
                }
            }
        }
    }
}

async fn write_vmess_wrapped_bytes(
    underlay: &mut VmessAeadUdpUnderlay,
    payload: &[u8],
) -> Result<(), String> {
    match underlay {
        VmessAeadUdpUnderlay::PlainTcp { stream } => {
            write_vmess_stream_bytes(stream, payload, "write VMess wrapped UDP session packet")
                .await
        }
        VmessAeadUdpUnderlay::HttpUpgradePlain { stream } => {
            write_vmess_stream_bytes(stream, payload, "write VMess wrapped UDP session packet")
                .await
        }
        VmessAeadUdpUnderlay::TlsTcp { client, .. } => {
            write_vmess_stream_bytes(
                client,
                payload,
                "write VMess TLS wrapped UDP session packet",
            )
            .await
        }
        VmessAeadUdpUnderlay::HttpUpgradeTls { client, .. } => {
            write_vmess_stream_bytes(
                client,
                payload,
                "write VMess TLS wrapped UDP session packet",
            )
            .await
        }
        VmessAeadUdpUnderlay::TcpHttpHeaderPlain { stream } => {
            write_vmess_stream_bytes(
                stream,
                payload,
                "write VMess TCP HTTP header UDP session packet",
            )
            .await
        }
        VmessAeadUdpUnderlay::TcpHttpHeaderTls { client, .. } => {
            write_vmess_stream_bytes(
                client,
                payload,
                "write VMess TLS TCP HTTP header UDP session packet",
            )
            .await
        }
        VmessAeadUdpUnderlay::WebSocketPlain { stream, .. } => {
            write_vmess_websocket_frame(stream, payload, "write VMess WebSocket UDP session packet")
                .await
        }
        VmessAeadUdpUnderlay::WebSocketTls { client, .. } => {
            write_vmess_websocket_frame(
                client,
                payload,
                "write VMess TLS WebSocket UDP session packet",
            )
            .await
        }
        VmessAeadUdpUnderlay::GrpcTls {
            send_stream,
            grpc_mode,
            ..
        } => send_grpc_data(send_stream, payload, false, *grpc_mode).await,
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
    write_vmess_stream_bytes(
        stream,
        &handshake.request,
        &format!("write {label} handshake"),
    )
    .await?;
    let response = read_http_head(
        stream,
        HttpHeadReadOptions {
            max_bytes: 16 * 1024,
            read_timeout: Some(RESIDENT_UDP_RESPONSE_TIMEOUT),
        },
    )
    .await
    .map_err(|error| format!("read {label} handshake: {error}"))?;
    validate_websocket_handshake_response(&response.head, &handshake.expected_accept)
        .map_err(|err| format!("validate {label} upgrade: {err}"))?;
    Ok(response.leftover)
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
    write_vmess_stream_bytes(stream, &request, &format!("write {label} handshake")).await?;
    let response = read_http_head(
        stream,
        HttpHeadReadOptions {
            max_bytes: 16 * 1024,
            read_timeout: Some(RESIDENT_UDP_RESPONSE_TIMEOUT),
        },
    )
    .await
    .map_err(|error| format!("read {label} handshake: {error}"))?;
    validate_http_status(&response.head, 101)
        .map_err(|err| format!("validate {label} upgrade: {err}"))?;
    Ok(response.leftover)
}

async fn write_vmess_websocket_frame<S>(
    stream: &mut S,
    payload: &[u8],
    label: &str,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let frame = websocket_client_binary_frame_with_random_mask(payload)
        .map_err(|err| format!("{label}: {err}"))?;
    write_vmess_stream_bytes(stream, &frame, label).await
}

async fn write_vmess_stream_bytes<S>(
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

async fn read_vmess_grpc_payload(
    underlay: &mut VmessAeadUdpUnderlay,
    mode: UdpStreamReadMode,
) -> Result<Option<Vec<u8>>, String> {
    let VmessAeadUdpUnderlay::GrpcTls { response_rx, .. } = underlay else {
        return Err("VMess gRPC payload reader received non-gRPC underlay".to_owned());
    };
    let response_rx = response_rx
        .as_mut()
        .ok_or_else(|| "VMess gRPC response reader is not initialized".to_owned())?;
    receive_vmess_grpc_payload(response_rx, mode).await
}

async fn receive_vmess_grpc_payload(
    receiver: &mut tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    mode: UdpStreamReadMode,
) -> Result<Option<Vec<u8>>, String> {
    let received = if mode.waits_for_readiness() {
        receiver.recv().await
    } else {
        match receiver.try_recv() {
            Ok(received) => Some(received),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return Ok(None),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => None,
        }
    };
    match received {
        Some(Ok(payload)) => Ok(Some(payload)),
        Some(Err(err)) => Err(err),
        None => Err("VMess gRPC response reader disconnected".to_owned()),
    }
}

fn start_vmess_grpc_response_reader(
    underlay: &mut VmessAeadUdpUnderlay,
    request: vmess::VMessAeadTcpRequest,
) -> Result<(), String> {
    let VmessAeadUdpUnderlay::GrpcTls {
        response,
        response_rx,
        response_reader,
        ..
    } = underlay
    else {
        return Err("VMess gRPC response reader received non-gRPC underlay".to_owned());
    };
    let response = response
        .take()
        .ok_or_else(|| "VMess gRPC response stream is not available".to_owned())?;
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    *response_rx = Some(rx);
    *response_reader = Some(tokio::spawn(async move {
        run_vmess_grpc_response_reader(response, request, tx).await;
    }));
    Ok(())
}

async fn run_vmess_grpc_response_reader(
    mut response: GrpcH2Response,
    request: vmess::VMessAeadTcpRequest,
    tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, String>>,
) {
    let grpc_mode = response.grpc_mode();
    let mut hunk_buffer = GrpcHunkReadBuffer::with_mode(grpc_mode);
    let mut encrypted = Vec::new();
    let mut encrypted_cursor = 0_usize;
    let mut decoder = None;
    let result: Result<(), String> = async {
        loop {
            let bytes = response
                .next_data()
                .await?
                .ok_or_else(|| "VMess gRPC response stream closed".to_owned())?;
            hunk_buffer.extend_from_slice(&bytes);
            while let Some(payload) = hunk_buffer.next_payload()? {
                compact_vmess_response_buffer(&mut encrypted, &mut encrypted_cursor);
                encrypted.extend_from_slice(payload);
                if decoder.is_none() {
                    decoder = vmess::aead_tcp_response_reader_from_buffer(&mut encrypted, &request)
                        .map_err(|err| format!("read VMess gRPC UDP response header: {err}"))?;
                }
                let Some(reader) = decoder.as_mut() else {
                    continue;
                };
                while let Some(payload) = reader
                    .try_read_chunk_in_place_from_buffer(&mut encrypted, &mut encrypted_cursor)
                    .map_err(|err| format!("read VMess gRPC UDP response packet: {err}"))?
                {
                    tx.send(Ok(payload.to_vec()))
                        .await
                        .map_err(|_| "VMess gRPC response consumer stopped".to_owned())?;
                }
                compact_vmess_response_buffer(&mut encrypted, &mut encrypted_cursor);
            }
        }
    }
    .await;
    if let Err(err) = result {
        let _ = tx.send(Err(err)).await;
    }
}

fn compact_vmess_response_buffer(buffer: &mut Vec<u8>, cursor: &mut usize) {
    if *cursor == 0 {
        return;
    }
    if *cursor >= buffer.len() {
        buffer.clear();
        *cursor = 0;
        return;
    }
    if *cursor >= 8192 && cursor.saturating_mul(2) >= buffer.len() {
        buffer.drain(..*cursor);
        *cursor = 0;
    }
}

fn vmess_udp_session_result(
    payload: Vec<u8>,
    session_executor: &'static str,
    underlay_reuse: &'static str,
    tls_underlay: Option<&'static str>,
    fixed_target: UdpSessionFixedTarget,
) -> UdpExchangeResult {
    let mut result = UdpExchangeResult::new(payload, "aead-udp-over-tcp")
        .with_session_executor(session_executor)
        .with_underlay_reuse(underlay_reuse);
    if let Some(tls_underlay) = tls_underlay {
        result = result.with_tls_underlay(tls_underlay);
    }
    result.with_session_fixed_target(fixed_target)
}

fn vmess_udp_pending_session_result(
    session_executor: &'static str,
    underlay_reuse: &'static str,
    tls_underlay: Option<&'static str>,
) -> UdpExchangeResult {
    let mut result = UdpExchangeResult::pending_response("aead-udp-over-tcp")
        .with_session_executor(session_executor)
        .with_underlay_reuse(underlay_reuse);
    if let Some(tls_underlay) = tls_underlay {
        result = result.with_tls_underlay(tls_underlay);
    }
    result
}

#[cfg(test)]
mod fixed_target_tests {
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
            "VMess fixture WebSocket UDP",
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
            "VMess fixture HTTPUpgrade UDP",
        )
        .await
        .unwrap();
        server_task.await.unwrap();
        let mut stream = AsyncPrefixedStream::new(leftover, client);
        let mut payload = [0_u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"first");
    }

    #[tokio::test]
    async fn grpc_ready_only_response_read_does_not_wait_for_a_packet() {
        let (_tx, mut rx) = tokio::sync::mpsc::channel(1);
        let result = time::timeout(
            Duration::from_millis(50),
            receive_vmess_grpc_payload(&mut rx, UdpStreamReadMode::ReadyOnly),
        )
        .await
        .expect("ready-only VMess gRPC read must complete immediately")
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn grpc_waiting_response_read_receives_later_packet() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let send = tokio::spawn(async move {
            tokio::task::yield_now().await;
            tx.send(Ok(b"response".to_vec())).await.unwrap();
        });
        let result = time::timeout(
            Duration::from_secs(1),
            receive_vmess_grpc_payload(&mut rx, UdpStreamReadMode::Wait),
        )
        .await
        .expect("waiting VMess gRPC read must receive the independently produced packet")
        .unwrap();
        send.await.unwrap();
        assert_eq!(result.as_deref(), Some(b"response".as_slice()));
    }

    #[tokio::test]
    async fn grpc_response_reader_preserves_typed_failure() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.send(Err("fixture response failure".to_owned()))
            .await
            .unwrap();
        let err = receive_vmess_grpc_payload(&mut rx, UdpStreamReadMode::Wait)
            .await
            .unwrap_err();
        assert_eq!(err, "fixture response failure");
    }

    #[test]
    fn vmess_udp_response_uses_its_bound_target() {
        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let mut session = VmessAeadUdpOverTcpSession::plain(
            "fixture-id".to_owned(),
            vmess::VMessBodySecurity::Aes128Gcm,
        );
        session
            .fixed_target
            .bind(target, "VMess AEAD UDP-over-TCP session")
            .unwrap();
        let response = vmess_udp_session_result(
            b"response".to_vec(),
            "tokio-stream-session",
            "stream-reused",
            None,
            session.fixed_target,
        );
        assert_eq!(
            response.validate_fixed_target(response.fixed_target_expectation(target)),
            UdpFixedTargetValidation::Validated
        );
    }
}
