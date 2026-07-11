use std::collections::VecDeque;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::*;

#[derive(Clone, Copy)]
pub(super) enum VmessAeadUdpWrapperKind {
    PlainTcp,
    TlsTcp,
    WebSocketPlain,
    WebSocketTls,
    HttpUpgradePlain,
    HttpUpgradeTls,
    GrpcTls,
}

pub(super) struct VmessAeadUdpOverTcpSession {
    id: String,
    wrapper: VmessAeadUdpWrapperKind,
    underlay: Option<VmessAeadUdpUnderlay>,
    upload: Option<vmess::VMessAeadTcpUploadCodec>,
    request: Option<vmess::VMessAeadTcpRequest>,
    response: Option<vmess::VMessAeadTcpResponseReader>,
    response_plaintext: Vec<u8>,
}

impl VmessAeadUdpOverTcpSession {
    pub(super) fn plain(id: String) -> Self {
        Self::new(id, VmessAeadUdpWrapperKind::PlainTcp)
    }

    pub(super) fn tls(id: String) -> Self {
        Self::new(id, VmessAeadUdpWrapperKind::TlsTcp)
    }

    pub(super) fn websocket_plain(id: String) -> Self {
        Self::new(id, VmessAeadUdpWrapperKind::WebSocketPlain)
    }

    pub(super) fn websocket_tls(id: String) -> Self {
        Self::new(id, VmessAeadUdpWrapperKind::WebSocketTls)
    }

    pub(super) fn httpupgrade_plain(id: String) -> Self {
        Self::new(id, VmessAeadUdpWrapperKind::HttpUpgradePlain)
    }

    pub(super) fn httpupgrade_tls(id: String) -> Self {
        Self::new(id, VmessAeadUdpWrapperKind::HttpUpgradeTls)
    }

    pub(super) fn grpc_tls(id: String) -> Self {
        Self::new(id, VmessAeadUdpWrapperKind::GrpcTls)
    }

    fn new(id: String, wrapper: VmessAeadUdpWrapperKind) -> Self {
        Self {
            id,
            wrapper,
            underlay: None,
            upload: None,
            request: None,
            response: None,
            response_plaintext: Vec::new(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        let result = if self.underlay.is_some() {
            self.exchange_next(payload).await
        } else {
            self.exchange_first(proxy, original_dst, payload).await
        };
        if result.is_err() {
            self.shutdown().await;
        }
        result
    }

    async fn exchange_first(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        let start = vmess::aead_udp_over_tcp_client_session_start(
            &self.id,
            &original_dst.to_string(),
            payload,
        )
        .map_err(|err| format!("start VMess AEAD UDP-over-TCP session: {err}"))?;
        let mut underlay = open_vmess_underlay(self.wrapper, proxy, &start.first_write).await?;
        let echoed = if underlay.is_grpc() {
            start_vmess_grpc_decoder(&mut underlay, start.request.clone())?;
            read_vmess_grpc_payload(&mut underlay).await?
        } else {
            self.response = None;
            self.response_plaintext.clear();
            self.request = Some(start.request);
            self.upload = Some(start.upload);
            self.underlay = Some(underlay);
            if let Some(response) = self.poll_response().await? {
                return Ok(response);
            }
            return Ok(self.pending_response_result());
        };
        let (session_executor, underlay_reuse, tls_underlay) = underlay.evidence_fields();
        self.underlay = Some(underlay);
        self.upload = Some(start.upload);
        self.request = Some(start.request);
        Ok(vmess_udp_session_result(
            echoed,
            session_executor,
            underlay_reuse,
            tls_underlay,
        ))
    }

    async fn exchange_next(&mut self, payload: &[u8]) -> Result<UdpExchangeResult, String> {
        let chunk = self
            .upload
            .as_mut()
            .ok_or_else(|| "VMess AEAD UDP-over-TCP upload codec is not initialized".to_owned())?
            .seal_chunk(payload)
            .map_err(|err| format!("seal VMess AEAD UDP-over-TCP session packet: {err}"))?;
        let is_grpc = {
            let underlay = self
                .underlay
                .as_mut()
                .ok_or_else(|| "VMess AEAD UDP-over-TCP underlay is not initialized".to_owned())?;
            write_vmess_wrapped_bytes(underlay, &chunk).await?;
            underlay.is_grpc()
        };
        let echoed = if is_grpc {
            let underlay = self
                .underlay
                .as_mut()
                .ok_or_else(|| "VMess AEAD UDP-over-TCP underlay is not initialized".to_owned())?;
            read_vmess_grpc_payload(underlay).await?
        } else {
            if let Some(response) = self.poll_response().await? {
                return Ok(response);
            }
            return Ok(self.pending_response_result());
        };
        let (session_executor, underlay_reuse, tls_underlay) = self
            .underlay
            .as_ref()
            .ok_or_else(|| "VMess AEAD UDP-over-TCP underlay is not initialized".to_owned())?
            .evidence_fields();
        Ok(vmess_udp_session_result(
            echoed,
            session_executor,
            underlay_reuse,
            tls_underlay,
        ))
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
            return if mode.waits_for_readiness() {
                std::future::pending().await
            } else {
                Ok(None)
            };
        }
        let mut buf = [0_u8; 8192];
        let Some(read) = read_vmess_underlay_plaintext(underlay, &mut buf, mode).await? else {
            return Ok(None);
        };
        self.response_plaintext.extend_from_slice(&buf[..read]);
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
        response
            .try_read_chunk_from_buffer(&mut self.response_plaintext)
            .map_err(|err| format!("read VMess wrapped UDP session packet: {err}"))
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        let (session_executor, underlay_reuse, tls_underlay) = self
            .underlay
            .as_ref()
            .map(VmessAeadUdpUnderlay::evidence_fields)
            .unwrap_or(("tokio-stream-session", "stream-reused", None));
        vmess_udp_session_result(payload, session_executor, underlay_reuse, tls_underlay)
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
    proxy: &ResidentProxyPlan,
    first_write: &[u8],
) -> Result<VmessAeadUdpUnderlay, String> {
    match wrapper {
        VmessAeadUdpWrapperKind::PlainTcp => {
            let mut stream = open_proxy_tcp_stream_async(proxy).await?;
            write_vmess_stream_bytes(
                &mut stream,
                first_write,
                "write VMess AEAD UDP-over-TCP session first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::PlainTcp { stream })
        }
        VmessAeadUdpWrapperKind::TlsTcp => {
            let mut client = open_async_resident_tls_client(proxy).await?;
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
        VmessAeadUdpWrapperKind::WebSocketPlain => {
            let mut stream = open_proxy_tcp_stream_async(proxy).await?;
            websocket_handshake_async(
                &mut stream,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess WebSocket UDP",
            )
            .await?;
            write_vmess_websocket_frame(
                &mut stream,
                first_write,
                "write VMess WebSocket UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::WebSocketPlain {
                stream,
                state: AsyncWebSocketPayloadState::default(),
            })
        }
        VmessAeadUdpWrapperKind::WebSocketTls => {
            let mut client = open_async_resident_tls_client(proxy).await?;
            let tls_underlay = async_resident_tls_underlay_name(&client);
            websocket_handshake_async(
                &mut client,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess TLS WebSocket UDP",
            )
            .await?;
            write_vmess_websocket_frame(
                &mut client,
                first_write,
                "write VMess TLS WebSocket UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::WebSocketTls {
                client,
                state: AsyncWebSocketPayloadState::default(),
                tls_underlay,
            })
        }
        VmessAeadUdpWrapperKind::HttpUpgradePlain => {
            let mut stream = open_proxy_tcp_stream_async(proxy).await?;
            httpupgrade_handshake_async(
                &mut stream,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess HTTPUpgrade UDP",
            )
            .await?;
            write_vmess_stream_bytes(
                &mut stream,
                first_write,
                "write VMess HTTPUpgrade UDP first packet",
            )
            .await?;
            Ok(VmessAeadUdpUnderlay::HttpUpgradePlain { stream })
        }
        VmessAeadUdpWrapperKind::HttpUpgradeTls => {
            let mut client = open_async_resident_tls_client(proxy).await?;
            let tls_underlay = async_resident_tls_underlay_name(&client);
            httpupgrade_handshake_async(
                &mut client,
                &proxy.stream_host,
                &proxy.stream_path,
                "VMess TLS HTTPUpgrade UDP",
            )
            .await?;
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
            let client = open_async_resident_tls_client(proxy).await?;
            let tls_underlay = async_resident_tls_underlay_name(&client);
            let (send_stream, recv_stream, connection_task) =
                open_grpc_h2_stream(client, proxy, first_write).await?;
            Ok(VmessAeadUdpUnderlay::GrpcTls {
                send_stream,
                recv_stream,
                connection_task,
                encrypted_writer: None,
                decrypted_rx: None,
                decoder: None,
                response_buf: GrpcHunkReadBuffer::default(),
                pending_plain: VecDeque::new(),
                decode_error: None,
                tls_underlay,
            })
        }
    }
}

impl VmessAeadUdpOverTcpSession {
    pub(super) async fn shutdown(&mut self) {
        self.upload = None;
        self.request = None;
        self.response = None;
        self.response_plaintext.clear();
        if let Some(mut underlay) = self.underlay.take() {
            underlay.shutdown().await;
        }
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
            VmessAeadUdpUnderlay::PlainTcp { stream }
            | VmessAeadUdpUnderlay::HttpUpgradePlain { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VmessAeadUdpUnderlay::TlsTcp { client, .. }
            | VmessAeadUdpUnderlay::HttpUpgradeTls { client, .. } => {
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
        recv_stream: h2::RecvStream,
        connection_task: tokio::task::JoinHandle<()>,
        encrypted_writer: Option<tokio::io::DuplexStream>,
        decrypted_rx: Option<tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>>,
        decoder: Option<tokio::task::JoinHandle<Result<(), String>>>,
        response_buf: GrpcHunkReadBuffer,
        pending_plain: VecDeque<Vec<u8>>,
        decode_error: Option<String>,
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
                encrypted_writer,
                decoder,
                ..
            } => {
                let _ = send_h2_data(send_stream, Bytes::new(), true).await;
                if let Some(writer) = encrypted_writer.as_mut() {
                    let _ = writer.shutdown().await;
                }
                encrypted_writer.take();
                connection_task.abort();
                if let Some(decoder) = decoder.take() {
                    let _ = decoder.await;
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
        VmessAeadUdpUnderlay::PlainTcp { stream }
        | VmessAeadUdpUnderlay::HttpUpgradePlain { stream } => {
            write_vmess_stream_bytes(stream, payload, "write VMess wrapped UDP session packet")
                .await
        }
        VmessAeadUdpUnderlay::TlsTcp { client, .. }
        | VmessAeadUdpUnderlay::HttpUpgradeTls { client, .. } => {
            write_vmess_stream_bytes(
                client,
                payload,
                "write VMess TLS wrapped UDP session packet",
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
        VmessAeadUdpUnderlay::GrpcTls { send_stream, .. } => {
            send_grpc_hunk(send_stream, payload, false).await
        }
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
    write_vmess_stream_bytes(stream, &request, &format!("write {label} handshake")).await?;
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
    write_vmess_stream_bytes(stream, &request, &format!("write {label} handshake")).await?;
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

async fn read_vmess_grpc_payload(underlay: &mut VmessAeadUdpUnderlay) -> Result<Vec<u8>, String> {
    let VmessAeadUdpUnderlay::GrpcTls {
        recv_stream,
        encrypted_writer,
        decrypted_rx,
        decoder: _,
        response_buf,
        pending_plain,
        decode_error,
        ..
    } = underlay
    else {
        return Err("VMess gRPC payload reader received non-gRPC underlay".to_owned());
    };
    if decrypted_rx.is_none() {
        return Err("VMess gRPC decoder is not initialized".to_owned());
    }
    if encrypted_writer.is_none() {
        return Err("VMess gRPC encrypted response writer is not initialized".to_owned());
    }
    let response_deadline = time::sleep(RESIDENT_UDP_RESPONSE_TIMEOUT);
    tokio::pin!(response_deadline);
    loop {
        if let Some(payload) = pending_plain.pop_front() {
            return Ok(payload);
        }
        let disconnected = {
            let rx = decrypted_rx
                .as_mut()
                .ok_or_else(|| "VMess gRPC decoder is not initialized".to_owned())?;
            let (chunks, disconnected) = collect_vmess_grpc_decrypted(rx, decode_error);
            pending_plain.extend(chunks);
            disconnected
        };
        if let Some(err) = decode_error.take() {
            return Err(err);
        }
        if let Some(payload) = pending_plain.pop_front() {
            return Ok(payload);
        }
        if disconnected {
            return Err("VMess gRPC response decoder disconnected".to_owned());
        }
        let decrypted = decrypted_rx
            .as_mut()
            .ok_or_else(|| "VMess gRPC decoder is not initialized".to_owned())?;
        tokio::select! {
            data = recv_stream.data() => match data {
            Some(Ok(bytes)) => {
                recv_stream
                    .flow_control()
                    .release_capacity(bytes.len())
                    .map_err(|err| format!("release VMess gRPC response capacity: {err}"))?;
                response_buf.extend_from_slice(&bytes);
                while let Some(payload) = response_buf.pop_payload()? {
                    if !payload.is_empty() {
                        let writer = encrypted_writer.as_mut().ok_or_else(|| {
                            "VMess gRPC encrypted response writer is not initialized".to_owned()
                        })?;
                        writer.write_all(&payload).await.map_err(|err| {
                            format!("write VMess gRPC encrypted UDP response to decoder: {err}")
                        })?;
                        writer.flush().await.map_err(|err| {
                            format!("flush VMess gRPC encrypted UDP response to decoder: {err}")
                        })?;
                    }
                }
            }
            Some(Err(err)) => return Err(format!("read VMess gRPC response data: {err}")),
            None => {
                if let Some(writer) = encrypted_writer.as_mut() {
                    let _ = writer.shutdown().await;
                }
                return Err("VMess gRPC response stream closed".to_owned());
            }
            },
            decoded = decrypted.recv() => match decoded {
                Some(Ok(payload)) => return Ok(payload),
                Some(Err(err)) => return Err(err),
                None => return Err("VMess gRPC response decoder disconnected".to_owned()),
            },
            _ = &mut response_deadline => {
                return Err("read VMess gRPC UDP response timeout".to_owned());
            }
        }
    }
}

fn start_vmess_grpc_decoder(
    underlay: &mut VmessAeadUdpUnderlay,
    request: vmess::VMessAeadTcpRequest,
) -> Result<(), String> {
    let VmessAeadUdpUnderlay::GrpcTls {
        encrypted_writer,
        decrypted_rx,
        decoder,
        ..
    } = underlay
    else {
        return Err("VMess gRPC decoder received non-gRPC underlay".to_owned());
    };
    let (writer, reader) = tokio::io::duplex(64 * 1024);
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let decoder_handle =
        tokio::spawn(
            async move { decode_vmess_grpc_response_stream_async(reader, request, tx).await },
        );
    *encrypted_writer = Some(writer);
    *decrypted_rx = Some(rx);
    *decoder = Some(decoder_handle);
    Ok(())
}

fn vmess_udp_session_result(
    payload: Vec<u8>,
    session_executor: &'static str,
    underlay_reuse: &'static str,
    tls_underlay: Option<&'static str>,
) -> UdpExchangeResult {
    let mut result = UdpExchangeResult::new(payload, "aead-udp-over-tcp")
        .with_session_executor(session_executor)
        .with_underlay_reuse(underlay_reuse);
    if let Some(tls_underlay) = tls_underlay {
        result = result.with_tls_underlay(tls_underlay);
    }
    result
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
