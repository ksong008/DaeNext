use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, atomic::Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dae_outbound::{
    shared_transport::{HttpUpgradeOptions, MeekRoundTripOptions},
    vless::{VlessEncryptedStream, packet},
};
use dae_resident_transport::{
    httpupgrade_handshake_over_resident_tls_async as native_httpupgrade_handshake_over_resident_tls_async,
    websocket_handshake_over_resident_tls_async as native_websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async as native_write_websocket_binary_frame_over_resident_tls_async,
};

use super::super::super::{ResidentStopSignal, SharedResidentStopSignal};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time;

use super::super::super::client::{
    open_async_resident_tls_client_with_binding, open_proxy_tcp_stream_with_binding,
};
use super::super::super::plan::{
    ResidentProtocolShape, ResidentProxyBinding, ResidentSecurityUnderlayPlan,
    ResidentStreamWrapperPlan, ResidentXhttpMode,
};
use super::super::super::{
    ResidentDataplaneMetrics, VLESS_RESPONSE_VERSION, acquire_vless_mux_logical_stream,
    tcp::{
        AsyncPrefixedStream, TcpProxySelection, XhttpPacketUpParts, XhttpStreamParts,
        close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
        meek_round_trip_async, open_grpc_h2_stream, open_h2_body_stream_with_deferred_response,
        open_xhttp_packet_up_parts, open_xhttp_stream_parts, relay_tcp_over_deferred_h2_body,
        relay_tcp_over_grpc_h2, relay_tcp_over_vless_tls_async, relay_tcp_over_vless_vision_duplex,
        relay_tcp_over_vless_websocket_tls_async, relay_tcp_over_xhttp_packet_up,
        relay_tcp_over_xhttp_stream, send_xhttp_packet_up_request, spawn_grpc_h2_payload_stream,
        spawn_websocket_payload_stream, spawn_xhttp_packet_up_payload_stream,
        spawn_xhttp_stream_payload_stream,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel, boxed_native_tcp_tunnel};

pub(super) async fn open_vless_native_tcp_tunnel(
    binding: ResidentProxyBinding,
    target: &str,
    owner_deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(binding, target);
    let execution = selection.proxy.execution_plan();
    let key = selection
        .proxy
        .vless_key()
        .map_err(NativeTcpProbeError::Open)?;
    let request = packet::first_write_bytes(&key, &selection.proxy.flow, "tcp", target, false, &[])
        .map_err(|err| {
            NativeTcpProbeError::Open(format!("build native VLESS TCP request: {err}"))
        })?;

    if execution.protocol == ResidentProtocolShape::VlessMux {
        return open_vless_mux_native_tcp_tunnel(selection, target, owner_deadline).await;
    }
    if execution.security == ResidentSecurityUnderlayPlan::None {
        let mut stream = open_proxy_tcp_stream_with_binding(&selection.proxy, selection.mptcp)
            .await
            .map_err(NativeTcpProbeError::Open)?;
        if let Some(encryption) = selection
            .proxy
            .vless_encryption()
            .map_err(NativeTcpProbeError::Open)?
        {
            let mut encrypted = VlessEncryptedStream::handshake(stream, encryption)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("VLESS Encryption handshake: {err}"))
                })?;
            encrypted.write_all(&request).await.map_err(|err| {
                NativeTcpProbeError::Open(format!("write native VLESS encrypted request: {err}"))
            })?;
            encrypted.flush().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("flush native VLESS encrypted request: {err}"))
            })?;
            return Ok(boxed_native_tcp_tunnel(VlessNativeTunnel::new(encrypted)));
        }
        tokio::io::AsyncWriteExt::write_all(&mut stream, &request)
            .await
            .map_err(|err| {
                NativeTcpProbeError::Open(format!("write native VLESS request: {err}"))
            })?;
        return Ok(boxed_native_tcp_tunnel(VlessNativeTunnel::new(stream)));
    }

    if execution.wrapper == ResidentStreamWrapperPlan::Meek {
        let meek_request =
            packet::first_write_bytes(&key, "", "tcp", target, false, &[]).map_err(|err| {
                NativeTcpProbeError::Open(format!("build native VLESS Meek request: {err}"))
            })?;
        return open_vless_meek_native_tcp_tunnel(selection, target, meek_request).await;
    }
    if matches!(execution.wrapper, ResidentStreamWrapperPlan::Xhttp(_)) {
        return open_vless_xhttp_native_tcp_tunnel(selection, request).await;
    }

    match execution.wrapper {
        ResidentStreamWrapperPlan::Grpc => {
            let (mut h2_send, mut h2_recv, carrier_lease) = open_grpc_h2_stream(
                &selection.proxy,
                if selection
                    .proxy
                    .vless_encryption()
                    .map_err(NativeTcpProbeError::Open)?
                    .is_some()
                {
                    &[]
                } else {
                    &request
                },
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            if let Some(encryption) = selection
                .proxy
                .vless_encryption()
                .map_err(NativeTcpProbeError::Open)?
            {
                let logical = spawn_grpc_h2_payload_stream(h2_send, h2_recv, carrier_lease);
                let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                    .await
                    .map_err(|err| {
                        NativeTcpProbeError::Open(format!("VLESS Encryption gRPC handshake: {err}"))
                    })?;
                encrypted.write_all(&request).await.map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "write native VLESS encrypted gRPC request: {err}"
                    ))
                })?;
                encrypted.flush().await.map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "flush native VLESS encrypted gRPC request: {err}"
                    ))
                })?;
                return Ok(boxed_native_tcp_tunnel(VlessNativeTunnel::new(encrypted)));
            }
            let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
            let stop = ResidentStopSignal::shared();
            let relay_stop = Arc::clone(&stop);
            let tunnel_stop = Arc::clone(&stop);
            let metrics = ResidentDataplaneMetrics::default();
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_grpc_h2(
                    &mut relay_side,
                    &mut h2_send,
                    &mut h2_recv,
                    relay_stop,
                    Default::default(),
                    &metrics,
                    true,
                )
                .await;
                drop(carrier_lease);
                stop.store(true, Ordering::Relaxed);
            });
            return Ok(Box::new(SpawnedNativeTcpTunnel::new(
                probe,
                task,
                tunnel_stop,
            )));
        }
        ResidentStreamWrapperPlan::H2 => {
            let (mut h2_send, response_task, carrier_lease) =
                open_h2_body_stream_with_deferred_response(
                    &selection.proxy,
                    vec![Bytes::from(request)],
                    "VLESS H2",
                )
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
            let stop = ResidentStopSignal::shared();
            let relay_stop = Arc::clone(&stop);
            let tunnel_stop = Arc::clone(&stop);
            let metrics = ResidentDataplaneMetrics::default();
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_deferred_h2_body(
                    &mut relay_side,
                    &mut h2_send,
                    response_task,
                    relay_stop,
                    Default::default(),
                    &metrics,
                    true,
                    "VLESS H2",
                )
                .await;
                drop(carrier_lease);
                stop.store(true, Ordering::Relaxed);
            });
            return Ok(Box::new(SpawnedNativeTcpTunnel::new(
                probe,
                task,
                tunnel_stop,
            )));
        }
        _ => {}
    }
    let mut client = open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    if execution.wrapper == ResidentStreamWrapperPlan::WebSocket {
        let options =
            HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
        let ws_leftover = native_websocket_handshake_over_resident_tls_async(&mut client, &options)
            .await
            .map_err(NativeTcpProbeError::Open)?;
        if let Some(encryption) = selection
            .proxy
            .vless_encryption()
            .map_err(NativeTcpProbeError::Open)?
        {
            // The Encryption layer belongs above decoded WebSocket payloads,
            // exactly as it does for the resident traffic handler.  Sending
            // the VLESS request as a plain binary frame here would make the
            // Xray server interpret the first bytes as a corrupted
            // Encryption handshake, causing probe-only failures that do not
            // reflect the actual traffic executor.
            let logical = spawn_websocket_payload_stream(client, ws_leftover);
            let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "VLESS Encryption websocket handshake: {err}"
                    ))
                })?;
            encrypted.write_all(&request).await.map_err(|err| {
                NativeTcpProbeError::Open(format!(
                    "write native VLESS encrypted websocket request: {err}"
                ))
            })?;
            encrypted.flush().await.map_err(|err| {
                NativeTcpProbeError::Open(format!(
                    "flush native VLESS encrypted websocket request: {err}"
                ))
            })?;
            return Ok(boxed_native_tcp_tunnel(VlessNativeTunnel::new(encrypted)));
        }
        native_write_websocket_binary_frame_over_resident_tls_async(
            &mut client,
            &request,
            "write native VLESS websocket request",
        )
        .await
        .map_err(NativeTcpProbeError::Open)?;
        let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
        let stop = ResidentStopSignal::shared();
        let relay_stop = Arc::clone(&stop);
        let tunnel_stop = Arc::clone(&stop);
        let metrics = ResidentDataplaneMetrics::default();
        let task = tokio::spawn(async move {
            let _ = relay_tcp_over_vless_websocket_tls_async(
                &mut relay_side,
                &mut client,
                relay_stop,
                0,
                ws_leftover,
                &metrics,
            )
            .await;
            stop.store(true, Ordering::Relaxed);
        });
        return Ok(Box::new(SpawnedNativeTcpTunnel::new(
            probe,
            task,
            tunnel_stop,
        )));
    }
    let response_prefix = if execution.wrapper == ResidentStreamWrapperPlan::HttpUpgrade {
        let options =
            HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
        native_httpupgrade_handshake_over_resident_tls_async(&mut client, &options)
            .await
            .map_err(NativeTcpProbeError::Open)?
    } else {
        Vec::new()
    };
    if let Some(encryption) = selection
        .proxy
        .vless_encryption()
        .map_err(NativeTcpProbeError::Open)?
    {
        let prefixed = AsyncPrefixedStream::new(response_prefix, client);
        let mut encrypted = VlessEncryptedStream::handshake(prefixed, encryption)
            .await
            .map_err(|err| {
                NativeTcpProbeError::Open(format!("VLESS Encryption handshake over TLS: {err}"))
            })?;
        encrypted.write_all(&request).await.map_err(|err| {
            NativeTcpProbeError::Open(format!("write native VLESS encrypted TLS request: {err}"))
        })?;
        encrypted.flush().await.map_err(|err| {
            NativeTcpProbeError::Open(format!("flush native VLESS encrypted TLS request: {err}"))
        })?;
        if execution.protocol == ResidentProtocolShape::VlessVision {
            let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
            let stop = ResidentStopSignal::shared();
            let relay_stop = Arc::clone(&stop);
            let tunnel_stop = Arc::clone(&stop);
            let metrics = ResidentDataplaneMetrics::default();
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vless_vision_duplex(
                    &mut relay_side,
                    &mut encrypted,
                    relay_stop,
                    key,
                    Vec::new(),
                    Vec::new(),
                    &metrics,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            return Ok(Box::new(SpawnedNativeTcpTunnel::new(
                probe,
                task,
                tunnel_stop,
            )));
        }
        return Ok(boxed_native_tcp_tunnel(VlessNativeTunnel::new(encrypted)));
    }
    client
        .write_plain_all(&request, "write native VLESS TLS request")
        .await
        .map_err(NativeTcpProbeError::Open)?;
    if execution.protocol == ResidentProtocolShape::VlessVision {
        let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
        let stop = ResidentStopSignal::shared();
        let relay_stop = Arc::clone(&stop);
        let tunnel_stop = Arc::clone(&stop);
        let flow = selection.proxy.flow.clone();
        let metrics = ResidentDataplaneMetrics::default();
        let task = tokio::spawn(async move {
            let _ = relay_tcp_over_vless_tls_async(
                &mut relay_side,
                &mut client,
                relay_stop,
                &flow,
                key,
                Vec::new(),
                response_prefix,
                &metrics,
            )
            .await;
            stop.store(true, Ordering::Relaxed);
        });
        return Ok(Box::new(SpawnedNativeTcpTunnel::new(
            probe,
            task,
            tunnel_stop,
        )));
    }
    VlessNativeTunnel::new_with_response_prefix(client, response_prefix)
        .map(boxed_native_tcp_tunnel)
        .map_err(NativeTcpProbeError::Open)
}

async fn open_vless_meek_native_tcp_tunnel(
    selection: TcpProxySelection,
    target: &str,
    first_payload: Vec<u8>,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let options = MeekRoundTripOptions {
        url: format!(
            "https://{}{}",
            selection.proxy.stream_host, selection.proxy.stream_path
        ),
        host: selection.proxy.stream_host.clone(),
        path: selection.proxy.stream_path.clone(),
        session_tag: format!("{}|{}", selection.proxy.graph_id, target).into_bytes(),
    };
    let binding = selection.proxy.clone();
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let tunnel_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let task = tokio::spawn(async move {
        let _ = relay_tcp_over_vless_meek_native_async(
            &mut relay_side,
            binding,
            options,
            first_payload,
            relay_stop,
            &metrics,
        )
        .await;
        stop.store(true, Ordering::Relaxed);
    });
    Ok(Box::new(SpawnedNativeTcpTunnel::new(
        probe,
        task,
        tunnel_stop,
    )))
}

async fn relay_tcp_over_vless_meek_native_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    binding: ResidentProxyBinding,
    options: MeekRoundTripOptions,
    first_payload: Vec<u8>,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let mut stripper = VlessResponseStripper::default();
    let mut next_body = Some(first_payload);
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut empty_poll_count = 0_usize;

    while !stop.load(Ordering::Relaxed) {
        let body = if let Some(body) = next_body.take() {
            body
        } else {
            let mut buf = [0_u8; 16 * 1024];
            match time::timeout(Duration::from_millis(150), inbound.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    inbound_closed = true;
                    Vec::new()
                }
                Ok(Ok(read)) => {
                    metrics.add_upload(read);
                    last_activity = Instant::now();
                    empty_poll_count = 0;
                    buf[..read].to_vec()
                }
                Ok(Err(err)) => return Err(format!("read native VLESS Meek upload: {err}")),
                Err(_) => Vec::new(),
            }
        };

        if body.is_empty() {
            empty_poll_count = empty_poll_count.saturating_add(1);
        }
        let response = meek_round_trip_async(&binding, &options, &body).await?;
        let response_payload = stripper.consume(&response)?;
        if !response_payload.is_empty() {
            inbound
                .write_all(&response_payload)
                .await
                .map_err(|err| format!("write native VLESS Meek response: {err}"))?;
            metrics.add_download(response_payload.len());
            last_activity = Instant::now();
            empty_poll_count = 0;
        }
        if inbound_closed && response_payload.is_empty() {
            break;
        }
        if empty_poll_count >= 3
            && last_activity.elapsed() > super::super::super::RESIDENT_TCP_IDLE_TIMEOUT
        {
            break;
        }
    }
    Ok(())
}

async fn open_vless_mux_native_tcp_tunnel(
    selection: TcpProxySelection,
    target: &str,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let logical =
        acquire_vless_mux_logical_stream(selection.proxy.clone(), target.to_owned(), deadline)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    Ok(boxed_native_tcp_tunnel(logical))
}

async fn open_vless_xhttp_native_tcp_tunnel(
    selection: TcpProxySelection,
    request: Vec<u8>,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let encryption = selection
        .proxy
        .vless_encryption()
        .map_err(NativeTcpProbeError::Open)?;
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let tunnel_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let task = match selection.proxy.xhttp_mode {
        ResidentXhttpMode::PacketUp => {
            let XhttpPacketUpParts {
                session_id,
                upload,
                download,
                upload_underlay,
                upload_http_version,
                download_separate,
            } = open_xhttp_packet_up_parts(&selection.proxy, selection.mptcp)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            if let Some(encryption) = encryption {
                let logical = spawn_xhttp_packet_up_payload_stream(XhttpPacketUpParts {
                    session_id,
                    upload,
                    download,
                    upload_underlay,
                    upload_http_version,
                    download_separate,
                });
                let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                    .await
                    .map_err(|err| {
                        NativeTcpProbeError::Open(format!(
                            "VLESS Encryption xHTTP packet-up handshake: {err}"
                        ))
                    })?;
                encrypted.write_all(&request).await.map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "write native VLESS encrypted xHTTP packet-up request: {err}"
                    ))
                })?;
                encrypted.flush().await.map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "flush native VLESS encrypted xHTTP packet-up request: {err}"
                    ))
                })?;
                return Ok(boxed_native_tcp_tunnel(VlessNativeTunnel::new(encrypted)));
            }
            let mut upload = upload;
            let mut download = download;
            send_xhttp_packet_up_request(&mut upload, &session_id, 0, Bytes::from(request))
                .await
                .map_err(NativeTcpProbeError::Open)?;
            tokio::spawn(async move {
                let _ = relay_tcp_over_xhttp_packet_up(
                    &mut relay_side,
                    &mut upload,
                    &mut download,
                    &session_id,
                    1,
                    relay_stop,
                    Default::default(),
                    &metrics,
                )
                .await;
                close_xhttp_download_client(download).await;
                close_xhttp_upload_client(upload).await;
                stop.store(true, Ordering::Relaxed);
            })
        }
        ResidentXhttpMode::StreamUp | ResidentXhttpMode::StreamOne => {
            let XhttpStreamParts {
                session_id,
                upload,
                download,
                upload_underlay,
                upload_http_version,
                download_separate,
            } = open_xhttp_stream_parts(
                &selection.proxy,
                selection.mptcp,
                if encryption.is_some() {
                    Bytes::new()
                } else {
                    Bytes::from(request.clone())
                },
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            if let Some(encryption) = encryption {
                let logical = spawn_xhttp_stream_payload_stream(XhttpStreamParts {
                    session_id,
                    upload,
                    download,
                    upload_underlay,
                    upload_http_version,
                    download_separate,
                });
                let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                    .await
                    .map_err(|err| {
                        NativeTcpProbeError::Open(format!(
                            "VLESS Encryption xHTTP stream handshake: {err}"
                        ))
                    })?;
                encrypted.write_all(&request).await.map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "write native VLESS encrypted xHTTP request: {err}"
                    ))
                })?;
                encrypted.flush().await.map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "flush native VLESS encrypted xHTTP request: {err}"
                    ))
                })?;
                return Ok(boxed_native_tcp_tunnel(VlessNativeTunnel::new(encrypted)));
            }
            let mut upload = upload;
            let mut download = download;
            tokio::spawn(async move {
                let _ = relay_tcp_over_xhttp_stream(
                    &mut relay_side,
                    &mut upload,
                    &mut download,
                    relay_stop,
                    Default::default(),
                    &metrics,
                )
                .await;
                close_xhttp_download_client(download).await;
                close_xhttp_stream_upload_client(upload).await;
                stop.store(true, Ordering::Relaxed);
            })
        }
    };
    Ok(Box::new(SpawnedNativeTcpTunnel::new(
        probe,
        task,
        tunnel_stop,
    )))
}

struct VlessNativeTunnel<S> {
    inner: S,
    stripper: VlessResponseStripper,
    pending_plain: VecDeque<u8>,
}

impl<S> VlessNativeTunnel<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            stripper: VlessResponseStripper::default(),
            pending_plain: VecDeque::new(),
        }
    }

    fn new_with_response_prefix(inner: S, response_prefix: Vec<u8>) -> Result<Self, String> {
        let mut tunnel = Self::new(inner);
        if !response_prefix.is_empty() {
            let plain = tunnel.stripper.consume(&response_prefix)?;
            tunnel.pending_plain.extend(plain);
        }
        Ok(tunnel)
    }
}

impl<S> AsyncRead for VlessNativeTunnel<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.drain_pending(buf) {
            return Poll::Ready(Ok(()));
        }

        let mut raw = [0_u8; 8192];
        let mut raw_buf = ReadBuf::new(&mut raw);
        match Pin::new(&mut self.inner).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(())) => {
                let read = raw_buf.filled().len();
                if read == 0 {
                    return Poll::Ready(Ok(()));
                }
                let plain = self
                    .stripper
                    .consume(&raw[..read])
                    .map_err(std::io::Error::other)?;
                self.pending_plain.extend(plain);
                self.drain_pending(buf);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> VlessNativeTunnel<S> {
    fn drain_pending(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let to_copy = self.pending_plain.len().min(buf.remaining());
        if to_copy == 0 {
            return false;
        }
        let contiguous = self.pending_plain.make_contiguous();
        buf.put_slice(&contiguous[..to_copy]);
        self.pending_plain.drain(..to_copy);
        true
    }
}

impl<S> AsyncWrite for VlessNativeTunnel<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct VlessResponseStripper {
    header: Vec<u8>,
    done: bool,
}

impl VlessResponseStripper {
    fn consume(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Ok(input.to_vec());
        }
        self.header.extend_from_slice(input);
        if self.header.len() < 2 {
            return Ok(Vec::new());
        }
        if self.header[0] != VLESS_RESPONSE_VERSION {
            return Err(format!(
                "unexpected VLESS response version: {}",
                self.header[0]
            ));
        }
        let header_len = 2 + self.header[1] as usize;
        if self.header.len() < header_len {
            return Ok(Vec::new());
        }
        self.done = true;
        Ok(self.header.split_off(header_len))
    }
}
