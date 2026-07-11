use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, atomic::Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dae_outbound::{
    shared_transport::{HttpUpgradeOptions, MeekRoundTripOptions, MuxFrameOptions, mux_new_frame},
    vless::{contract::is_xtls_rprx_vision_flow, packet},
    vmess::VMessMetadata,
};

use super::super::super::{ResidentStopSignal, SharedResidentStopSignal};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time;

use super::super::super::client::{
    open_async_vless_tls_client_with_flow, open_proxy_tcp_stream_async_with_flow,
};
use super::super::super::plan::ResidentProxyPlan;
use super::super::super::plan::{ResidentProxyProtocolPlan, ResidentXhttpMode};
use super::super::super::{
    ResidentDataplaneMetrics, VLESS_RESPONSE_VERSION,
    tcp::{
        TcpProxySelection, XhttpPacketUpParts, XhttpStreamParts, close_xhttp_download_client,
        close_xhttp_stream_upload_client, close_xhttp_upload_client, meek_round_trip_async,
        native_httpupgrade_handshake_over_resident_tls_async,
        native_websocket_handshake_over_resident_tls_async,
        native_write_websocket_binary_frame_over_resident_tls_async, open_grpc_h2_stream,
        open_h2_body_stream_with_deferred_response, open_xhttp_packet_up_parts,
        open_xhttp_stream_parts, relay_tcp_over_deferred_h2_body, relay_tcp_over_grpc_h2,
        relay_tcp_over_vless_mux_tls_async, relay_tcp_over_vless_tls_async,
        relay_tcp_over_vless_websocket_tls_async, relay_tcp_over_xhttp_packet_up,
        relay_tcp_over_xhttp_stream, send_xhttp_packet_up_request,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_vless_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    if !vless_native_tcp_net_admitted(&selection) {
        return Err(NativeTcpProbeError::NotAdmitted);
    }
    let key = selection
        .proxy
        .vless_key()
        .map_err(NativeTcpProbeError::Open)?;
    let request = packet::first_write_bytes(&key, &selection.proxy.flow, "tcp", target, false, &[])
        .map_err(|err| {
            NativeTcpProbeError::Open(format!("build native VLESS TCP request: {err}"))
        })?;

    if matches!(
        selection.proxy.handler,
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. }
    ) {
        return open_vless_mux_native_tcp_tunnel(selection, key, target).await;
    }
    if matches!(selection.proxy.tls.as_str(), "" | "none") {
        let mut stream = open_proxy_tcp_stream_async_with_flow(
            &selection.proxy,
            selection.mark,
            selection.mptcp,
        )
        .await
        .map_err(NativeTcpProbeError::Open)?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &request)
            .await
            .map_err(|err| {
                NativeTcpProbeError::Open(format!("write native VLESS request: {err}"))
            })?;
        return Ok(Box::new(VlessNativeTunnel::new(stream)));
    }

    if selection.proxy.net == "meek" {
        let meek_request =
            packet::first_write_bytes(&key, "", "tcp", target, false, &[]).map_err(|err| {
                NativeTcpProbeError::Open(format!("build native VLESS Meek request: {err}"))
            })?;
        return open_vless_meek_native_tcp_tunnel(selection, target, meek_request).await;
    }
    if selection.proxy.net == "xhttp" {
        return open_vless_xhttp_native_tcp_tunnel(selection, request).await;
    }

    let mut client =
        open_async_vless_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    match selection.proxy.net.as_str() {
        "grpc" => {
            let (mut h2_send, mut h2_recv, connection_task) =
                open_grpc_h2_stream(client, &selection.proxy, &request)
                    .await
                    .map_err(NativeTcpProbeError::Open)?;
            let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
            let stop = ResidentStopSignal::shared();
            let relay_stop = Arc::clone(&stop);
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
                connection_task.abort();
                stop.store(true, Ordering::Relaxed);
            });
            return Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)));
        }
        "h2" => {
            let (mut h2_send, response_task, connection_task) =
                open_h2_body_stream_with_deferred_response(
                    client,
                    &selection.proxy,
                    vec![Bytes::from(request)],
                    "VLESS H2",
                )
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
            let stop = ResidentStopSignal::shared();
            let relay_stop = Arc::clone(&stop);
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
                connection_task.abort();
                stop.store(true, Ordering::Relaxed);
            });
            return Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)));
        }
        _ => {}
    }
    if selection.proxy.net == "websocket" {
        let options =
            HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
        native_websocket_handshake_over_resident_tls_async(&mut client, &options)
            .await
            .map_err(NativeTcpProbeError::Open)?;
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
        let metrics = ResidentDataplaneMetrics::default();
        let task = tokio::spawn(async move {
            let _ = relay_tcp_over_vless_websocket_tls_async(
                &mut relay_side,
                &mut client,
                relay_stop,
                0,
                &metrics,
            )
            .await;
            stop.store(true, Ordering::Relaxed);
        });
        return Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)));
    }
    if selection.proxy.net == "httpupgrade" {
        let options =
            HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
        native_httpupgrade_handshake_over_resident_tls_async(&mut client, &options)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    }
    client
        .write_plain_all(&request, "write native VLESS TLS request")
        .await
        .map_err(NativeTcpProbeError::Open)?;
    if is_xtls_rprx_vision_flow(&selection.proxy.flow) {
        let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
        let stop = ResidentStopSignal::shared();
        let relay_stop = Arc::clone(&stop);
        let flow = selection.proxy.flow.clone();
        let metrics = ResidentDataplaneMetrics::default();
        let task = tokio::spawn(async move {
            let _ = relay_tcp_over_vless_tls_async(
                &mut relay_side,
                &mut client,
                relay_stop,
                &flow,
                key,
                &[],
                &metrics,
            )
            .await;
            stop.store(true, Ordering::Relaxed);
        });
        return Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)));
    }
    Ok(Box::new(VlessNativeTunnel::new(client)))
}

fn vless_native_tcp_net_admitted(selection: &TcpProxySelection) -> bool {
    match selection.proxy.net.as_str() {
        "websocket" => !is_xtls_rprx_vision_flow(&selection.proxy.flow),
        "httpupgrade" => true,
        "grpc" | "h2" | "xhttp" => true,
        "meek" => true,
        _ => true,
    }
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
    let proxy = Arc::clone(&selection.proxy);
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let task = tokio::spawn(async move {
        let _ = relay_tcp_over_vless_meek_native_async(
            &mut relay_side,
            proxy,
            options,
            first_payload,
            relay_stop,
            &metrics,
        )
        .await;
        stop.store(true, Ordering::Relaxed);
    });
    Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
}

async fn relay_tcp_over_vless_meek_native_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: Arc<ResidentProxyPlan>,
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
        let response = meek_round_trip_async(&proxy, &options, &body).await?;
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
    key: [u8; 16],
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let mut client =
        open_async_vless_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    let header =
        packet::request_header(&key, "", "tcp", "0.0.0.0:0", true, &[]).map_err(|err| {
            NativeTcpProbeError::Open(format!("build native VLESS mux header: {err}"))
        })?;
    let mux_target = VMessMetadata::parse("tcp", target).map_err(|err| {
        NativeTcpProbeError::Open(format!("build native VLESS mux target: {err}"))
    })?;
    let mux_id = mux_target.port().to_be_bytes();
    let mux_options = MuxFrameOptions::new(mux_id, mux_target.hostname(), mux_target.port(), "tcp");
    let mux_new = mux_new_frame(&mux_options)
        .map_err(|err| NativeTcpProbeError::Open(format!("build native VLESS mux frame: {err}")))?;
    client
        .write_plain_all(&header, "write native VLESS mux header")
        .await
        .map_err(NativeTcpProbeError::Open)?;
    client
        .write_plain_all(&mux_new, "write native VLESS mux new frame")
        .await
        .map_err(NativeTcpProbeError::Open)?;

    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let task = tokio::spawn(async move {
        let _ = relay_tcp_over_vless_mux_tls_async(
            &mut relay_side,
            &mut client,
            relay_stop,
            mux_id,
            &[],
            &metrics,
        )
        .await;
        stop.store(true, Ordering::Relaxed);
    });
    Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
}

async fn open_vless_xhttp_native_tcp_tunnel(
    selection: TcpProxySelection,
    request: Vec<u8>,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let task = match selection.proxy.xhttp_mode {
        ResidentXhttpMode::PacketUp => {
            let XhttpPacketUpParts {
                session_id,
                mut upload,
                mut download,
                ..
            } = open_xhttp_packet_up_parts(&selection.proxy, selection.mark, selection.mptcp)
                .await
                .map_err(NativeTcpProbeError::Open)?;
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
                mut upload,
                mut download,
                ..
            } = open_xhttp_stream_parts(
                &selection.proxy,
                selection.mark,
                selection.mptcp,
                Bytes::from(request),
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
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
    Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
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
