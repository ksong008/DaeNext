use std::sync::{Arc, atomic::Ordering};

use dae_outbound::{shared_transport::HttpUpgradeOptions, vmess::aead_tcp_client_session_start};
use tokio::io::AsyncWriteExt;

use super::super::super::ResidentStopSignal;

use super::super::super::client::open_async_resident_tls_client_with_flow;
use super::super::super::direct::DirectTcpRelayStats;
use super::super::super::plan::{
    ResidentProxyPlan, ResidentProxyProtocolPlan, ResidentSecurityUnderlayPlan,
    ResidentStreamWrapperPlan,
};
use super::super::super::{
    ResidentDataplaneMetrics,
    tcp::{
        native_httpupgrade_handshake_over_async_stream,
        native_httpupgrade_handshake_over_resident_tls_async,
        native_websocket_handshake_over_async_stream,
        native_websocket_handshake_over_resident_tls_async,
        native_write_websocket_binary_frame_over_resident_tls_async,
        native_write_websocket_binary_frame_to_async_stream, open_grpc_h2_stream,
        open_h2_body_stream, open_plain_proxy_tcp_stream_async, relay_tcp_over_vmess_aead_async,
        relay_tcp_over_vmess_grpc_h2, relay_tcp_over_vmess_h2_body,
        relay_tcp_over_vmess_tls_aead_async, relay_tcp_over_vmess_websocket_aead_async,
        relay_tcp_over_vmess_websocket_tls_aead_async,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_vmess_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler else {
        return Err(NativeTcpProbeError::NotAdmitted);
    };
    let session = aead_tcp_client_session_start(id, target, &[]).map_err(|err| {
        NativeTcpProbeError::Open(format!("build native VMess AEAD session: {err}"))
    })?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let tunnel_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let stats = DirectTcpRelayStats::default();
    let execution = selection.proxy.execution_plan();

    match execution.wrapper {
        ResidentStreamWrapperPlan::None
            if execution.security == ResidentSecurityUnderlayPlan::None =>
        {
            let mut stream = open_plain_proxy_tcp_stream_async(&selection)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            stream
                .write_all(&session.first_write)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native VMess request: {err}"))
                })?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_aead_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    session,
                    stats,
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
        ResidentStreamWrapperPlan::None if execution.security.is_tls_stream() => {
            let mut client = open_async_resident_tls_client_with_flow(
                &selection.proxy,
                selection.mark,
                selection.mptcp,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            client
                .write_plain_all(&session.first_write, "write native VMess TLS request")
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_tls_aead_async(
                    &mut relay_side,
                    &mut client,
                    relay_stop,
                    session,
                    stats,
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
        ResidentStreamWrapperPlan::WebSocket
            if execution.security == ResidentSecurityUnderlayPlan::None =>
        {
            let mut stream = open_plain_proxy_tcp_stream_async(&selection)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            native_websocket_handshake_over_async_stream(&mut stream, &options)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            native_write_websocket_binary_frame_to_async_stream(
                &mut stream,
                &session.first_write,
                "write native VMess websocket request",
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_websocket_aead_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    session,
                    stats,
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
        ResidentStreamWrapperPlan::WebSocket if execution.security.is_tls_stream() => {
            let mut client = open_async_resident_tls_client_with_flow(
                &selection.proxy,
                selection.mark,
                selection.mptcp,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            native_websocket_handshake_over_resident_tls_async(&mut client, &options)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            native_write_websocket_binary_frame_over_resident_tls_async(
                &mut client,
                &session.first_write,
                "write native VMess TLS websocket request",
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_websocket_tls_aead_async(
                    &mut relay_side,
                    &mut client,
                    relay_stop,
                    session,
                    stats,
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
        ResidentStreamWrapperPlan::HttpUpgrade
            if execution.security == ResidentSecurityUnderlayPlan::None =>
        {
            let mut stream = open_plain_proxy_tcp_stream_async(&selection)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            native_httpupgrade_handshake_over_async_stream(&mut stream, &options)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            stream
                .write_all(&session.first_write)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "write native VMess HTTP Upgrade request: {err}"
                    ))
                })?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_aead_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    session,
                    stats,
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
        ResidentStreamWrapperPlan::HttpUpgrade if execution.security.is_tls_stream() => {
            let mut client = open_async_resident_tls_client_with_flow(
                &selection.proxy,
                selection.mark,
                selection.mptcp,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            native_httpupgrade_handshake_over_resident_tls_async(&mut client, &options)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            client
                .write_plain_all(
                    &session.first_write,
                    "write native VMess TLS HTTP Upgrade request",
                )
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_tls_aead_async(
                    &mut relay_side,
                    &mut client,
                    relay_stop,
                    session,
                    stats,
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
        ResidentStreamWrapperPlan::Grpc if execution.security.is_tls_stream() => {
            let (mut h2_send, mut h2_recv, carrier_lease) =
                open_grpc_h2_stream(&selection.proxy, &session.first_write)
                    .await
                    .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_grpc_h2(
                    &mut relay_side,
                    &mut h2_send,
                    &mut h2_recv,
                    relay_stop,
                    session,
                    stats,
                    &metrics,
                )
                .await;
                drop(carrier_lease);
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(
                probe,
                task,
                tunnel_stop,
            )))
        }
        ResidentStreamWrapperPlan::H2 if execution.security.is_tls_stream() => {
            let (mut h2_send, mut h2_recv, carrier_lease) =
                open_h2_body_stream(&selection.proxy, &session.first_write, "VMess H2")
                    .await
                    .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_vmess_h2_body(
                    &mut relay_side,
                    &mut h2_send,
                    &mut h2_recv,
                    relay_stop,
                    session,
                    stats,
                    &metrics,
                )
                .await;
                drop(carrier_lease);
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(
                probe,
                task,
                tunnel_stop,
            )))
        }
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}
