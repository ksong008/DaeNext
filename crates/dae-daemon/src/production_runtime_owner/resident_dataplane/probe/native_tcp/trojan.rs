use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use dae_outbound::{shared_transport::HttpUpgradeOptions, trojan::packet as trojan_packet};

use super::super::super::client::open_async_resident_tls_client_with_flow;
use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::super::{
    ResidentDataplaneMetrics,
    tcp::{
        native_httpupgrade_handshake_over_resident_tls_async,
        native_websocket_handshake_over_resident_tls_async,
        native_write_websocket_binary_frame_over_resident_tls_async,
        relay_tcp_over_resident_tls_plain_async, relay_tcp_over_trojan_websocket_tls_async,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_trojan_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    let ResidentProxyProtocolPlan::TrojanTcpTls { password } = &selection.proxy.handler else {
        return Err(NativeTcpProbeError::NotAdmitted);
    };
    if !matches!(
        selection.proxy.net.as_str(),
        "tcp" | "websocket" | "httpupgrade"
    ) {
        return Err(NativeTcpProbeError::NotAdmitted);
    }

    let request = trojan_packet::tcp_request_header(password, "tcp", target, &[])
        .map_err(|err| NativeTcpProbeError::Open(format!("build native Trojan request: {err}")))?;
    let mut client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = Arc::new(AtomicBool::new(false));
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();

    match selection.proxy.net.as_str() {
        "websocket" => {
            native_websocket_handshake_over_resident_tls_async(&mut client, &options)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            native_write_websocket_binary_frame_over_resident_tls_async(
                &mut client,
                &request,
                "write native Trojan websocket request",
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_trojan_websocket_tls_async(
                    &mut relay_side,
                    &mut client,
                    relay_stop,
                    &metrics,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
        "httpupgrade" => {
            native_httpupgrade_handshake_over_resident_tls_async(&mut client, &options)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            client
                .write_plain_all(&request, "write native Trojan HTTP Upgrade request")
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_resident_tls_plain_async(
                    &mut relay_side,
                    &mut client,
                    relay_stop,
                    &metrics,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
        _ => {
            client
                .write_plain_all(&request, "write native Trojan request")
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_resident_tls_plain_async(
                    &mut relay_side,
                    &mut client,
                    relay_stop,
                    &metrics,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
    }
}
