use std::sync::{Arc, atomic::Ordering};

use dae_outbound_core::trojan::packet as trojan_packet;
use dae_outbound_stream::shared_transport::HttpUpgradeOptions;
use dae_resident_transport::{
    httpupgrade_handshake_over_resident_tls_async as native_httpupgrade_handshake_over_resident_tls_async,
    websocket_handshake_over_resident_tls_async as native_websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async as native_write_websocket_binary_frame_over_resident_tls_async,
};

use super::super::super::ResidentStopSignal;

use super::super::super::client::open_async_resident_tls_client_with_binding;
use super::super::super::plan::{
    ResidentProxyBinding, ResidentProxyProtocolPlan, ResidentStreamWrapperPlan,
};
use super::super::super::{
    ResidentDataplaneMetrics,
    tcp::{
        open_grpc_h2_stream, relay_tcp_over_grpc_h2, relay_tcp_over_resident_tls_plain_async,
        relay_tcp_over_trojan_websocket_inner_shadowsocks_tls,
        relay_tcp_over_trojan_websocket_tls_async,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_trojan_native_tcp_tunnel(
    binding: ResidentProxyBinding,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(binding, target);
    let wrapper = selection.proxy.execution_plan().wrapper;
    let password = match &selection.proxy.handler {
        ResidentProxyProtocolPlan::TrojanTcpTls { password } => password.as_str(),
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => {
            return open_trojan_inner_shadowsocks_native_tcp_tunnel(selection, target).await;
        }
        _ => return Err(NativeTcpProbeError::NotAdmitted),
    };
    if !matches!(
        wrapper,
        ResidentStreamWrapperPlan::None
            | ResidentStreamWrapperPlan::WebSocket
            | ResidentStreamWrapperPlan::HttpUpgrade
            | ResidentStreamWrapperPlan::Grpc
    ) {
        return Err(NativeTcpProbeError::NotAdmitted);
    }

    let request = trojan_packet::tcp_request_header(password, "tcp", target, &[])
        .map_err(|err| NativeTcpProbeError::Open(format!("build native Trojan request: {err}")))?;
    if wrapper == ResidentStreamWrapperPlan::Grpc {
        let (mut h2_send, mut h2_recv, carrier_lease) =
            open_grpc_h2_stream(&selection.proxy, &request)
                .await
                .map_err(NativeTcpProbeError::Open)?;
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
                false,
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
    let mut client = open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let tunnel_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();

    match wrapper {
        ResidentStreamWrapperPlan::WebSocket => {
            let leftover =
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
                    leftover,
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
        ResidentStreamWrapperPlan::HttpUpgrade => {
            let leftover =
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
                    leftover,
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
                    Vec::new(),
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
    }
}

async fn open_trojan_inner_shadowsocks_native_tcp_tunnel(
    selection: super::super::super::tcp::TcpProxySelection,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    if selection.proxy.execution_plan().wrapper != ResidentStreamWrapperPlan::WebSocket {
        return Err(NativeTcpProbeError::NotAdmitted);
    }
    let mut client = open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    let leftover = native_websocket_handshake_over_resident_tls_async(&mut client, &options)
        .await
        .map_err(NativeTcpProbeError::Open)?;

    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let tunnel_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let target = target.to_owned();
    let binding = selection.proxy.clone();
    let task = tokio::spawn(async move {
        let ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
            password,
            inner_cipher,
            inner_password,
        } = &binding.plan().handler
        else {
            stop.store(true, Ordering::Relaxed);
            return;
        };
        let _ = relay_tcp_over_trojan_websocket_inner_shadowsocks_tls(
            &mut relay_side,
            &mut client,
            relay_stop,
            &target,
            password,
            inner_cipher,
            inner_password,
            Vec::new(),
            &metrics,
            leftover,
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
