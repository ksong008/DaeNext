use std::sync::{Arc, atomic::Ordering};

use dae_outbound::{
    shadowsocks::{ShadowsocksRStreamDecoder, shadowsocksr_http_simple_origin_request},
    shared_transport::HttpUpgradeOptions,
};
use tokio::io::AsyncWriteExt;

use super::super::super::ResidentStopSignal;

use super::super::super::client::open_async_resident_tls_client_with_binding;
use super::super::super::plan::{ResidentProxyBinding, ResidentProxyProtocolPlan};
use super::super::super::{
    ResidentDataplaneMetrics,
    tcp::{
        native_websocket_handshake_over_resident_tls_async, open_plain_proxy_tcp_stream_async,
        read_http_head_and_leftover_from_async_stream, relay_tcp_over_shadowsocks_2022_async,
        relay_tcp_over_shadowsocks_2022_simple_obfs_http_async,
        relay_tcp_over_shadowsocks_aead_async, relay_tcp_over_shadowsocks_simple_obfs_http_async,
        relay_tcp_over_shadowsocks_simple_obfs_tls_async,
        relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws, relay_tcp_shadowsocksr_stream_async,
        validate_simple_obfs_http_response_status,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_shadowsocks_native_tcp_tunnel(
    binding: ResidentProxyBinding,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(binding, target);
    if matches!(
        &selection.proxy.handler,
        ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
    ) {
        return open_shadowsocks_v2ray_plugin_native_tcp_tunnel(selection, target.to_owned()).await;
    }
    let mut stream = open_plain_proxy_tcp_stream_async(&selection)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let tunnel_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let target = target.to_owned();

    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
            cipher,
            password,
            obfs_host,
            obfs_port,
        } => {
            let mut client_iv = [0_u8; 16];
            fastrand::fill(&mut client_iv);
            let (request, mut encoder) = shadowsocksr_http_simple_origin_request(
                cipher,
                password,
                &target,
                &[],
                obfs_host,
                *obfs_port,
                client_iv,
            )
            .map_err(|err| {
                NativeTcpProbeError::Open(format!("build native ShadowsocksR request: {err}"))
            })?;
            stream.write_all(&request).await.map_err(|err| {
                NativeTcpProbeError::Open(format!("write native ShadowsocksR request: {err}"))
            })?;
            stream.flush().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("flush native ShadowsocksR request: {err}"))
            })?;
            let (response_head, leftover) =
                read_http_head_and_leftover_from_async_stream(&mut stream)
                    .await
                    .map_err(|err| {
                        NativeTcpProbeError::Open(format!(
                            "read native ShadowsocksR obfs response: {err}"
                        ))
                    })?;
            validate_simple_obfs_http_response_status(&response_head).map_err(|err| {
                NativeTcpProbeError::Open(format!(
                    "validate native ShadowsocksR obfs response: {err}"
                ))
            })?;
            let mut decoder = ShadowsocksRStreamDecoder::new(cipher, password).map_err(|err| {
                NativeTcpProbeError::Open(format!(
                    "create native ShadowsocksR stream decoder: {err}"
                ))
            })?;
            let initial_plain = if leftover.is_empty() {
                Vec::new()
            } else {
                decoder.decode(&leftover).map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "decode native ShadowsocksR initial response: {err}"
                    ))
                })?
            };
            let task = tokio::spawn(async move {
                if !initial_plain.is_empty() {
                    let _ = relay_side.write_all(&initial_plain).await;
                }
                let _ = relay_tcp_shadowsocksr_stream_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    &metrics,
                    &mut encoder,
                    &mut decoder,
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
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
            let binding = selection.proxy.clone();
            let task = tokio::spawn(async move {
                match &binding.plan().handler {
                    ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                        cipher,
                        password,
                        salt_len,
                    } => {
                        let _ = relay_tcp_over_shadowsocks_aead_async(
                            &mut relay_side,
                            &mut stream,
                            relay_stop,
                            &target,
                            cipher,
                            password,
                            *salt_len,
                            Vec::new(),
                            &metrics,
                        )
                        .await;
                    }
                    ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                        cipher,
                        password,
                        salt_len,
                        ..
                    } => {
                        let _ = relay_tcp_over_shadowsocks_2022_async(
                            &mut relay_side,
                            &mut stream,
                            relay_stop,
                            &target,
                            cipher,
                            password,
                            *salt_len,
                            Vec::new(),
                            &metrics,
                        )
                        .await;
                    }
                    ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
                        cipher,
                        password,
                        salt_len,
                        host,
                        path,
                    } => {
                        let _ = relay_tcp_over_shadowsocks_simple_obfs_http_async(
                            &mut relay_side,
                            &mut stream,
                            relay_stop,
                            &target,
                            cipher,
                            password,
                            *salt_len,
                            Vec::new(),
                            &metrics,
                            host,
                            path,
                        )
                        .await;
                    }
                    ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
                        cipher,
                        password,
                        salt_len,
                        host,
                    } => {
                        let _ = relay_tcp_over_shadowsocks_simple_obfs_tls_async(
                            &mut relay_side,
                            &mut stream,
                            relay_stop,
                            &target,
                            cipher,
                            password,
                            *salt_len,
                            Vec::new(),
                            &metrics,
                            host,
                        )
                        .await;
                    }
                    ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
                        cipher,
                        password,
                        salt_len,
                        host,
                        path,
                    } => {
                        let _ = relay_tcp_over_shadowsocks_2022_simple_obfs_http_async(
                            &mut relay_side,
                            &mut stream,
                            relay_stop,
                            &target,
                            cipher,
                            password,
                            *salt_len,
                            Vec::new(),
                            &metrics,
                            host,
                            path,
                        )
                        .await;
                    }
                    _ => {}
                }
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

async fn open_shadowsocks_v2ray_plugin_native_tcp_tunnel(
    selection: super::super::super::tcp::TcpProxySelection,
    target: String,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let mut client = open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    let ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { host, path, .. } =
        &selection.proxy.handler
    else {
        return Err(NativeTcpProbeError::NotAdmitted);
    };
    let options = HttpUpgradeOptions::new(host, path);
    native_websocket_handshake_over_resident_tls_async(&mut client, &options)
        .await
        .map_err(NativeTcpProbeError::Open)?;

    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let tunnel_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let binding = selection.proxy.clone();
    let task = tokio::spawn(async move {
        if let ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
            cipher,
            password,
            salt_len,
            ..
        } = &binding.plan().handler
        {
            let _ = relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws(
                &mut relay_side,
                &mut client,
                relay_stop,
                &target,
                cipher,
                password,
                *salt_len,
                Vec::new(),
                &metrics,
            )
            .await;
        }
        stop.store(true, Ordering::Relaxed);
    });
    Ok(Box::new(SpawnedNativeTcpTunnel::new(
        probe,
        task,
        tunnel_stop,
    )))
}
