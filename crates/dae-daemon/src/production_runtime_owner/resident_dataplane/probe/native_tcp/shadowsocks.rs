use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use dae_outbound::shared_transport::HttpUpgradeOptions;

use super::super::super::client::open_async_resident_tls_client_with_flow;
use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::super::{
    ResidentDataplaneMetrics,
    tcp::{
        native_websocket_handshake_over_resident_tls_async, open_plain_proxy_tcp_stream_async,
        relay_tcp_over_shadowsocks_2022_async,
        relay_tcp_over_shadowsocks_2022_simple_obfs_http_async,
        relay_tcp_over_shadowsocks_aead_async, relay_tcp_over_shadowsocks_simple_obfs_http_async,
        relay_tcp_over_shadowsocks_simple_obfs_tls_async,
        relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_shadowsocks_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(Arc::clone(&proxy), target);
    if let ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
        cipher,
        password,
        salt_len,
        host,
        path,
    } = selection.proxy.handler.clone()
    {
        return open_shadowsocks_v2ray_plugin_native_tcp_tunnel(
            proxy,
            target.to_owned(),
            cipher,
            password,
            salt_len,
            host,
            path,
        )
        .await;
    }
    let mut stream = open_plain_proxy_tcp_stream_async(&selection)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = Arc::new(AtomicBool::new(false));
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let target = target.to_owned();

    match selection.proxy.handler.clone() {
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher,
            password,
            salt_len,
        } => {
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_shadowsocks_aead_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    &target,
                    &cipher,
                    &password,
                    salt_len,
                    &[],
                    &metrics,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
            cipher,
            password,
            salt_len,
            ..
        } => {
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_shadowsocks_2022_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    &target,
                    &cipher,
                    &password,
                    salt_len,
                    &[],
                    &metrics,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => {
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_shadowsocks_simple_obfs_http_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    &target,
                    &cipher,
                    &password,
                    salt_len,
                    &[],
                    &metrics,
                    &host,
                    &path,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
            cipher,
            password,
            salt_len,
            host,
        } => {
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_shadowsocks_simple_obfs_tls_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    &target,
                    &cipher,
                    &password,
                    salt_len,
                    &[],
                    &metrics,
                    &host,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
        ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => {
            let task = tokio::spawn(async move {
                let _ = relay_tcp_over_shadowsocks_2022_simple_obfs_http_async(
                    &mut relay_side,
                    &mut stream,
                    relay_stop,
                    &target,
                    &cipher,
                    &password,
                    salt_len,
                    &[],
                    &metrics,
                    &host,
                    &path,
                )
                .await;
                stop.store(true, Ordering::Relaxed);
            });
            Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
        }
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}

async fn open_shadowsocks_v2ray_plugin_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: String,
    cipher: String,
    password: String,
    salt_len: usize,
    host: String,
    path: String,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, &target);
    let mut client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    let options = HttpUpgradeOptions::new(&host, &path);
    native_websocket_handshake_over_resident_tls_async(&mut client, &options)
        .await
        .map_err(NativeTcpProbeError::Open)?;

    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = Arc::new(AtomicBool::new(false));
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let task = tokio::spawn(async move {
        let _ = relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws(
            &mut relay_side,
            &mut client,
            relay_stop,
            &target,
            &cipher,
            &password,
            salt_len,
            &[],
            &metrics,
        )
        .await;
        stop.store(true, Ordering::Relaxed);
    });
    Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
}
