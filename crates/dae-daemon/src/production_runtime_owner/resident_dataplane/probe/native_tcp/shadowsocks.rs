use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::super::{
    ResidentDataplaneMetrics,
    tcp::{
        open_plain_proxy_tcp_stream_async, relay_tcp_over_shadowsocks_2022_async,
        relay_tcp_over_shadowsocks_aead_async,
    },
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_shadowsocks_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    let mut stream = open_plain_proxy_tcp_stream_async(&selection)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = Arc::new(AtomicBool::new(false));
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let target = target.to_owned();

    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher,
            password,
            salt_len,
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
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
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
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
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}
