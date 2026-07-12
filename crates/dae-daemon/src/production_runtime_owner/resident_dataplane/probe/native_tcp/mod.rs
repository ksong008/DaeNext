use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

mod basic_tcp;
mod check;
mod errors;
mod frame_tls;
mod quic_stream;
mod shadowsocks;
mod target;
mod trojan;
mod tunnel;
mod vless;
mod vmess;

use self::basic_tcp::open_basic_native_tcp_tunnel;
use self::check::probe_native_tcp_tunnel;
use self::errors::NativeTcpProbeError;
use self::frame_tls::open_frame_tls_native_tcp_tunnel;
use self::quic_stream::open_quic_stream_native_tcp_tunnel;
use self::shadowsocks::open_shadowsocks_native_tcp_tunnel;
use self::trojan::open_trojan_native_tcp_tunnel;
use self::tunnel::NativeTcpTunnel;
use self::vless::open_vless_native_tcp_tunnel;
use self::vmess::open_vmess_native_tcp_tunnel;
use super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};

pub(in crate::production_runtime_owner::resident_dataplane) async fn probe_native_proxy_tcp_async(
    proxy: Arc<ResidentProxyPlan>,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    let probe = async {
        match open_native_tcp_tunnel(Arc::clone(&proxy), target).await {
            Ok(mut tunnel) => {
                probe_native_tcp_tunnel(&mut *tunnel, scheme, host, path, method, timeout).await
            }
            Err(NativeTcpProbeError::NotAdmitted) => Err(format!(
                "native outbound probe not admitted for protocol {} net {} tls {}",
                proxy.protocol, proxy.net, proxy.tls
            )),
            Err(NativeTcpProbeError::Open(err)) => Err(err),
        }
    };
    await_native_tcp_probe_with_timeout(timeout, probe).await
}

async fn await_native_tcp_probe_with_timeout<F>(timeout: Duration, probe: F) -> Result<(), String>
where
    F: Future<Output = Result<(), String>>,
{
    tokio::time::timeout(timeout, probe).await.map_err(|_| {
        format!(
            "native outbound probe timed out after {} ms",
            timeout.as_millis()
        )
    })?
}

async fn open_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    match &proxy.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { .. }
        | ResidentProxyProtocolPlan::HttpProxyTcp { .. } => {
            open_basic_native_tcp_tunnel(proxy, target).await
        }
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
        | ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => {
            open_vless_native_tcp_tunnel(proxy, target).await
        }
        ResidentProxyProtocolPlan::VmessAeadTcp { .. } => {
            open_vmess_native_tcp_tunnel(proxy, target).await
        }
        ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        | ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => {
            open_trojan_native_tcp_tunnel(proxy, target).await
        }
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => {
            open_frame_tls_native_tcp_tunnel(proxy, target).await
        }
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
            open_shadowsocks_native_tcp_tunnel(proxy, target).await
        }
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
        | ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => {
            open_quic_stream_native_tcp_tunnel(proxy, target).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_bounds_the_complete_native_probe_future() {
        let timeout = Duration::from_millis(1);
        let result = await_native_tcp_probe_with_timeout(
            timeout,
            std::future::pending::<Result<(), String>>(),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            "native outbound probe timed out after 1 ms"
        );
    }
}
