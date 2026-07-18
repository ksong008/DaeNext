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
use super::super::Hysteria2OwnerRegistryHandle;
use super::super::plan::{ResidentProxyPlan, ResidentTcpProbeDispatch};
use super::super::tcp::QuicEndpointCallerClass;

#[allow(clippy::too_many_arguments)]
pub(in crate::production_runtime_owner::resident_dataplane) async fn probe_native_proxy_tcp_async(
    proxy: Arc<ResidentProxyPlan>,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
) -> Result<(), String> {
    let owner_deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(std::time::Instant::now(), timeout);
    let probe = async {
        match open_native_tcp_tunnel(
            Arc::clone(&proxy),
            target,
            hysteria2_owner_registry,
            caller,
            owner_deadline,
        )
        .await
        {
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
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
    owner_deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    match proxy.execution_plan().protocol.probe_dispatch() {
        ResidentTcpProbeDispatch::Basic => open_basic_native_tcp_tunnel(proxy, target).await,
        ResidentTcpProbeDispatch::Vless => open_vless_native_tcp_tunnel(proxy, target).await,
        ResidentTcpProbeDispatch::Vmess => open_vmess_native_tcp_tunnel(proxy, target).await,
        ResidentTcpProbeDispatch::Trojan => open_trojan_native_tcp_tunnel(proxy, target).await,
        ResidentTcpProbeDispatch::AnyTls => open_frame_tls_native_tcp_tunnel(proxy, target).await,
        ResidentTcpProbeDispatch::Shadowsocks => {
            open_shadowsocks_native_tcp_tunnel(proxy, target).await
        }
        ResidentTcpProbeDispatch::Quic => {
            open_quic_stream_native_tcp_tunnel(
                proxy,
                target,
                hysteria2_owner_registry,
                caller,
                owner_deadline,
            )
            .await
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
