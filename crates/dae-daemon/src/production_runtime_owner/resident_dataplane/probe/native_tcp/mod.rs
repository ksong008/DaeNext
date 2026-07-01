use std::sync::Arc;
use std::time::Duration;

mod basic_tcp;
mod check;
mod errors;
mod target;
mod tunnel;
mod vless;

use self::basic_tcp::open_basic_native_tcp_tunnel;
use self::check::probe_native_tcp_tunnel;
use self::errors::NativeTcpProbeError;
use self::tunnel::NativeTcpTunnel;
use self::vless::open_vless_native_tcp_tunnel;
use super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::tcp::probe_resident_proxy_tcp_async;

pub(in crate::production_runtime_owner::resident_dataplane) async fn probe_native_proxy_tcp_async(
    proxy: Arc<ResidentProxyPlan>,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    match open_native_tcp_tunnel(Arc::clone(&proxy), target).await {
        Ok(mut tunnel) => {
            probe_native_tcp_tunnel(&mut *tunnel, scheme, host, path, method, timeout).await
        }
        Err(NativeTcpProbeError::NotAdmitted) => {
            probe_resident_proxy_tcp_async(proxy, scheme, target, host, path, method, timeout).await
        }
        Err(NativeTcpProbeError::Open(err)) => Err(err),
    }
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
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => {
            open_vless_native_tcp_tunnel(proxy, target).await
        }
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}
