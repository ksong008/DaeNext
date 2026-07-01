use std::sync::Arc;

use super::super::super::client::open_async_resident_tls_client_with_flow;
use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::super::tcp::{
    http_proxy_connect_async, http_proxy_connect_plain_async, open_plain_proxy_tcp_stream_async,
    socks5_connect_async,
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::NativeTcpTunnel;

pub(super) async fn open_basic_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            let mut stream = open_plain_proxy_tcp_stream_async(&selection)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            socks5_connect_async(&mut stream, target, username, password)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            Ok(Box::new(stream))
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username,
            password,
            transport,
            transport_host,
            transport_path,
        } if selection.proxy.tls == "none" => {
            let mut stream = open_plain_proxy_tcp_stream_async(&selection)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            http_proxy_connect_plain_async(
                &mut stream,
                target,
                username,
                password,
                *transport,
                transport_host,
                transport_path,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            Ok(Box::new(stream))
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username,
            password,
            transport,
            transport_host,
            transport_path,
        } if selection.proxy.tls == "tls" => {
            let mut stream = open_async_resident_tls_client_with_flow(
                &selection.proxy,
                selection.mark,
                selection.mptcp,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            http_proxy_connect_async(
                &mut stream,
                target,
                username,
                password,
                *transport,
                transport_host,
                transport_path,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            Ok(Box::new(stream))
        }
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}
