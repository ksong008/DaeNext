use super::super::super::client::open_async_resident_tls_client_with_binding;
use super::super::super::plan::{
    ResidentProxyBinding, ResidentProxyProtocolPlan, ResidentSecurityUnderlayPlan,
};
use super::super::super::tcp::{
    http_proxy_connect_async, http_proxy_connect_plain_async, open_plain_proxy_tcp_stream_async,
    socks5_connect_async,
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, PrefixedNativeTcpTunnel, boxed_native_tcp_tunnel};

pub(super) async fn open_basic_native_tcp_tunnel(
    binding: ResidentProxyBinding,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(binding, target);
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            let mut stream = open_plain_proxy_tcp_stream_async(&selection)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            socks5_connect_async(&mut stream, target, username, password)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            Ok(boxed_native_tcp_tunnel(stream))
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username,
            password,
            transport,
            transport_host,
            transport_path,
        } if selection.proxy.execution_plan().security == ResidentSecurityUnderlayPlan::None => {
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
            Ok(boxed_native_tcp_tunnel(stream))
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username,
            password,
            transport,
            transport_host,
            transport_path,
        } if selection.proxy.execution_plan().security.is_tls_stream() => {
            let mut stream =
                open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp)
                    .await
                    .map_err(NativeTcpProbeError::Open)?;
            let response_leftover = http_proxy_connect_async(
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
            Ok(boxed_native_tcp_tunnel(PrefixedNativeTcpTunnel::new(
                response_leftover,
                stream,
            )))
        }
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}
