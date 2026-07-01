use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use super::super::client::open_async_resident_tls_client_with_flow;
use super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::tcp::{
    TcpProxySelection, TcpRouteSelection, TcpRoutingLogMetadata, http_proxy_connect_async,
    http_proxy_connect_plain_async, open_plain_proxy_tcp_stream_async,
    probe_resident_proxy_tcp_async, socks5_connect_async,
};
use super::{
    read_resident_tcp_probe_https_response_over_stream_async,
    read_resident_tcp_probe_response_async, resident_tcp_probe_http_request,
};

pub(crate) trait NativeTcpTunnel: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NativeTcpTunnel for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

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

async fn probe_native_tcp_tunnel(
    tunnel: &mut dyn NativeTcpTunnel,
    scheme: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    match scheme {
        "http" => {
            let request = resident_tcp_probe_http_request(method, path, host);
            tokio::time::timeout(
                timeout,
                tokio::io::AsyncWriteExt::write_all(tunnel, &request),
            )
            .await
            .map_err(|_| "write native TCP probe HTTP request: timeout".to_owned())?
            .map_err(|err| format!("write native TCP probe HTTP request: {err}"))?;
            tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::flush(tunnel))
                .await
                .map_err(|_| "flush native TCP probe HTTP request: timeout".to_owned())?
                .map_err(|err| format!("flush native TCP probe HTTP request: {err}"))?;
            read_resident_tcp_probe_response_async(tunnel, path, timeout).await
        }
        "https" => {
            read_resident_tcp_probe_https_response_over_stream_async(
                tunnel, host, path, method, timeout,
            )
            .await
        }
        other => Err(format!("native TCP probe unsupported scheme: {other}")),
    }
}

fn native_tcp_probe_selection(proxy: Arc<ResidentProxyPlan>, target: &str) -> TcpProxySelection {
    TcpProxySelection {
        mark: proxy.mark,
        mptcp: proxy.mptcp,
        route: TcpRouteSelection {
            initial_outbound: 0,
            final_outbound: 0,
            final_mark: proxy.mark,
            userspace_route_executed: false,
            userspace_route_must: false,
            dial_target: target.to_owned(),
            dial_ip: false,
            log_metadata: TcpRoutingLogMetadata {
                pid: 0,
                dscp: 0,
                pname: String::new(),
                mac: String::new(),
            },
        },
        proxy,
    }
}

enum NativeTcpProbeError {
    NotAdmitted,
    Open(String),
}
