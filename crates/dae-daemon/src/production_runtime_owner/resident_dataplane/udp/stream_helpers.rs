use super::*;

use crate::production_runtime_owner::resident_dataplane::resolve_socket_addr_candidates;

pub(super) fn proxy_server_authority(proxy: &ResidentProxyPlan) -> String {
    format!("{}:{}", proxy.server_host, proxy.server_port)
}

pub(super) async fn resolve_proxy_udp_socket_addr_candidates_async(
    proxy: &ResidentProxyPlan,
) -> Result<Vec<SocketAddr>, String> {
    let authority = proxy_server_authority(proxy);
    resolve_socket_addr_candidates(
        &authority,
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        "resolve UDP proxy",
    )
    .await
}

pub(super) async fn socks5_udp_relay_addr_candidates_async(
    bind: &str,
    control_peer: SocketAddr,
) -> Result<Vec<SocketAddr>, String> {
    let parsed =
        Socks5Address::parse(bind).map_err(|err| format!("parse SOCKS5 UDP bind: {err}"))?;
    let port = parsed.port();
    if port == 0 {
        return Err("SOCKS5 UDP associate returned port 0".to_owned());
    }
    let host = parsed.host();
    if host == "0.0.0.0" || host == "::" || host.is_empty() {
        return Ok(vec![SocketAddr::new(control_peer.ip(), port)]);
    }
    let authority = parsed.authority();
    resolve_socket_addr_candidates(
        &authority,
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        "resolve SOCKS5 UDP relay",
    )
    .await
}

pub(super) async fn write_async_tls_plain_all(
    client: &mut AsyncResidentTlsClient,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        client.write_plain_all(payload, label),
    )
    .await
    .map_err(|_| format!("{label} timeout"))?
}

#[cfg(test)]
mod tests;
