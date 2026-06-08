use super::*;
pub(super) fn resolve_proxy_addr(proxy: &ResidentProxyPlan) -> Result<SocketAddrV4, String> {
    if let Ok(addr) = proxy.server_host.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(addr, proxy.server_port));
    }
    (proxy.server_host.as_str(), proxy.server_port)
        .to_socket_addrs()
        .map_err(|err| {
            format!(
                "resolve VLESS server {}:{}: {err}",
                proxy.server_host, proxy.server_port
            )
        })?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            format!(
                "resolve VLESS server {}:{} returned no IPv4 address",
                proxy.server_host, proxy.server_port
            )
        })
}
