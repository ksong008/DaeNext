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

pub(super) async fn wait_anytls_udp_synack_async(
    client: &mut AsyncResidentTlsClient,
) -> Result<(), String> {
    loop {
        let frame = read_anytls_frame_async(client).await?;
        if frame.cmd == anytls_contract::CMD_SYNACK && frame.sid == 1 && frame.data.is_empty() {
            return Ok(());
        }
        if frame.cmd == anytls_contract::CMD_ALERT {
            return Err(format!(
                "AnyTLS UDP alert before SYNACK: {} bytes",
                frame.data.len()
            ));
        }
        if matches!(
            frame.cmd,
            anytls_contract::CMD_WASTE
                | anytls_contract::CMD_SERVER_SETTINGS
                | anytls_contract::CMD_UPDATE_PADDING
                | anytls_contract::CMD_HEART_RESPONSE
        ) {
            continue;
        }
        return Err(format!(
            "unexpected AnyTLS UDP frame before SYNACK: cmd={} sid={} len={}",
            frame.cmd,
            frame.sid,
            frame.data.len()
        ));
    }
}

pub(super) async fn read_anytls_frame_async(
    client: &mut AsyncResidentTlsClient,
) -> Result<AnyTlsRuntimeFrame, String> {
    let mut header = [0_u8; anytls_contract::HEADER_OVERHEAD_SIZE];
    read_async_tls_plain_exact(client, &mut header, "read AnyTLS UDP frame header").await?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0_u8; len];
    read_async_tls_plain_exact(client, &mut data, "read AnyTLS UDP frame data").await?;
    Ok(AnyTlsRuntimeFrame {
        cmd: header[0],
        sid: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        data,
    })
}

pub(super) struct AnyTlsRuntimeFrame {
    pub(super) cmd: u8,
    pub(super) sid: u32,
    pub(super) data: Vec<u8>,
}

pub(super) async fn read_async_tls_plain_exact(
    client: &mut AsyncResidentTlsClient,
    mut out: &mut [u8],
    label: &str,
) -> Result<(), String> {
    let started = Instant::now();
    while !out.is_empty() {
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err(format!("{label}: timeout"));
        }
        match time::timeout(RESIDENT_IDLE_SLEEP, client.read_plain(out)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(read)) => {
                let tmp = out;
                out = &mut tmp[read..];
            }
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Ok(Err(err)) => return Err(format!("{label}: {err}")),
            Err(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
