use super::*;

pub(super) fn proxy_server_authority(proxy: &ResidentProxyPlan) -> String {
    format!("{}:{}", proxy.server_host, proxy.server_port)
}

pub(super) async fn resolve_proxy_udp_socket_addr_async(
    proxy: &ResidentProxyPlan,
) -> Result<SocketAddr, String> {
    let authority = proxy_server_authority(proxy);
    tokio::net::lookup_host(authority.as_str())
        .await
        .map_err(|err| format!("resolve UDP proxy {authority}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve UDP proxy {authority}: no address"))
}

pub(super) async fn socks5_udp_relay_addr_async(
    proxy: &ResidentProxyPlan,
    bind: &str,
) -> Result<SocketAddr, String> {
    let parsed =
        Socks5Address::parse(bind).map_err(|err| format!("parse SOCKS5 UDP bind: {err}"))?;
    let port = parsed.port();
    if port == 0 {
        return Err("SOCKS5 UDP associate returned port 0".to_owned());
    }
    let host = parsed.host();
    let authority = if host == "0.0.0.0" || host == "::" || host.is_empty() {
        format!("{}:{port}", proxy.server_host)
    } else {
        parsed.authority()
    };
    tokio::net::lookup_host(authority.as_str())
        .await
        .map_err(|err| format!("resolve SOCKS5 UDP relay {authority}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve SOCKS5 UDP relay {authority}: no address"))
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

pub(super) async fn read_async_tls_plain_until<T, F>(
    client: &mut AsyncResidentTlsClient,
    label: &str,
    mut decode: F,
) -> Result<T, String>
where
    F: FnMut(&[u8]) -> Result<T, dae_outbound::OutboundError>,
{
    let started = Instant::now();
    let mut plaintext = Vec::new();
    let mut buf = [0_u8; 4096];
    let mut last_decode_error = "no data decoded yet".to_owned();
    loop {
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err(format!(
                "{label}: timeout{}",
                format!(" after decode error: {last_decode_error}")
            ));
        }
        match decode(&plaintext) {
            Ok(value) => return Ok(value),
            Err(err) => last_decode_error = err.to_string(),
        }
        match time::timeout(RESIDENT_IDLE_SLEEP, client.read_plain(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(read)) => plaintext.extend_from_slice(&buf[..read]),
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Ok(Err(err)) => return Err(format!("{label}: {err}")),
            Err(_) => {}
        }
    }
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

pub(super) async fn read_anytls_udp_payload_async(
    client: &mut AsyncResidentTlsClient,
) -> Result<Vec<u8>, String> {
    loop {
        let frame = read_anytls_frame_async(client).await?;
        if frame.cmd == anytls_contract::CMD_PSH && frame.sid == 1 {
            let packet = dae_outbound::anytls::decode_packet_next_write(&frame.data)
                .map_err(|err| format!("decode AnyTLS UDP response packet: {err}"))?;
            return Ok(packet.payload);
        }
        if frame.cmd == anytls_contract::CMD_ALERT {
            return Err(format!(
                "AnyTLS UDP alert frame: {} bytes",
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
            "unexpected AnyTLS UDP response frame: cmd={} sid={} len={}",
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
