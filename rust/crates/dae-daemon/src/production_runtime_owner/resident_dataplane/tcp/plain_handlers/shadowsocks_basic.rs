use super::*;
pub(crate) fn handle_shadowsocks_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set Shadowsocks proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks inbound write timeout: {err}"))?;
    let stats = relay_tcp_over_shadowsocks_aead(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
    );
    stats
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &stats,
                "plain-tcp-relay",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &err,
                "plain-tcp-relay",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_shadowsocks_2022_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set Shadowsocks 2022 proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 inbound write timeout: {err}"))?;
    let stats = relay_tcp_over_shadowsocks_2022(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
    );
    stats
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &stats,
                "shadowsocks-2022-tcp",
            );
            append_proxy_tcp_execution_fields(
                &mut event,
                "shadowsocks-2022-tcp",
                "shadowsocks",
                Some("aead-2022"),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &err,
                "shadowsocks-2022-tcp",
            );
            append_proxy_tcp_execution_fields(
                &mut event,
                "shadowsocks-2022-tcp",
                "shadowsocks",
                Some("aead-2022"),
                None,
            );
            Ok::<Value, String>(event)
        })
}
