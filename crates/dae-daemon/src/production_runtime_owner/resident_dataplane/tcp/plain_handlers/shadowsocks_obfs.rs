use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_shadowsocks_simple_obfs_http_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
    host: &str,
    path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let stats = relay_tcp_over_shadowsocks_simple_obfs_http_async(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
        host,
        path,
    )
    .await;
    stats
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &stats,
                "plain-tcp-relay",
            );
            event["plugin_wrapper"] = json!("simple-obfs-http");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plain-tcp-relay",
                "shadowsocks",
                Some("aead"),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &err,
                "plain-tcp-relay",
            );
            event["plugin_wrapper"] = json!("simple-obfs-http");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plain-tcp-relay",
                "shadowsocks",
                Some("aead"),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_shadowsocks_simple_obfs_tls_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
    host: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let stats = relay_tcp_over_shadowsocks_simple_obfs_tls_async(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
        host,
    )
    .await;
    stats
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &stats,
                "plugin-wrapper-aead",
            );
            event["plugin_wrapper"] = json!("simple-obfs-tls");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-aead",
                "shadowsocks",
                Some("aead"),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &err,
                "plugin-wrapper-aead",
            );
            event["plugin_wrapper"] = json!("simple-obfs-tls");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-aead",
                "shadowsocks",
                Some("aead"),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_shadowsocks_2022_simple_obfs_http_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
    host: &str,
    path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let stats = relay_tcp_over_shadowsocks_2022_simple_obfs_http_async(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
        host,
        path,
    )
    .await;
    stats
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &stats,
                "plugin-wrapper-aead-2022",
            );
            event["plugin_wrapper"] = json!("simple-obfs-http");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-aead-2022",
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
                &selection,
                sniff,
                "shadowsocks",
                &err,
                "plugin-wrapper-aead-2022",
            );
            event["plugin_wrapper"] = json!("simple-obfs-http");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-aead-2022",
                "shadowsocks",
                Some("aead-2022"),
                None,
            );
            Ok::<Value, String>(event)
        })
}
