use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_socks5_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    socks5_connect_async(&mut proxy, &selection.route.dial_target, username, password).await?;
    let initial_payload = sniff.take_payload();
    relay_tcp_direct_async(inbound, &mut proxy, stop, initial_payload, metrics)
        .await
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "socks5",
                &stats,
                "plain-tcp-relay",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "socks5",
                &err,
                "plain-tcp-relay",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_http_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    http_proxy_connect_plain_async(
        &mut proxy,
        &selection.route.dial_target,
        username,
        password,
        transport,
        transport_host,
        transport_path,
    )
    .await?;
    let initial_payload = sniff.take_payload();
    relay_tcp_direct_async(inbound, &mut proxy, stop, initial_payload, metrics)
        .await
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "http-proxy",
                &stats,
                "plain-tcp-relay",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "http-proxy",
                &err,
                "plain-tcp-relay",
            ))
        })
}

// HTTPS proxy setup carries proxy auth, transport metadata, sniff context, and metrics.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_https_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<Value, String> {
    let mut proxy =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    dae_outbound::http_proxy::EffectiveHttpProxyApplicationProtocol::Http1
        .validate_negotiated_alpn(proxy.negotiated_alpn())
        .map_err(|err| format!("validate HTTPS proxy negotiated ALPN: {err}"))?;
    let tls_underlay = async_resident_tls_underlay_name(&proxy);
    let response_leftover = http_proxy_connect_async(
        &mut proxy,
        &selection.route.dial_target,
        username,
        password,
        transport,
        transport_host,
        transport_path,
    )
    .await?;
    if !response_leftover.is_empty() {
        inbound
            .write_all(&response_leftover)
            .await
            .map_err(|err| format!("write HTTPS proxy early tunnel payload to client: {err}"))?;
        metrics.add_download(response_leftover.len());
    }
    let response_leftover_len = response_leftover.len();
    drop(response_leftover);
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    if initial_payload_len != 0 {
        proxy
            .write_plain_all(&initial_payload, "write HTTPS proxy initial payload")
            .await?;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);
    relay_tcp_over_resident_tls_plain_async(inbound, &mut proxy, stop, metrics, Vec::new())
        .await
        .map(|mut stats| {
            stats.client_to_direct += initial_payload_len;
            stats.direct_to_client += response_leftover_len;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "http-proxy",
                &stats,
                "async-secure-endpoint-connect",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["secure_endpoint"] = json!(true);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-secure-endpoint-connect",
                "http-proxy",
                Some(tls_underlay),
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
                "http-proxy",
                &err,
                "async-secure-endpoint-connect",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["secure_endpoint"] = json!(true);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-secure-endpoint-connect",
                "http-proxy",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

pub(crate) async fn http_proxy_connect_async(
    stream: &mut AsyncResidentTlsClient,
    target: &str,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<Vec<u8>, String> {
    let mut options = HttpConnectOptions::connect(target);
    options.username = username.to_owned();
    options.password = password.to_owned();
    options.transport.enabled = transport;
    options.host_override = transport_host.to_owned();
    options.transport.path = transport_path.to_owned();
    let request = http_request::connect_request(&options)
        .map_err(|err| format!("build HTTPS proxy CONNECT request: {err}"))?;
    stream
        .write_plain_all(&request, "write HTTPS proxy CONNECT request")
        .await?;
    let (response, leftover) = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        read_http_head_and_leftover_from_async_stream(stream),
    )
    .await
    .map_err(|_| "read HTTPS proxy CONNECT response timeout".to_owned())??;
    let status = http_request::parse_connect_response(&response)
        .map_err(|err| format!("parse HTTPS proxy CONNECT response: {err}"))?;
    if status != 200 {
        return Err(format!("HTTPS proxy CONNECT status: {status}"));
    }
    Ok(leftover)
}
