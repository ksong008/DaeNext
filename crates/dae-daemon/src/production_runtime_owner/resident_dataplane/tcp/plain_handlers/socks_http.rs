use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_socks5_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection.proxy).await?;
    socks5_connect_async(&mut proxy, &selection.route.dial_target, username, password).await?;
    relay_tcp_direct_async(inbound, &mut proxy, stop, &sniff.payload, metrics)
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
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection.proxy).await?;
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
    relay_tcp_direct_async(inbound, &mut proxy, stop, &sniff.payload, metrics)
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

pub(crate) async fn handle_https_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<Value, String> {
    let mut proxy = open_async_resident_tls_client(&selection.proxy).await?;
    let tls_underlay = async_resident_tls_underlay_name(&proxy);
    http_proxy_connect_async(
        &mut proxy,
        &selection.route.dial_target,
        username,
        password,
        transport,
        transport_host,
        transport_path,
    )
    .await?;
    if !sniff.payload.is_empty() {
        proxy
            .write_plain_all(&sniff.payload, "write HTTPS proxy initial payload")
            .await?;
        metrics.add_upload(sniff.payload.len());
    }
    relay_tcp_over_resident_tls_plain_async(inbound, &mut proxy, stop, metrics)
        .await
        .map(|mut stats| {
            stats.client_to_direct += sniff.payload.len();
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
) -> Result<(), String> {
    let mut options = HttpConnectOptions::connect(target);
    options.username = username.to_owned();
    options.password = password.to_owned();
    options.transport.enabled = transport;
    options.host_override = transport_host.to_owned();
    options.transport.path = transport_path.to_owned();
    let request = http_request::connect_request(&options);
    stream
        .write_plain_all(&request, "write HTTPS proxy CONNECT request")
        .await?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.read_plain(&mut buf))
            .await
            .map_err(|_| "read HTTPS proxy CONNECT response timeout".to_owned())?
            .map_err(|err| format!("read HTTPS proxy CONNECT response: {err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err("HTTPS proxy CONNECT response too large".to_owned());
        }
    }
    let status = http_request::parse_connect_response(&response)
        .map_err(|err| format!("parse HTTPS proxy CONNECT response: {err}"))?;
    if status != 200 {
        return Err(format!("HTTPS proxy CONNECT status: {status}"));
    }
    Ok(())
}
