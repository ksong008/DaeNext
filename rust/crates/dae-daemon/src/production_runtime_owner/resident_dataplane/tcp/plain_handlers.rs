#[allow(clippy::too_many_arguments)]
fn handle_socks5_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    socks5_connect(&mut proxy, &selection.route.dial_target, username, password)?;
    proxy
        .set_nonblocking(true)
        .map_err(|err| format!("set SOCKS5 proxy TCP nonblocking: {err}"))?;
    inbound
        .set_nonblocking(true)
        .map_err(|err| format!("set inbound TCP nonblocking after SOCKS5 handshake: {err}"))?;
    relay_tcp_direct(inbound, &mut proxy, stop, &sniff.payload, metrics)
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
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
                selection,
                sniff,
                "socks5",
                &err,
                "plain-tcp-relay",
            ))
        })
}
fn handle_http_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    http_proxy_connect(
        &mut proxy,
        &selection.route.dial_target,
        username,
        password,
        transport,
        transport_host,
        transport_path,
    )?;
    proxy
        .set_nonblocking(true)
        .map_err(|err| format!("set HTTP proxy TCP nonblocking: {err}"))?;
    inbound
        .set_nonblocking(true)
        .map_err(|err| format!("set inbound TCP nonblocking after HTTP proxy CONNECT: {err}"))?;
    relay_tcp_direct(inbound, &mut proxy, stop, &sniff.payload, metrics)
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
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
                selection,
                sniff,
                "http-proxy",
                &err,
                "plain-tcp-relay",
            ))
        })
}
async fn handle_https_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
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

async fn http_proxy_connect_async(
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
fn handle_shadowsocks_proxy_tcp_connection(
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
fn handle_shadowsocks_2022_proxy_tcp_connection(
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
fn handle_shadowsocks_simple_obfs_http_proxy_tcp_connection(
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
    host: &str,
    path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set Shadowsocks simple-obfs proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs inbound write timeout: {err}"))?;
    let stats = relay_tcp_over_shadowsocks_simple_obfs_http(
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
                selection,
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
fn handle_shadowsocks_simple_obfs_tls_proxy_tcp_connection(
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
    host: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set Shadowsocks simple-obfs TLS proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs TLS proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs TLS proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs TLS inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs TLS inbound write timeout: {err}"))?;
    let stats = relay_tcp_over_shadowsocks_simple_obfs_tls(
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
                selection,
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
fn handle_shadowsocks_2022_simple_obfs_http_proxy_tcp_connection(
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
    host: &str,
    path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set Shadowsocks 2022 simple-obfs proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 simple-obfs proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 simple-obfs proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 simple-obfs inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks 2022 simple-obfs inbound write timeout: {err}"))?;
    let stats = relay_tcp_over_shadowsocks_2022_simple_obfs_http(
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
                selection,
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

#[allow(clippy::too_many_arguments)]
async fn handle_shadowsocks_v2ray_plugin_tls_ws_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
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
    let mut client = open_async_resident_tls_client(&selection.proxy).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options = HttpUpgradeOptions::new(host, path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let stats = relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws(
        inbound,
        &mut client,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
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
                "plugin-wrapper-tls-websocket-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["plugin_wrapper"] = json!("v2ray-plugin-tls-websocket");
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-tls-websocket-aead",
                "shadowsocks",
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
                "shadowsocks",
                &err,
                "plugin-wrapper-tls-websocket-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["plugin_wrapper"] = json!("v2ray-plugin-tls-websocket");
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-tls-websocket-aead",
                "shadowsocks",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}
