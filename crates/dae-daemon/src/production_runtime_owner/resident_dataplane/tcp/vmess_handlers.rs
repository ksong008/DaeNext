use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess AEAD TCP session: {err}"))?;
    proxy
        .write_all(&session.first_write)
        .await
        .map_err(|err| format!("write VMess AEAD TCP initial request: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_aead_async(inbound, &mut proxy, stop, session, initial_stats, metrics)
        .await
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &stats,
                "aead-tcp-relay",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &err,
                "aead-tcp-relay",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_tls_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess TLS AEAD TCP session: {err}"))?;
    client
        .write_plain_all(
            &session.first_write,
            "write VMess TLS AEAD TCP initial request",
        )
        .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_tls_aead_async(inbound, &mut client, stop, session, initial_stats, metrics)
        .await
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &stats,
                "aead-tls-tcp-relay",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "aead-tls-tcp-relay",
                "vmess",
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
                "vmess",
                &err,
                "aead-tls-tcp-relay",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "aead-tls-tcp-relay",
                "vmess",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_websocket_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_async_stream(&mut proxy, &options).await?;
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess WebSocket AEAD TCP session: {err}"))?;
    write_websocket_binary_frame_to_async_stream(
        &mut proxy,
        &session.first_write,
        "write VMess websocket request",
    )
    .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_websocket_aead_async(
        inbound,
        &mut proxy,
        stop,
        session,
        initial_stats,
        metrics,
    )
    .await
    .map(|stats| {
        let mut event = generic_proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "vmess",
            &stats,
            "wrapped-websocket-aead",
        );
        event["stream_wrapper"] = json!("websocket");
        event
    })
    .or_else(|err| {
        let mut event = generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "vmess",
            &err,
            "wrapped-websocket-aead",
        );
        event["stream_wrapper"] = json!("websocket");
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_httpupgrade_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_async_stream(&mut proxy, &options).await?;
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess HTTP Upgrade AEAD TCP session: {err}"))?;
    proxy
        .write_all(&session.first_write)
        .await
        .map_err(|err| format!("write VMess HTTP Upgrade request: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_aead_async(inbound, &mut proxy, stop, session, initial_stats, metrics)
        .await
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &stats,
                "wrapped-httpupgrade-aead",
            );
            event["stream_wrapper"] = json!("httpupgrade");
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &err,
                "wrapped-httpupgrade-aead",
            );
            event["stream_wrapper"] = json!("httpupgrade");
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_websocket_tls_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess TLS WebSocket AEAD TCP session: {err}"))?;
    write_websocket_binary_frame_over_resident_tls_async(
        &mut client,
        &session.first_write,
        "write VMess TLS websocket request",
    )
    .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_websocket_tls_aead_async(
        inbound,
        &mut client,
        stop,
        session,
        initial_stats,
        metrics,
    )
    .await
    .map(|stats| {
        let mut event = generic_proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "vmess",
            &stats,
            "wrapped-websocket-aead",
        );
        event["tls_underlay"] = json!(tls_underlay);
        event["stream_wrapper"] = json!("websocket");
        append_proxy_tcp_execution_fields(
            &mut event,
            "wrapped-websocket-aead",
            "vmess",
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
            "vmess",
            &err,
            "wrapped-websocket-aead",
        );
        event["tls_underlay"] = json!(tls_underlay);
        event["stream_wrapper"] = json!("websocket");
        append_proxy_tcp_execution_fields(
            &mut event,
            "wrapped-websocket-aead",
            "vmess",
            Some(tls_underlay),
            None,
        );
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_httpupgrade_tls_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess TLS HTTP Upgrade AEAD TCP session: {err}"))?;
    client
        .write_plain_all(&session.first_write, "write VMess TLS HTTP Upgrade request")
        .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_tls_aead_async(inbound, &mut client, stop, session, initial_stats, metrics)
        .await
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &stats,
                "wrapped-httpupgrade-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("httpupgrade");
            append_proxy_tcp_execution_fields(
                &mut event,
                "wrapped-httpupgrade-aead",
                "vmess",
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
                "vmess",
                &err,
                "wrapped-httpupgrade-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("httpupgrade");
            append_proxy_tcp_execution_fields(
                &mut event,
                "wrapped-httpupgrade-aead",
                "vmess",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_grpc_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess gRPC AEAD TCP session: {err}"))?;
    let (mut h2_send, mut h2_recv, connection_task) =
        open_grpc_h2_stream(client, &selection.proxy, &session.first_write).await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    let result = relay_tcp_over_vmess_grpc_h2(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        session,
        initial_stats,
        metrics,
    )
    .await;
    connection_task.abort();
    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &stats,
                "wrapped-grpc-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "wrapped-grpc-aead",
                "vmess",
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
                "vmess",
                &err,
                "wrapped-grpc-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "wrapped-grpc-aead",
                "vmess",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

pub(crate) async fn open_grpc_h2_stream(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    first_payload: &[u8],
) -> Result<
    (
        h2::SendStream<Bytes>,
        h2::RecvStream,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| "gRPC HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("gRPC HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let authority = grpc_authority(proxy);
    let uri = format!(
        "https://{}{}",
        authority,
        grpc_request_path(&proxy.stream_path)
    );
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .header(http::header::USER_AGENT, "dae-rust-native-resident")
        .body(())
        .map_err(|err| format!("build gRPC HTTP/2 request: {err}"))?;
    let (response, send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send gRPC HTTP/2 request headers: {err}"))?;
    let mut send_stream = send_stream;
    send_grpc_hunk(&mut send_stream, first_payload, false).await?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "gRPC HTTP/2 response headers timeout".to_owned())?
        .map_err(|err| format!("read gRPC HTTP/2 response headers: {err}"))?;
    if !response.status().is_success() {
        connection_task.abort();
        return Err(format!("gRPC HTTP/2 response status {}", response.status()));
    }
    Ok((send_stream, response.into_body(), connection_task))
}
