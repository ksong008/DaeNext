use super::*;

fn take_vmess_tcp_session(
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
    target: &str,
    sniff: &mut TcpSniffReport,
    build_context: &str,
) -> Result<(VMessAeadTcpClientSessionStart, usize), String> {
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let session = dae_outbound::vmess::aead_tcp_client_session_start_with_security(
        id,
        target,
        &initial_payload,
        body_security,
    )
    .map_err(|err| format!("{build_context}: {err}"))?;
    drop(initial_payload);
    Ok((session, initial_payload_len))
}

fn discard_vmess_first_write(session: &mut VMessAeadTcpClientSessionStart) {
    drop(std::mem::take(&mut session.first_write));
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess AEAD TCP session",
    )?;
    proxy
        .write_all(&session.first_write)
        .await
        .map_err(|err| format!("write VMess AEAD TCP initial request: {err}"))?;
    discard_vmess_first_write(&mut session);
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
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
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess TLS AEAD TCP session",
    )?;
    client
        .write_plain_all(
            &session.first_write,
            "write VMess TLS AEAD TCP initial request",
        )
        .await?;
    discard_vmess_first_write(&mut session);
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
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
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_async_stream(&mut proxy, &options).await?;
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess WebSocket AEAD TCP session",
    )?;
    write_websocket_binary_frame_to_async_stream(
        &mut proxy,
        &session.first_write,
        "write VMess websocket request",
    )
    .await?;
    discard_vmess_first_write(&mut session);
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
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
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_async_stream(&mut proxy, &options).await?;
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess HTTP Upgrade AEAD TCP session",
    )?;
    proxy
        .write_all(&session.first_write)
        .await
        .map_err(|err| format!("write VMess HTTP Upgrade request: {err}"))?;
    discard_vmess_first_write(&mut session);
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
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
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess TLS WebSocket AEAD TCP session",
    )?;
    write_websocket_binary_frame_over_resident_tls_async(
        &mut client,
        &session.first_write,
        "write VMess TLS websocket request",
    )
    .await?;
    discard_vmess_first_write(&mut session);
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
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
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess TLS HTTP Upgrade AEAD TCP session",
    )?;
    client
        .write_plain_all(&session.first_write, "write VMess TLS HTTP Upgrade request")
        .await?;
    discard_vmess_first_write(&mut session);
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
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
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess gRPC AEAD TCP session",
    )?;
    let (mut h2_send, mut h2_recv, carrier_lease) =
        open_grpc_h2_stream(&selection.proxy, &session.first_write).await?;
    discard_vmess_first_write(&mut session);
    let tls_underlay = carrier_lease.tls_underlay();
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_vmess_h2_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess H2 AEAD TCP session",
    )?;
    let (mut h2_send, mut h2_recv, carrier_lease) =
        open_h2_body_stream(&selection.proxy, &session.first_write, "VMess H2").await?;
    discard_vmess_first_write(&mut session);
    let tls_underlay = carrier_lease.tls_underlay();
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }

    let result = relay_tcp_over_vmess_h2_body(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        session,
        initial_stats,
        metrics,
    )
    .await;
    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &stats,
                "wrapped-h2-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "wrapped-h2-aead",
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
                "wrapped-h2-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "wrapped-h2-aead",
                "vmess",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}
