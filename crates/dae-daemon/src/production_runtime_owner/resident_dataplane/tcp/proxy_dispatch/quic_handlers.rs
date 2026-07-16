use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            tls_identity,
            max_rx,
            obfs,
            port_hop_ports,
        } => {
            let auth = auth.clone();
            let tls_identity = tls_identity.clone();
            let max_rx = *max_rx;
            let obfs = obfs.clone();
            let port_hop_ports = port_hop_ports.clone();
            handle_hysteria2_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &auth,
                &tls_identity,
                max_rx,
                &obfs,
                &port_hop_ports,
            )
            .await
        }
        ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid,
            password,
            alpn,
            allow_insecure,
        } => {
            let uuid = uuid.clone();
            let password = password.clone();
            let alpn = alpn.clone();
            let allow_insecure = *allow_insecure;
            handle_tuic_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &uuid,
                &password,
                &alpn,
                allow_insecure,
            )
            .await
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
        } => {
            let uuid = uuid.clone();
            let password = password.clone();
            let allow_insecure = *allow_insecure;
            let pinned_certchain_sha256 = pinned_certchain_sha256.clone();
            handle_juicity_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &uuid,
                &password,
                allow_insecure,
                &pinned_certchain_sha256,
            )
            .await
        }
        _ => Err("QUIC dispatcher received unsupported handler".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_hysteria2_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    auth: &str,
    tls_identity: &dae_outbound::hysteria2::Hysteria2TlsIdentity,
    max_rx: u64,
    obfs: &ResidentHysteria2ObfsPlan,
    port_hop_ports: &[u16],
) -> Result<Value, String> {
    let ResidentConnectedQuicEndpoint {
        remote,
        endpoint,
        connection,
    } = open_hysteria2_quic_connection_candidates_async(
        &selection.proxy,
        selection.mark,
        obfs,
        port_hop_ports,
        tls_identity,
        RESIDENT_CONNECT_TIMEOUT,
        QuicEndpointCallerClass::TcpData,
    )
    .await?;
    let port_hopping = !port_hop_ports.is_empty();
    let auth_session =
        match authenticate_hysteria2_connection(connection.clone(), auth, max_rx).await {
            Ok(session) => session,
            Err(err) => {
                endpoint.mark_failed();
                return Err(format!("authenticate Hysteria2 QUIC connection: {err}"));
            }
        };
    if !auth_session.report().auth_ok {
        endpoint.mark_failed();
        connection.close(0x101_u32.into(), b"resident hysteria2 auth failed");
        let mut event = generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "hysteria2",
            &format!("Hysteria2 auth status {}", auth_session.report().status),
            "async-proxy-quic-tcp",
        );
        event["quic_underlay"] = json!("quinn-h3");
        event["hysteria2_port_hopping"] = json!(port_hopping);
        event["hysteria2_selected_port"] = json!(remote.port());
        append_proxy_tcp_execution_fields(
            &mut event,
            "async-proxy-quic-tcp",
            "hysteria2",
            None,
            Some("quinn-h3"),
        );
        return Ok(event);
    }
    endpoint.mark_ready();
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open Hysteria2 TCP stream: {err}"))?;
    write_hysteria2_tcp_request(&mut send, &selection.route.dial_target)
        .await
        .map_err(|err| format!("write Hysteria2 TCP request: {err}"))?;
    let response = read_hysteria2_tcp_response(&mut recv)
        .await
        .map_err(|err| format!("read Hysteria2 TCP response: {err}"))?;
    if !response.ok {
        connection.close(0x101_u32.into(), b"resident hysteria2 tcp response failed");
        let mut event = generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "hysteria2",
            &format!("Hysteria2 TCP response rejected: {}", response.message),
            "async-proxy-quic-tcp",
        );
        event["quic_underlay"] = json!("quinn-h3");
        event["hysteria2_port_hopping"] = json!(port_hopping);
        event["hysteria2_selected_port"] = json!(remote.port());
        append_proxy_tcp_execution_fields(
            &mut event,
            "async-proxy-quic-tcp",
            "hysteria2",
            None,
            Some("quinn-h3"),
        );
        return Ok(event);
    }
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        send.write_all(&sniff.payload)
            .await
            .map_err(|err| format!("write Hysteria2 initial payload: {err}"))?;
        send.flush()
            .await
            .map_err(|err| format!("flush Hysteria2 initial payload: {err}"))?;
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            connection.close(0_u32.into(), b"resident hysteria2 done");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "hysteria2",
                &stats,
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            event["hysteria2_port_hopping"] = json!(port_hopping);
            event["hysteria2_selected_port"] = json!(remote.port());
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "hysteria2",
                None,
                Some("quinn-h3"),
            );
            event["hysteria2_udp_enabled"] = json!(auth_session.report().udp_enabled);
            Ok(event)
        }
        Err(err) => {
            connection.close(0x101_u32.into(), b"resident hysteria2 relay failed");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "hysteria2",
                &err,
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            event["hysteria2_port_hopping"] = json!(port_hopping);
            event["hysteria2_selected_port"] = json!(remote.port());
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "hysteria2",
                None,
                Some("quinn-h3"),
            );
            event["hysteria2_udp_enabled"] = json!(auth_session.report().udp_enabled);
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tuic_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    uuid: &str,
    password: &str,
    alpn: &[String],
    allow_insecure: bool,
) -> Result<Value, String> {
    let ResidentConnectedQuicEndpoint {
        endpoint,
        connection,
        ..
    } = open_tuic_quic_connection_candidates_async(
        &selection.proxy,
        selection.mark,
        alpn,
        allow_insecure,
        RESIDENT_CONNECT_TIMEOUT,
        QuicEndpointCallerClass::TcpData,
    )
    .await?;
    let auth_report = match authenticate_tuic_connection(&connection, uuid, password).await {
        Ok(report) => report,
        Err(err) => {
            endpoint.mark_failed();
            return Err(format!("authenticate TUIC QUIC connection: {err}"));
        }
    };
    endpoint.mark_ready();
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open TUIC TCP stream: {err}"))?;
    write_tuic_connect_request(&mut send, &selection.route.dial_target)
        .await
        .map_err(|err| format!("write TUIC TCP connect: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        send.write_all(&sniff.payload)
            .await
            .map_err(|err| format!("write TUIC initial payload: {err}"))?;
        send.flush()
            .await
            .map_err(|err| format!("flush TUIC initial payload: {err}"))?;
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            connection.close(0_u32.into(), b"resident tuic done");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "tuic",
                &stats,
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "tuic",
                None,
                Some("quinn"),
            );
            event["tuic_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            Ok(event)
        }
        Err(err) => {
            connection.close(0x101_u32.into(), b"resident tuic relay failed");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "tuic",
                &err,
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "tuic",
                None,
                Some("quinn"),
            );
            event["tuic_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_juicity_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    uuid: &str,
    password: &str,
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
) -> Result<Value, String> {
    let ResidentConnectedQuicEndpoint {
        endpoint,
        connection,
        ..
    } = open_juicity_quic_connection_candidates_async(
        &selection.proxy,
        selection.mark,
        allow_insecure,
        pinned_certchain_sha256,
        RESIDENT_CONNECT_TIMEOUT,
        QuicEndpointCallerClass::TcpData,
    )
    .await?;
    let (auth_report, mut auth_stream) =
        match authenticate_juicity_connection(&connection, uuid, password).await {
            Ok(auth) => auth,
            Err(err) => {
                endpoint.mark_failed();
                return Err(format!("authenticate Juicity QUIC connection: {err}"));
            }
        };
    endpoint.mark_ready();
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open Juicity TCP stream: {err}"))?;
    write_juicity_tcp_request(&mut send, &selection.route.dial_target, &sniff.payload)
        .await
        .map_err(|err| format!("write Juicity TCP request: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            let _ = auth_stream.finish().await;
            connection.close(0_u32.into(), b"resident juicity done");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "juicity",
                &stats,
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "juicity",
                None,
                Some("quinn-h3"),
            );
            event["juicity_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            event["juicity_certchain_pinned"] = json!(!pinned_certchain_sha256.is_empty());
            event["juicity_allow_insecure"] = json!(allow_insecure);
            Ok(event)
        }
        Err(err) => {
            let _ = auth_stream.finish().await;
            connection.close(0x101_u32.into(), b"resident juicity relay failed");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "juicity",
                &err,
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "juicity",
                None,
                Some("quinn-h3"),
            );
            event["juicity_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            event["juicity_certchain_pinned"] = json!(!pinned_certchain_sha256.is_empty());
            event["juicity_allow_insecure"] = json!(allow_insecure);
            Ok(event)
        }
    }
}
