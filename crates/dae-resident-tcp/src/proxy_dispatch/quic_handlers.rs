use super::*;
#[allow(clippy::too_many_arguments)]
pub async fn handle_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    mut sniff: TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    hysteria2_owner_registry: Option<&Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<&TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<&JuicityOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { port_hop_ports, .. } => {
            let port_hop_ports = port_hop_ports.clone();
            let hysteria2_owner_registry = hysteria2_owner_registry.ok_or_else(|| {
                "Hysteria2 transport owner registry is unavailable for TCP flow".to_owned()
            })?;
            handle_hysteria2_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                metrics,
                hysteria2_owner_registry,
                owner_deadline,
                &port_hop_ports,
            )
            .await
        }
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => {
            let tuic_owner_registry = tuic_owner_registry.ok_or_else(|| {
                "TUIC transport owner registry is unavailable for TCP flow".to_owned()
            })?;
            handle_tuic_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                metrics,
                tuic_owner_registry,
                owner_deadline,
            )
            .await
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => {
            let juicity_owner_registry = juicity_owner_registry.ok_or_else(|| {
                "Juicity transport owner registry is unavailable for TCP flow".to_owned()
            })?;
            handle_juicity_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                metrics,
                juicity_owner_registry,
                owner_deadline,
            )
            .await
        }
        _ => Err("QUIC dispatcher received unsupported handler".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_hysteria2_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    hysteria2_owner_registry: &Hysteria2OwnerRegistryHandle,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    port_hop_ports: &[u16],
) -> Result<Value, String> {
    let deadline = owner_deadline.unwrap_or_else(|| {
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT)
    });
    let transport = hysteria2_owner_registry
        .acquire(
            selection.proxy.clone(),
            QuicEndpointCallerClass::TcpData,
            deadline,
        )
        .await?;
    let remote = transport.remote();
    let connection = transport.connection();
    let port_hopping = !port_hop_ports.is_empty();
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "Hysteria2 TCP stream setup deadline elapsed".to_owned())?;
    let ((mut send, mut recv), response) = time::timeout(remaining, async {
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
        Ok::<_, String>(((send, recv), response))
    })
    .await
    .map_err(|_| "Hysteria2 TCP stream setup deadline elapsed".to_owned())??;
    if !response.ok {
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
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    if initial_payload_len != 0 {
        send.write_all(&initial_payload)
            .await
            .map_err(|err| format!("write Hysteria2 initial payload: {err}"))?;
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
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
            event["hysteria2_udp_enabled"] = json!(transport.auth_report().udp_enabled);
            Ok(event)
        }
        Err(err) => {
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
            event["hysteria2_udp_enabled"] = json!(transport.auth_report().udp_enabled);
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_tuic_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    tuic_owner_registry: &TuicOwnerRegistryHandle,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> Result<Value, String> {
    let deadline = owner_deadline.unwrap_or_else(|| {
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT)
    });
    let transport = tuic_owner_registry
        .acquire(
            selection.proxy.clone(),
            QuicEndpointCallerClass::TcpData,
            deadline,
        )
        .await?;
    let connection = transport.connection();
    let auth_report = transport.auth_report().clone();
    let remote = transport.remote();
    let congestion = transport.congestion().as_str();
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open TUIC TCP stream: {err}"))?;
    write_tuic_connect_request(&mut send, &selection.route.dial_target)
        .await
        .map_err(|err| format!("write TUIC TCP connect: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    if initial_payload_len != 0 {
        send.write_all(&initial_payload)
            .await
            .map_err(|err| format!("write TUIC initial payload: {err}"))?;
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
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
            event["tuic_congestion"] = json!(congestion);
            event["tuic_remote_family"] = json!(if remote.is_ipv4() { "ipv4" } else { "ipv6" });
            Ok(event)
        }
        Err(err) => {
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
            event["tuic_congestion"] = json!(congestion);
            event["tuic_remote_family"] = json!(if remote.is_ipv4() { "ipv4" } else { "ipv6" });
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_juicity_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    owner_registry: &JuicityOwnerRegistryHandle,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> Result<Value, String> {
    let deadline = owner_deadline.unwrap_or_else(|| {
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT)
    });
    let transport = owner_registry
        .acquire(
            selection.proxy.clone(),
            QuicEndpointCallerClass::TcpData,
            deadline,
        )
        .await?;
    let physical_owner_id = transport.physical_owner_id();
    let auth_token_nonzero = transport.auth_token_nonzero();
    let (allow_insecure, certchain_pinned) = match &selection.proxy.handler {
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            allow_insecure,
            pinned_certchain_sha256,
            ..
        } => (*allow_insecure, !pinned_certchain_sha256.is_empty()),
        _ => return Err("Juicity owner received a non-Juicity TCP selection".to_owned()),
    };
    let (mut send, mut recv) = transport.open_stream(deadline).await?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    write_juicity_tcp_request(&mut send, &selection.route.dial_target, &initial_payload)
        .await
        .map_err(|err| format!("write Juicity TCP request: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
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
            event["juicity_auth_token_nonzero"] = json!(auth_token_nonzero);
            event["juicity_certchain_pinned"] = json!(certchain_pinned);
            event["juicity_allow_insecure"] = json!(allow_insecure);
            event["juicity_physical_owner_id"] = json!(physical_owner_id);
            Ok(event)
        }
        Err(err) => {
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
            event["juicity_auth_token_nonzero"] = json!(auth_token_nonzero);
            event["juicity_certchain_pinned"] = json!(certchain_pinned);
            event["juicity_allow_insecure"] = json!(allow_insecure);
            event["juicity_physical_owner_id"] = json!(physical_owner_id);
            Ok(event)
        }
    }
}
