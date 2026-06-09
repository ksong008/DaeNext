use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            pin_sha256,
            max_rx,
            port_hop_ports,
        } => {
            let auth = auth.clone();
            let pin_sha256 = pin_sha256.clone();
            let max_rx = *max_rx;
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
                &pin_sha256,
                max_rx,
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
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    auth: &str,
    pin_sha256: &str,
    max_rx: u64,
    port_hop_ports: &[u16],
) -> Result<Value, String> {
    let mut endpoint = open_marked_quic_endpoint(selection.proxy.mark)?;
    endpoint.set_default_client_config(
        build_hysteria2_pinned_client_config(pin_sha256.to_owned())
            .map_err(|err| format!("build Hysteria2 QUIC client config: {err}"))?,
    );
    let remote = resolve_hysteria2_quic_remote_async(&selection.proxy, port_hop_ports).await?;
    let port_hopping = !port_hop_ports.is_empty();
    let connection = endpoint
        .connect(remote, &selection.proxy.server_name)
        .map_err(|err| format!("connect Hysteria2 QUIC endpoint: {err}"))?
        .await
        .map_err(|err| format!("await Hysteria2 QUIC connect: {err}"))?;
    let auth_report = authenticate_hysteria2_connection(connection.clone(), auth, max_rx)
        .await
        .map_err(|err| format!("authenticate Hysteria2 QUIC connection: {err}"))?;
    if !auth_report.auth_ok {
        connection.close(0x101_u32.into(), b"resident hysteria2 auth failed");
        let mut event = generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "hysteria2",
            &format!("Hysteria2 auth status {}", auth_report.status),
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
            event["hysteria2_udp_enabled"] = json!(auth_report.udp_enabled);
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
            event["hysteria2_udp_enabled"] = json!(auth_report.udp_enabled);
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tuic_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    uuid: &str,
    password: &str,
    alpn: &[String],
    allow_insecure: bool,
) -> Result<Value, String> {
    let mut endpoint = open_marked_quic_endpoint(selection.proxy.mark)?;
    endpoint.set_default_client_config(
        build_tuic_runtime_client_config(alpn, allow_insecure)
            .map_err(|err| format!("build TUIC QUIC client config: {err}"))?,
    );
    let remote = resolve_proxy_udp_addr_async(&selection.proxy).await?;
    let connection = endpoint
        .connect(remote, &selection.proxy.server_name)
        .map_err(|err| format!("connect TUIC QUIC endpoint: {err}"))?
        .await
        .map_err(|err| format!("await TUIC QUIC connect: {err}"))?;
    let auth_report = authenticate_tuic_connection(&connection, uuid, password)
        .await
        .map_err(|err| format!("authenticate TUIC QUIC connection: {err}"))?;
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
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    uuid: &str,
    password: &str,
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
) -> Result<Value, String> {
    let mut endpoint = open_marked_quic_endpoint(selection.proxy.mark)?;
    endpoint.set_default_client_config(
        build_juicity_runtime_client_config(allow_insecure, pinned_certchain_sha256)
            .map_err(|err| format!("build Juicity QUIC client config: {err}"))?,
    );
    let remote = resolve_proxy_udp_addr_async(&selection.proxy).await?;
    let connection = endpoint
        .connect(remote, &selection.proxy.server_name)
        .map_err(|err| format!("connect Juicity QUIC endpoint: {err}"))?
        .await
        .map_err(|err| format!("await Juicity QUIC connect: {err}"))?;
    let (auth_report, mut auth_stream) =
        authenticate_juicity_connection(&connection, uuid, password)
            .await
            .map_err(|err| format!("authenticate Juicity QUIC connection: {err}"))?;
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
