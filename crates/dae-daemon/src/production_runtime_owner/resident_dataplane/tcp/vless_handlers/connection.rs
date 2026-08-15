use super::*;
use crate::production_runtime_owner::resident_dataplane::acquire_vless_mux_logical_stream;
use std::borrow::Cow;
pub(crate) async fn handle_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    mut sniff: TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let execution = selection.proxy.execution_plan();
    if execution.wrapper == ResidentStreamWrapperPlan::Mux {
        return handle_vless_mux_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::WebSocket {
        return handle_vless_websocket_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::HttpUpgrade {
        return handle_vless_httpupgrade_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::Grpc {
        return handle_vless_grpc_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::H2 {
        return handle_vless_h2_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::Meek {
        return handle_vless_meek_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if matches!(execution.wrapper, ResidentStreamWrapperPlan::Xhttp(_)) {
        return handle_vless_xhttp_h2_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::None
        && execution.security == ResidentSecurityUnderlayPlan::None
    {
        return handle_vless_plain_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper != ResidentStreamWrapperPlan::None {
        return Err("materialized VLESS wrapper has no TCP executor".to_owned());
    }
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let encryption = selection.proxy.vless_encryption()?;
    let encryption_enabled = encryption.is_some();
    let key = selection.proxy.vless_key()?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    if let Some(encryption) = encryption {
        let mut client = VlessEncryptedStream::handshake(client, encryption)
            .await
            .map_err(|err| format!("VLESS Encryption handshake over TLS: {err}"))?;
        client
            .write_all(&request)
            .await
            .map_err(|err| format!("write VLESS encrypted TCP request over TLS: {err}"))?;
        client
            .flush()
            .await
            .map_err(|err| format!("flush VLESS encrypted TCP request over TLS: {err}"))?;
        drop(request);
        let initial_payload = sniff.take_payload();
        if is_xtls_rprx_vision_flow(&selection.proxy.flow) {
            relay_tcp_over_vless_vision_duplex(
                inbound,
                &mut client,
                stop,
                key,
                initial_payload,
                metrics,
            )
            .await
        } else {
            relay_tcp_over_vless_plain_async(inbound, &mut client, stop, initial_payload, metrics)
                .await
        }
    } else {
        client
            .write_plain_all(&request, "write VLESS TCP request")
            .await?;
        drop(request);
        let initial_payload = sniff.take_payload();
        relay_tcp_over_vless_tls_async(
            inbound,
            &mut client,
            stop,
            &selection.proxy.flow,
            key,
            initial_payload,
            metrics,
        )
        .await
    }
    .map(|stats| {
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            &sniff,
            tls_underlay,
            &stats,
            "async-proxy-tls",
        );
        event["vless_encryption"] = json!(encryption_enabled);
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            &sniff,
            tls_underlay,
            &err,
            "async-proxy-tls",
        );
        event["vless_encryption"] = json!(encryption_enabled);
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_plain_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client = open_proxy_tcp_stream_with_binding(&selection.proxy, selection.mptcp).await?;
    let encryption = selection.proxy.vless_encryption()?;
    let encryption_enabled = encryption.is_some();
    let key = selection.proxy.vless_key()?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS plain TCP request: {err}"))?;
    if let Some(encryption) = encryption {
        let mut client = VlessEncryptedStream::handshake(client, encryption)
            .await
            .map_err(|err| format!("VLESS Encryption handshake: {err}"))?;
        client
            .write_all(&request)
            .await
            .map_err(|err| format!("write VLESS encrypted TCP request: {err}"))?;
        client
            .flush()
            .await
            .map_err(|err| format!("flush VLESS encrypted TCP request: {err}"))?;
        drop(request);
        let initial_payload = sniff.take_payload();
        relay_tcp_over_vless_plain_async(inbound, &mut client, stop, initial_payload, metrics).await
    } else {
        client
            .write_all(&request)
            .await
            .map_err(|err| format!("write VLESS plain TCP request: {err}"))?;
        drop(request);
        let initial_payload = sniff.take_payload();
        relay_tcp_over_vless_plain_async(inbound, &mut client, stop, initial_payload, metrics).await
    }
    .map(|stats| {
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "none",
            &stats,
            "async-proxy-plain",
        );
        event["vless_encryption"] = json!(encryption_enabled);
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "none",
            &err,
            "async-proxy-plain",
        );
        event["vless_encryption"] = json!(encryption_enabled);
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_mux_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let mut logical = acquire_vless_mux_logical_stream(
        selection.proxy.clone(),
        selection.route.dial_target.clone(),
        deadline,
    )
    .await?;
    let encryption_enabled = selection.proxy.vless_encryption()?.is_some();
    let tls_underlay = logical.tls_underlay();
    let mux_sid = logical.sid();
    let physical_instance_id = logical.physical_instance_id();
    let initial_payload = sniff.take_payload();
    relay_tcp_over_vless_mux_stream_async(inbound, &mut logical, stop, initial_payload, metrics)
        .await
        .map(|stats| {
            let mut event = proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                tls_underlay,
                &stats,
                "async-mux-tls",
            );
            event["stream_wrapper"] = json!("mux");
            event["packet_semantics"] = json!("multiplexed-stream");
            event["mux_sid"] = json!(mux_sid);
            event["mux_physical_instance_id"] = json!(physical_instance_id);
            event["vless_encryption"] = json!(encryption_enabled);
            event
        })
        .or_else(|err| {
            let mut event = proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                tls_underlay,
                &err,
                "async-mux-tls",
            );
            event["stream_wrapper"] = json!("mux");
            event["packet_semantics"] = json!("multiplexed-stream");
            event["mux_sid"] = json!(mux_sid);
            event["mux_physical_instance_id"] = json!(physical_instance_id);
            event["vless_encryption"] = json!(encryption_enabled);
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_websocket_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let encryption = selection.proxy.vless_encryption()?;
    let encryption_enabled = encryption.is_some();
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        if encryption.is_some() {
            &[]
        } else {
            &initial_payload
        },
    )
    .map_err(|err| format!("build VLESS WebSocket TCP request: {err}"))?;
    if let Some(encryption) = encryption {
        let logical = spawn_websocket_payload_stream(client);
        let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
            .await
            .map_err(|err| format!("VLESS Encryption websocket handshake: {err}"))?;
        encrypted
            .write_all(&request)
            .await
            .map_err(|err| format!("write VLESS encrypted websocket request: {err}"))?;
        encrypted
            .flush()
            .await
            .map_err(|err| format!("flush VLESS encrypted websocket request: {err}"))?;
        drop(request);
        relay_tcp_over_vless_plain_async(inbound, &mut encrypted, stop, initial_payload, metrics)
            .await
    } else {
        write_websocket_binary_frame_over_resident_tls_async(
            &mut client,
            &request,
            "write VLESS websocket request",
        )
        .await?;
        if initial_payload_len != 0 {
            metrics.add_upload(initial_payload_len);
        }
        drop((request, initial_payload));
        relay_tcp_over_vless_websocket_tls_async(
            inbound,
            &mut client,
            stop,
            initial_payload_len,
            metrics,
        )
        .await
    }
    .map(|stats| {
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-websocket-tls",
        );
        event["stream_wrapper"] = json!("websocket");
        event["vless_encryption"] = json!(encryption_enabled);
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-websocket-tls",
        );
        event["stream_wrapper"] = json!("websocket");
        event["vless_encryption"] = json!(encryption_enabled);
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_httpupgrade_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS HTTP Upgrade TCP request: {err}"))?;
    let initial_payload = sniff.take_payload();
    let encryption = selection.proxy.vless_encryption()?;
    let encryption_enabled = encryption.is_some();
    if let Some(encryption) = encryption {
        let mut encrypted = VlessEncryptedStream::handshake(client, encryption)
            .await
            .map_err(|err| format!("VLESS Encryption HTTP Upgrade handshake: {err}"))?;
        encrypted
            .write_all(&request)
            .await
            .map_err(|err| format!("write VLESS encrypted HTTP Upgrade request: {err}"))?;
        encrypted
            .flush()
            .await
            .map_err(|err| format!("flush VLESS encrypted HTTP Upgrade request: {err}"))?;
        drop(request);
        if is_xtls_rprx_vision_flow(&selection.proxy.flow) {
            relay_tcp_over_vless_vision_duplex(
                inbound,
                &mut encrypted,
                stop,
                key,
                initial_payload,
                metrics,
            )
            .await
        } else {
            relay_tcp_over_vless_plain_async(
                inbound,
                &mut encrypted,
                stop,
                initial_payload,
                metrics,
            )
            .await
        }
    } else {
        client
            .write_plain_all(&request, "write VLESS HTTP Upgrade TCP request")
            .await?;
        drop(request);
        relay_tcp_over_vless_tls_async(
            inbound,
            &mut client,
            stop,
            &selection.proxy.flow,
            key,
            initial_payload,
            metrics,
        )
        .await
    }
    .map(|stats| {
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-httpupgrade-tls",
        );
        event["stream_wrapper"] = json!("httpupgrade");
        event["vless_encryption"] = json!(encryption_enabled);
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-httpupgrade-tls",
        );
        event["stream_wrapper"] = json!("httpupgrade");
        event["vless_encryption"] = json!(encryption_enabled);
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_meek_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let tls_underlay = if selection.proxy.utls_fingerprint.is_some() {
        "boringssl"
    } else {
        "boringssl"
    };
    let key = selection.proxy.vless_key()?;
    let options = meek_options_from_proxy(&selection, peer, original_dst);
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let first_payload = packet::first_write_bytes(
        &key,
        "",
        "tcp",
        &selection.route.dial_target,
        false,
        &initial_payload,
    )
    .map_err(|err| format!("build VLESS Meek TCP request: {err}"))?;
    let mut stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);
    let mut stripper = VlessResponseStripper::default();
    let mut next_body = Some(first_payload);
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut empty_poll_count = 0_usize;
    let mut inbound_buffer = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        let body: Cow<'_, [u8]> = if let Some(body) = next_body.take() {
            Cow::Owned(body)
        } else {
            match time::timeout(
                Duration::from_millis(150),
                inbound.read(&mut inbound_buffer),
            )
            .await
            {
                Ok(Ok(0)) => {
                    inbound_closed = true;
                    Cow::Borrowed(&[])
                }
                Ok(Ok(read)) => {
                    stats.client_to_direct += read;
                    metrics.add_upload(read);
                    last_activity = Instant::now();
                    empty_poll_count = 0;
                    Cow::Borrowed(&inbound_buffer[..read])
                }
                Ok(Err(err)) if is_graceful_stream_close_error(&err) => {
                    inbound_closed = true;
                    Cow::Borrowed(&[])
                }
                Ok(Err(err)) => return Err(format!("read inbound TCP for Meek relay: {err}")),
                Err(_) => Cow::Borrowed(&[]),
            }
        };

        if body.is_empty() {
            empty_poll_count = empty_poll_count.saturating_add(1);
        }
        let response = meek_round_trip_async(&selection.proxy, &options, body.as_ref()).await?;
        let response_payload = stripper.consume(&response)?;
        if !response_payload.is_empty() {
            inbound
                .write_all(&response_payload)
                .await
                .map_err(|err| format!("write Meek response payload to client: {err}"))?;
            stats.direct_to_client += response_payload.len();
            metrics.add_download(response_payload.len());
            last_activity = Instant::now();
            empty_poll_count = 0;
        }
        if inbound_closed && response_payload.is_empty() {
            break;
        }
        if empty_poll_count >= 3 && last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            break;
        }
    }

    let mut event = generic_proxy_tcp_finished_event(
        peer,
        original_dst,
        &selection,
        sniff,
        "vless",
        &stats,
        "async-proxy-meek-tls",
    );
    event["tls_underlay"] = json!(tls_underlay);
    event["stream_wrapper"] = json!("meek");
    event["meek_polling"] = json!(true);
    append_proxy_tcp_execution_fields(
        &mut event,
        "async-proxy-meek-tls",
        "vless",
        Some(tls_underlay),
        None,
    );
    Ok(event)
}
