use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_h2_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let key = selection.proxy.vless_key()?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let initial_chunks = vless_h2_initial_data_chunks(
        &key,
        &selection.proxy.flow,
        &selection.route.dial_target,
        initial_payload,
    )?;
    let (mut h2_send, response_task, carrier_lease) =
        open_h2_body_stream_with_deferred_response(&selection.proxy, initial_chunks, "VLESS H2")
            .await?;
    let tls_underlay = carrier_lease.tls_underlay();
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }

    let result = relay_tcp_over_deferred_h2_body(
        inbound,
        &mut h2_send,
        response_task,
        stop,
        initial_stats,
        metrics,
        true,
        "VLESS H2",
    )
    .await;
    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &stats,
                "async-proxy-h2-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-h2-tls",
                "vless",
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
                "vless",
                &err,
                "async-proxy-h2-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-h2-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

fn vless_h2_initial_data_chunks(
    key: &[u8; 16],
    flow: &str,
    dial_target: &str,
    sniff_payload: Vec<u8>,
) -> Result<Vec<Bytes>, String> {
    let request = packet::first_write_bytes(key, flow, "tcp", dial_target, false, &[])
        .map_err(|err| format!("build VLESS H2 TCP request: {err}"))?;
    let mut chunks = vec![Bytes::from(request)];
    if !sniff_payload.is_empty() {
        chunks.push(Bytes::from(sniff_payload));
    }
    Ok(chunks)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_grpc_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let key = selection.proxy.vless_key()?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &initial_payload,
    )
    .map_err(|err| format!("build VLESS gRPC TCP request: {err}"))?;
    let (mut h2_send, mut h2_recv, carrier_lease) =
        open_grpc_h2_stream(&selection.proxy, &request).await?;
    drop((request, initial_payload));
    let tls_underlay = carrier_lease.tls_underlay();
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }

    let result = relay_tcp_over_grpc_h2(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        initial_stats,
        metrics,
        true,
    )
    .await;
    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &stats,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "vless",
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
                "vless",
                &err,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_xhttp_h2_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let key = selection.proxy.vless_key()?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &initial_payload,
    )
    .map_err(|err| format!("build VLESS xHTTP TCP request: {err}"))?;

    let mut initial_stats = DirectTcpRelayStats::default();
    initial_stats.client_to_direct += initial_payload_len;
    if initial_payload_len != 0 {
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);
    let xhttp_mode = selection.proxy.xhttp_mode;
    let (result, upload_underlay, upload_http_version, download_separate) = match xhttp_mode {
        ResidentXhttpMode::PacketUp => {
            let XhttpPacketUpParts {
                session_id,
                mut upload,
                mut download,
                upload_underlay,
                upload_http_version,
                download_separate,
            } = open_xhttp_packet_up_parts(&selection.proxy, selection.mptcp).await?;
            let result = async {
                let mut seq = 0_u64;
                send_xhttp_packet_up_request(&mut upload, &session_id, seq, Bytes::from(request))
                    .await?;
                seq = seq.saturating_add(1);
                relay_tcp_over_xhttp_packet_up(
                    inbound,
                    &mut upload,
                    &mut download,
                    &session_id,
                    seq,
                    stop,
                    initial_stats,
                    metrics,
                )
                .await
            }
            .await;
            close_xhttp_download_client(download).await;
            close_xhttp_upload_client(upload).await;
            (
                result,
                upload_underlay,
                upload_http_version,
                download_separate,
            )
        }
        ResidentXhttpMode::StreamUp | ResidentXhttpMode::StreamOne => {
            let XhttpStreamParts {
                session_id: _,
                mut upload,
                mut download,
                upload_underlay,
                upload_http_version,
                download_separate,
            } = open_xhttp_stream_parts(&selection.proxy, selection.mptcp, Bytes::from(request))
                .await?;
            let result = relay_tcp_over_xhttp_stream(
                inbound,
                &mut upload,
                &mut download,
                stop,
                initial_stats,
                metrics,
            )
            .await;
            close_xhttp_download_client(download).await;
            close_xhttp_stream_upload_client(upload).await;
            (
                result,
                upload_underlay,
                upload_http_version,
                download_separate,
            )
        }
    };
    let executor_label = match upload_http_version {
        ResidentXhttpHttpVersion::H1 => "async-proxy-xhttp-h1-tls",
        ResidentXhttpHttpVersion::H2 => "async-proxy-xhttp-h2-tls",
        ResidentXhttpHttpVersion::H3 => "async-proxy-xhttp-h3-tls",
    };
    let xhttp_alpn = upload_http_version.alpn_label();

    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &stats,
                executor_label,
            );
            event["tls_underlay"] = json!(upload_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!(xhttp_mode.as_str());
            event["xhttp_alpn"] = json!(xhttp_alpn);
            event["xhttp_download_separate"] = json!(download_separate);
            append_proxy_tcp_execution_fields(
                &mut event,
                executor_label,
                "vless",
                Some(upload_underlay),
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
                "vless",
                &err,
                executor_label,
            );
            event["tls_underlay"] = json!(upload_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!(xhttp_mode.as_str());
            event["xhttp_alpn"] = json!(xhttp_alpn);
            event["xhttp_download_separate"] = json!(download_separate);
            append_proxy_tcp_execution_fields(
                &mut event,
                executor_label,
                "vless",
                Some(upload_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_h2_initial_payload_is_not_coalesced_with_request_header() {
        let key = [7_u8; 16];
        let sniff = b"TLS-client-hello";
        let chunks =
            vless_h2_initial_data_chunks(&key, "", "203.0.113.10:443", sniff.to_vec()).unwrap();
        let coalesced =
            packet::first_write_bytes(&key, "", "tcp", "203.0.113.10:443", false, sniff).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].as_ref(), sniff);
        assert!(coalesced.starts_with(chunks[0].as_ref()));
        assert_eq!(&coalesced[chunks[0].len()..], sniff);
    }
}
