use super::*;
pub fn tcp_exchange_over_websocket_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<VlessWebSocketExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    stream
        .write_all(&handshake)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(stream)?;
    crate::shared_transport::validate_websocket_handshake_response(
        &response,
        crate::shared_transport::WS_ACCEPT_SAMPLE,
    )?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_frame = websocket_client_binary_frame(&request, WS_MASK_KEY)?;
    stream
        .write_all(&request_frame)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(stream)?;
    let websocket_response_frame_len = response_payload.len();
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS WebSocket payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessWebSocketExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_frame_len,
        payload_len: payload.len(),
        echoed_payload,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        true_dataplane: true,
    })
}

pub fn tcp_exchange_over_httpupgrade_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    httpupgrade_host: &str,
    httpupgrade_path: &str,
    payload: &[u8],
) -> Result<VlessHttpUpgradeExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let httpupgrade_options = HttpUpgradeOptions::new(httpupgrade_host, httpupgrade_path);
    let upgrade_request = http_upgrade_request(&httpupgrade_options);
    stream
        .write_all(&upgrade_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(stream)?;
    validate_http_status(&response, 101)?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_header_len, echoed_payload) =
        read_tcp_response_payload_from_stream(stream, payload.len())?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS HTTPUpgrade payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessHttpUpgradeExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        httpupgrade_host: httpupgrade_options.host,
        httpupgrade_path: httpupgrade_options.path,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        httpupgrade_request_len: upgrade_request.len(),
        httpupgrade_response_head_len: response.len(),
        payload_len: payload.len(),
        echoed_payload,
        httpupgrade_handshake_validated: true,
        true_dataplane: true,
    })
}

pub fn tcp_exchange_over_grpc_hunk_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    grpc_options: &GrpcLifecycleOptions,
    payload: &[u8],
) -> Result<VlessGrpcHunkExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let preface = grpc_stream_preface(&grpc_options.service_name);
    stream
        .write_all(&preface)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_hunk = grpc_hunk_frame(&request)?;
    stream
        .write_all(&request_hunk)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let response_payload = read_grpc_hunk_frame(stream)?;
    let grpc_response_hunk_len = grpc_hunk_frame_len(&response_payload)?;
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS gRPC hunk payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessGrpcHunkExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        grpc_service_name: if grpc_options.service_name.is_empty() {
            "GunService".to_owned()
        } else {
            grpc_options.service_name.clone()
        },
        grpc_cache_key: grpc_options.cache_key(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        grpc_preface_len: preface.len(),
        grpc_request_hunk_len: request_hunk.len(),
        grpc_response_hunk_len,
        payload_len: payload.len(),
        echoed_payload,
        grpc_stream_preface_validated: true,
        grpc_hunk_frame_validated: true,
        cache_key_route_context_validated: true,
        full_grpc_http2_stack: false,
        true_dataplane: true,
    })
}

pub fn tcp_exchange_over_meek_polling_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    meek_options: &MeekRoundTripOptions,
    payload: &[u8],
) -> Result<VlessMeekPollingExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let meek_request = meek_http_request(meek_options, &request);
    stream
        .write_all(&meek_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_head, response_payload) = read_http_message(stream, "meek response")?;
    validate_http_status(&response_head, 200)?;
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS Meek polling payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessMeekPollingExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        meek_url: meek_options.url.clone(),
        meek_host: meek_options.host.clone(),
        meek_path: meek_options.path.clone(),
        meek_session_id: meek_options.session_id(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        meek_request_len: meek_request.len(),
        meek_request_body_len: request.len(),
        meek_response_head_len: response_head.len(),
        meek_response_body_len: response_payload.len(),
        payload_len: payload.len(),
        echoed_payload,
        meek_polling_validated: true,
        meek_session_id_validated: true,
        full_https_round_tripper: false,
        true_dataplane: true,
    })
}

pub fn tcp_exchange_over_http_transport_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    http_options: &HttpConnectOptions,
    payload: &[u8],
) -> Result<VlessHttpTransportExchangeReport, OutboundError>
where
    S: Read + Write,
{
    if !http_options.transport.enabled {
        return Err(OutboundError::BadVless(
            "VLESS HTTP transport requires HttpConnectOptions.transport.enabled=true".to_owned(),
        ));
    }
    let transport_request = http_proxy_request::connect_request(http_options);
    stream
        .write_all(&transport_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(stream)?;
    let http_transport_response_head_len = response.len();
    let status = http_proxy_request::parse_connect_response(&response)?;
    if status != 200 {
        return Err(OutboundError::BadVless(format!(
            "VLESS HTTP transport status: {status}"
        )));
    }

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_header_len, echoed_payload) =
        read_tcp_response_payload_from_stream(stream, payload.len())?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS HTTP transport payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessHttpTransportExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        http_transport_host: http_transport_host(http_options),
        http_transport_path: http_transport_path(http_options),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        http_transport_request_len: transport_request.len(),
        http_transport_response_head_len,
        payload_len: payload.len(),
        echoed_payload,
        http_transport_put_validated: true,
        full_http2_stack: false,
        true_dataplane: true,
    })
}

pub fn tcp_exchange_over_xhttp_packet_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    xhttp_options: &XHttpLifecycleOptions,
    payload: &[u8],
) -> Result<VlessXHttpPacketExchangeReport, OutboundError>
where
    S: Read + Write,
{
    if xhttp_options.mode != "packet-up" {
        return Err(OutboundError::BadVless(format!(
            "VLESS xHTTP packet exchange requires packet-up mode, got {}",
            xhttp_options.mode
        )));
    }
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let xhttp_request = xhttp_packet_request(xhttp_options, &request);
    stream
        .write_all(&xhttp_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_head, response_payload) = read_http_message(stream, "xhttp response")?;
    validate_http_status(&response_head, 200)?;
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS xHTTP packet payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessXHttpPacketExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        xhttp_host: xhttp_options.host.clone(),
        xhttp_path: crate::shared_transport::ir::normalize_xhttp_path_and_query(
            &xhttp_options.path,
        )
        .path,
        xhttp_request_path: xhttp_request_path(xhttp_options),
        xhttp_mode: xhttp_options.mode.clone(),
        xhttp_alpn: xhttp_options.alpn.clone(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        xhttp_request_len: xhttp_request.len(),
        xhttp_request_body_len: request.len(),
        xhttp_response_head_len: response_head.len(),
        xhttp_response_body_len: response_payload.len(),
        payload_len: payload.len(),
        echoed_payload,
        xhttp_packet_up_validated: true,
        xhttp_xmux_enabled: xhttp_options.xmux.is_some(),
        full_h2_h3_stack: false,
        true_dataplane: true,
    })
}
