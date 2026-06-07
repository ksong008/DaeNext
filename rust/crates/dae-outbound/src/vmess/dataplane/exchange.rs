use super::*;

pub fn aead_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess AEAD TCP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_client_session_start(
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadTcpClientSessionStart, OutboundError> {
    let material = VMessAeadMaterial::random();
    let normalized_uuid = normalize_vmess_uuid(uuid);
    let cmd_key = vmess_cmd_key_from_uuid(&normalized_uuid)?;
    let eauth_id = put_eauth_id(&cmd_key, unix_timestamp_now()?, material.eauth_random)?;
    let instruction = request_instruction(&material, target, VMessNetwork::Tcp)?;
    let header = encrypt_request_header(
        &cmd_key,
        &eauth_id,
        &material.connection_nonce,
        &instruction,
    )?;
    let parsed = parse_instruction(&instruction)?;
    let mut codec = BodyCodec::new(
        parsed.request_body_key,
        parsed.request_body_iv,
        parsed.request_options,
    )?;
    let chunk = if payload.is_empty() {
        Vec::new()
    } else {
        codec.seal_chunk(payload)?
    };
    let mut first_write = Vec::with_capacity(header.len() + chunk.len());
    first_write.extend_from_slice(&header);
    first_write.extend_from_slice(&chunk);
    let request = VMessAeadTcpRequest {
        version: parsed.version,
        uuid: normalized_uuid,
        cmd_key_hex: hex_encode(&cmd_key),
        eauth_crc_validated: true,
        eauth_timestamp: 0,
        request_options: parsed.request_options,
        security: parsed.security,
        command: parsed.command,
        target: parsed.target,
        payload: payload.to_vec(),
        request_header_len: header.len(),
        request_chunk_len: chunk.len(),
        response_auth: parsed.response_auth,
        request_body_iv: parsed.request_body_iv,
        request_body_key: parsed.request_body_key,
        response_body_iv: parsed.response_body_iv,
        response_body_key: parsed.response_body_key,
    };
    Ok(VMessAeadTcpClientSessionStart {
        first_write,
        request,
        upload: VMessAeadTcpUploadCodec { codec },
    })
}

impl VMessAeadTcpUploadCodec {
    pub fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
        self.codec.seal_chunk(payload)
    }
}

impl VMessAeadTcpResponseReader {
    pub fn read_chunk_from_stream<S>(&mut self, stream: &mut S) -> Result<Vec<u8>, OutboundError>
    where
        S: Read,
    {
        self.codec.open_chunk(stream).map(|(payload, _)| payload)
    }
}

pub fn aead_tcp_response_reader_from_stream<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
) -> Result<VMessAeadTcpResponseReader, OutboundError>
where
    S: Read,
{
    let response_header_len = read_aead_response_header(stream, request)?;
    let codec = BodyCodec::new(
        request.response_body_key,
        request.response_body_iv,
        request.request_options,
    )?;
    Ok(VMessAeadTcpResponseReader {
        response_header_len,
        codec,
    })
}

pub fn aead_udp_over_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadUdpOverTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Udp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess AEAD UDP-over-TCP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadUdpOverTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Udp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        packet_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_packet_addr_udp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    packet_target: &str,
    payload: &[u8],
) -> Result<VMessAeadPacketAddrUdpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request_target = packet_addr_magic_target(packet_target)?;
    let packet_payload = put_packet_addr_payload(packet_target, payload)?;
    let packet = build_aead_request(uuid, &request_target, VMessNetwork::Udp, &packet_payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_packet, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    let (echoed_target, packet_addr_len, echoed_payload) =
        parse_packet_addr_payload(&echoed_packet)?;
    if echoed_target != packet_target {
        return Err(OutboundError::BadVmess(format!(
            "VMess packet-addr target mismatch: got {echoed_target}, want {packet_target}"
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess packet-addr UDP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadPacketAddrUdpExchangeReport {
        proxy: proxy.to_owned(),
        request_target,
        packet_target: packet_target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Udp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        packet_addr_len,
        packet_len: packet_payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_mux_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    mux_id: [u8; 2],
    mux_target: &str,
    network: &str,
    payload: &[u8],
) -> Result<VMessAeadMuxExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request_target = "0.0.0.0:0";
    let metadata = VMessMetadata::parse(network, mux_target)?;
    let options = MuxFrameOptions::new(mux_id, metadata.hostname(), metadata.port(), network);
    let new_frame = mux_new_frame(&options);
    let data_frame = mux_data_frame(mux_id, payload)?;
    let end_frame = mux_end_frame(mux_id);
    let packet = build_aead_request_chunks(
        uuid,
        request_target,
        VMessNetwork::Mux,
        &[&new_frame, &data_frame, &end_frame],
    )?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    for chunk in &packet.chunks {
        stream
            .write_all(chunk)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    }

    let (response_header_len, response_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    let echoed = read_mux_frame_from_bytes(&response_payload)?;
    if echoed.id != mux_id
        || echoed.status != mux::SESSION_STATUS_KEEP
        || echoed.option != mux::OPTION_DATA
    {
        return Err(OutboundError::BadVmess(format!(
            "VMess mux response frame mismatch: id={:?} status={} option={}",
            echoed.id, echoed.status, echoed.option
        )));
    }
    if echoed.payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess mux payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadMuxExchangeReport {
        proxy: proxy.to_owned(),
        request_target: request_target.to_owned(),
        mux_target: mux_target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Mux.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        mux_id_hex: hex_encode(&mux_id),
        request_header_len: packet.header.len(),
        request_chunk_len: packet.request.request_chunk_len,
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        echoed_payload: echoed.payload,
        new_frame_validated: true,
        data_frame_validated: true,
        end_frame_sent: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_websocket_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<VMessAeadWebSocketExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    stream
        .write_all(&handshake)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let response = read_http_head(stream)?;
    validate_http_status(&response, 101)?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let request_frame = websocket_client_binary_frame(&request_payload, WS_MASK_KEY)?;
    stream
        .write_all(&request_frame)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(stream)?;
    let websocket_response_frame_len = response_payload.len();
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess WebSocket response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess WebSocket payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadWebSocketExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_frame_len,
        payload_len: payload.len(),
        echoed_payload,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_httpupgrade_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    httpupgrade_host: &str,
    httpupgrade_path: &str,
    payload: &[u8],
) -> Result<VMessAeadHttpUpgradeExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let options = HttpUpgradeOptions::new(httpupgrade_host, httpupgrade_path);
    let upgrade_request = http_upgrade_request(&options);
    stream
        .write_all(&upgrade_request)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let response = read_http_head(stream)?;
    let httpupgrade_response_head_len = response.len();
    validate_http_status(&response, 101)?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess HTTPUpgrade payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadHttpUpgradeExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        httpupgrade_host: options.host,
        httpupgrade_path: options.path,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        httpupgrade_request_len: upgrade_request.len(),
        httpupgrade_response_head_len,
        payload_len: payload.len(),
        echoed_payload,
        httpupgrade_handshake_validated: true,
        httpupgrade_tunnel_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_grpc_hunk_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    grpc_options: &GrpcLifecycleOptions,
    payload: &[u8],
) -> Result<VMessAeadGrpcHunkExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let preface = grpc_stream_preface(&grpc_options.service_name);
    stream
        .write_all(&preface)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let request_hunk = grpc_hunk_frame(&request_payload)?;
    stream
        .write_all(&request_hunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let response_payload = read_grpc_hunk_frame(stream)?;
    let grpc_response_hunk_len = grpc_hunk_frame_len(&response_payload)?;
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess gRPC hunk response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess gRPC hunk payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadGrpcHunkExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        grpc_service_name: if grpc_options.service_name.is_empty() {
            "GunService".to_owned()
        } else {
            grpc_options.service_name.clone()
        },
        grpc_cache_key: grpc_options.cache_key(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
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
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_meek_polling_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    meek_options: &MeekRoundTripOptions,
    payload: &[u8],
) -> Result<VMessAeadMeekPollingExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let meek_request = meek_http_request(meek_options, &request_payload);
    stream
        .write_all(&meek_request)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_head, response_payload) = read_http_message(stream, "meek response")?;
    validate_http_status(&response_head, 200)?;
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess Meek polling response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess Meek polling payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadMeekPollingExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        meek_url: meek_options.url.clone(),
        meek_host: meek_options.host.clone(),
        meek_path: meek_options.path.clone(),
        meek_session_id: meek_options.session_id(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        meek_request_len: meek_request.len(),
        meek_request_body_len: request_payload.len(),
        meek_response_head_len: response_head.len(),
        meek_response_body_len: response_payload.len(),
        payload_len: payload.len(),
        echoed_payload,
        meek_polling_validated: true,
        full_https_round_tripper: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_http_transport_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    http_options: &HttpConnectOptions,
    payload: &[u8],
) -> Result<VMessAeadHttpTransportExchangeReport, OutboundError>
where
    S: Read + Write,
{
    if !http_options.transport.enabled {
        return Err(OutboundError::BadVmess(
            "VMess HTTP transport requires HttpConnectOptions.transport.enabled=true".to_owned(),
        ));
    }
    let transport_request = http_proxy_request::connect_request(http_options);
    stream
        .write_all(&transport_request)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let response = read_http_head(stream)?;
    let http_transport_response_head_len = response.len();
    let status = http_proxy_request::parse_connect_response(&response)?;
    if status != 200 {
        return Err(OutboundError::BadVmess(format!(
            "VMess HTTP transport status: {status}"
        )));
    }

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess HTTP transport payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadHttpTransportExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        http_transport_host: http_transport_host(http_options),
        http_transport_path: http_transport_path(http_options),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        http_transport_request_len: transport_request.len(),
        http_transport_response_head_len,
        payload_len: payload.len(),
        echoed_payload,
        http_transport_put_validated: true,
        full_http2_stack: false,
        true_dataplane: true,
        default_go_path: true,
    })
}
