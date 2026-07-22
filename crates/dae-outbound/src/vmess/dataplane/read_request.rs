use super::*;

pub fn read_aead_tcp_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadTcpRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_request_from_stream(stream, uuid)?;
    if request.command != VMessNetwork::Tcp.byte() {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess AEAD TCP command: {}",
            request.command
        )));
    }
    Ok(request)
}

pub fn read_aead_udp_over_tcp_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadUdpOverTcpRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_request_from_stream(stream, uuid)?;
    if request.command != VMessNetwork::Udp.byte() {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess AEAD UDP command: {}",
            request.command
        )));
    }
    let packet_len = request.payload.len();
    Ok(VMessAeadUdpOverTcpRequest {
        request,
        packet_len,
    })
}

pub fn read_aead_packet_addr_udp_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadPacketAddrUdpRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_udp_over_tcp_request_from_stream(stream, uuid)?;
    let (packet_target, packet_addr_len, packet_payload) =
        parse_packet_addr_payload(&request.request.payload)?;
    Ok(VMessAeadPacketAddrUdpRequest {
        request: request.request,
        packet_target,
        packet_addr_len,
        packet_payload,
    })
}

pub fn read_aead_mux_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadMuxRequest, OutboundError>
where
    S: Read,
{
    let (mut request, mut request_codec) = read_aead_request_header_from_stream(stream, uuid)?;
    if request.command != VMessNetwork::Mux.byte() {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess AEAD mux command: {}",
            request.command
        )));
    }
    let (new_payload, new_chunk_len) = request_codec.open_chunk(stream)?;
    let (data_payload, data_chunk_len) = request_codec.open_chunk(stream)?;
    let (end_payload, end_chunk_len) = request_codec.open_chunk(stream)?;
    let new_frame = read_mux_frame_from_bytes(&new_payload)?;
    let data_frame = read_mux_frame_from_bytes(&data_payload)?;
    let end_frame = read_mux_frame_from_bytes(&end_payload)?;
    request.request_chunk_len = new_chunk_len + data_chunk_len + end_chunk_len;
    request.payload = [new_payload, data_payload, end_payload].concat();
    Ok(VMessAeadMuxRequest {
        mux_id_hex: hex_encode(&new_frame.id),
        request,
        new_frame,
        data_frame,
        end_frame,
    })
}

pub fn read_aead_tcp_request_from_websocket_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadWebSocketRequest, OutboundError>
where
    S: Read,
{
    let payload = read_websocket_binary_frame(stream)?;
    let websocket_request_frame_len = payload.len();
    let mut cursor = Cursor::new(&payload);
    let request = read_aead_tcp_request_from_stream(&mut cursor, uuid)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess WebSocket request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VMessAeadWebSocketRequest {
        request,
        websocket_request_frame_len,
    })
}

pub fn read_aead_tcp_request_from_httpupgrade_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadHttpUpgradeRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_tcp_request_from_stream(stream, uuid)?;
    Ok(VMessAeadHttpUpgradeRequest {
        request,
        httpupgrade_tunnel_validated: true,
    })
}

pub fn read_aead_tcp_request_from_grpc_hunk_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadGrpcHunkRequest, OutboundError>
where
    S: Read,
{
    let payload = read_grpc_hunk_frame(stream)?;
    let grpc_request_hunk_len = grpc_hunk_frame_len(&payload)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_aead_tcp_request_from_stream(&mut cursor, uuid)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess gRPC hunk request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VMessAeadGrpcHunkRequest {
        request,
        grpc_request_hunk_len,
    })
}

pub fn read_aead_tcp_request_from_meek_polling_stream<S>(
    stream: &mut S,
    uuid: &str,
    meek_options: &MeekRoundTripOptions,
) -> Result<VMessAeadMeekPollingRequest, OutboundError>
where
    S: Read,
{
    let (request_head, payload) = read_http_message(stream, "meek request")?;
    validate_meek_request_head(&request_head, meek_options)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_aead_tcp_request_from_stream(&mut cursor, uuid)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess Meek polling request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VMessAeadMeekPollingRequest {
        request,
        meek_request_body_len: payload.len(),
        meek_session_id_validated: true,
    })
}

pub fn read_http_transport_request_head_from_stream<S>(
    stream: &mut S,
    http_options: &HttpConnectOptions,
) -> Result<VMessHttpTransportRequestHead, OutboundError>
where
    S: Read,
{
    if !http_options.transport.enabled {
        return Err(OutboundError::BadVmess(
            "VMess HTTP transport request requires transport.enabled=true".to_owned(),
        ));
    }
    let request_head = read_http_head(stream)?;
    validate_http_transport_request_head(&request_head, http_options)
}

pub(super) fn read_aead_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadTcpRequest, OutboundError>
where
    S: Read,
{
    let (mut request, mut request_codec) = read_aead_request_header_from_stream(stream, uuid)?;
    let (payload, request_chunk_len) = request_codec.open_chunk(stream)?;
    request.payload = payload;
    request.request_chunk_len = request_chunk_len;
    Ok(request)
}

pub(super) fn read_aead_request_header_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<(VMessAeadTcpRequest, BodyCodec), OutboundError>
where
    S: Read,
{
    let normalized_uuid = normalize_vmess_uuid(uuid);
    let cmd_key = vmess_cmd_key_from_uuid(&normalized_uuid)?;
    let mut eauth_id = [0_u8; 16];
    read_exact(stream, &mut eauth_id, "vmess eauth id")?;
    let (eauth_timestamp, eauth_crc_validated) = decrypt_eauth_id(&cmd_key, &eauth_id)?;
    if !eauth_crc_validated {
        return Err(OutboundError::BadVmess(
            "VMess EAuthID checksum mismatch".to_owned(),
        ));
    }

    let mut length_and_nonce = [0_u8; 26];
    read_exact(
        stream,
        &mut length_and_nonce,
        "vmess request header length and connection nonce",
    )?;
    let connection_nonce = &length_and_nonce[18..26];
    let length_plain = aes128_gcm_decrypt(
        &kdf16(
            &cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                &eauth_id,
                connection_nonce,
            ],
        ),
        &kdf12(
            &cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                &eauth_id,
                connection_nonce,
            ],
        ),
        &length_and_nonce[..18],
        &eauth_id,
    )?;
    if length_plain.len() != 2 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess request header length plaintext: {} bytes",
            length_plain.len()
        )));
    }
    let instruction_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
    let mut encrypted_instruction = vec![0_u8; instruction_len + 16];
    read_exact(
        stream,
        &mut encrypted_instruction,
        "vmess encrypted request header payload",
    )?;
    let instruction = aes128_gcm_decrypt(
        &kdf16(
            &cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_AEAD_KEY,
                &eauth_id,
                connection_nonce,
            ],
        ),
        &kdf12(
            &cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_AEAD_IV, &eauth_id, connection_nonce],
        ),
        &encrypted_instruction,
        &eauth_id,
    )?;
    if instruction.len() != instruction_len {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess instruction length: got {}, want {}",
            instruction.len(),
            instruction_len
        )));
    }

    let parsed = parse_instruction(&instruction)?;
    let request_codec = BodyCodec::new(
        parsed.request_body_key,
        parsed.request_body_iv,
        parsed.security,
        parsed.request_options,
    )?;
    Ok((
        VMessAeadTcpRequest {
            version: parsed.version,
            uuid: normalized_uuid,
            cmd_key_hex: hex_encode(&cmd_key),
            eauth_crc_validated,
            eauth_timestamp,
            request_options: parsed.request_options,
            security: parsed.security,
            command: parsed.command,
            target: parsed.target,
            payload: Vec::new(),
            request_header_len: 16 + 26 + encrypted_instruction.len(),
            request_chunk_len: 0,
            response_auth: parsed.response_auth,
            request_body_iv: parsed.request_body_iv,
            request_body_key: parsed.request_body_key,
            response_body_iv: parsed.response_body_iv,
            response_body_key: parsed.response_body_key,
        },
        request_codec,
    ))
}
