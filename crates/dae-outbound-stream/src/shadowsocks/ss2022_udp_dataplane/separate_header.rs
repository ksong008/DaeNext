use super::*;
#[allow(clippy::too_many_arguments)]
pub(super) fn encode_separate_header_client_packet(
    cipher: &str,
    psk_list: &[Vec<u8>],
    header_cipher: &Ss2022AesBlockCipher,
    payload_cipher: &Ss2022SeparatePayloadCipher,
    session_id: [u8; 8],
    packet_id: u64,
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let separate_header = separate_header(session_id, packet_id);
    let mut out = Vec::new();
    out.extend_from_slice(&header_cipher.encrypt_block(&separate_header)?);
    let identity_headers = encode_udp_identity_headers(psk_list, &separate_header)?;
    out.extend_from_slice(&identity_headers);
    let message = encode_client_message(target, payload, timestamp)?;
    let sealed = payload_cipher.encrypt(&separate_header[4..16], &message)?;
    out.extend_from_slice(&sealed);
    Ok(Ss2022UdpEncodedPacket {
        wire: out,
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: HEADER_TYPE_CLIENT_PACKET,
        packet_id,
        session_id,
        client_session_id: None,
        target: Socks5Address::parse(target)?.authority(),
        payload_len: payload.len(),
        timestamp,
        separate_header_len: AES_BLOCK_LEN,
        packet_nonce_len: 0,
        identity_header_count: psk_list.len().saturating_sub(1),
        identity_header_bytes_len: identity_headers.len(),
    })
}

// SS2022 UDP packet encoding mirrors the wire fields explicitly.
#[allow(clippy::too_many_arguments)]
pub(super) fn encode_separate_header_server_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    server_session_id: [u8; 8],
    packet_id: u64,
    client_session_id: [u8; 8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let separate_header = separate_header(server_session_id, packet_id);
    let mut out = Vec::new();
    out.extend_from_slice(&encrypt_aes_block(upsk, &separate_header)?);
    let message = encode_server_message(client_session_id, target, payload, timestamp)?;
    out.extend_from_slice(&seal_separate_payload(
        conf,
        upsk,
        &separate_header,
        &message,
    )?);
    Ok(Ss2022UdpEncodedPacket {
        wire: out,
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: HEADER_TYPE_SERVER_PACKET,
        packet_id,
        session_id: server_session_id,
        client_session_id: Some(client_session_id),
        target: Socks5Address::parse(target)?.authority(),
        payload_len: payload.len(),
        timestamp,
        separate_header_len: AES_BLOCK_LEN,
        packet_nonce_len: 0,
        identity_header_count: 0,
        identity_header_bytes_len: 0,
    })
}

pub(super) fn decode_separate_header_client_packet(
    conf: &CipherConf2022,
    cipher: &str,
    psk_list: &[Vec<u8>],
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    if input.len() < AES_BLOCK_LEN {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP packet missing separate header".to_owned(),
        ));
    }
    let separate_header = decrypt_aes_block(&psk_list[0], &input[..AES_BLOCK_LEN])?;
    let identity_len = psk_list.len().saturating_sub(1) * AES_BLOCK_LEN;
    if input.len() < AES_BLOCK_LEN + identity_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP packet missing identity header".to_owned(),
        ));
    }
    let identity = &input[AES_BLOCK_LEN..AES_BLOCK_LEN + identity_len];
    validate_udp_identity_headers(psk_list, &separate_header, identity)?;
    let upsk = psk_list
        .last()
        .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?;
    let payload = open_separate_payload(
        conf,
        upsk,
        &separate_header,
        &input[AES_BLOCK_LEN + identity_len..],
    )?;
    let parsed = parse_client_message(&payload, now)?;
    Ok(Ss2022UdpDecodedPacket {
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: parsed.packet_type,
        packet_id: u64::from_be_bytes(separate_header[8..16].try_into().expect("header len")),
        session_id: separate_header[..8].try_into().expect("header len"),
        client_session_id: None,
        target: parsed.target,
        target_metadata_len: parsed.target_metadata_len,
        padding_len: parsed.padding_len,
        payload: parsed.payload,
        timestamp: parsed.timestamp,
        identity_header_count: psk_list.len().saturating_sub(1),
        identity_header_bytes_len: identity_len,
        identity_header_validated: true,
    })
}

pub(super) fn decode_separate_header_server_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    header_cipher: &Ss2022AesBlockCipher,
    payload_cipher: &mut Option<([u8; 8], Ss2022SeparatePayloadCipher)>,
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    if input.len() < AES_BLOCK_LEN {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP server packet missing separate header".to_owned(),
        ));
    }
    let separate_header = header_cipher.decrypt_block(&input[..AES_BLOCK_LEN])?;
    let session_id = separate_header[..8].try_into().expect("header len");
    let sealed_payload = &input[AES_BLOCK_LEN..];
    let payload = if let Some((cached_session_id, cipher)) = payload_cipher.as_ref()
        && cached_session_id == &session_id
    {
        cipher.decrypt(&separate_header[4..16], sealed_payload)?
    } else {
        let cipher = separate_payload_cipher(conf, upsk, &session_id)?;
        let payload = cipher.decrypt(&separate_header[4..16], sealed_payload)?;
        *payload_cipher = Some((session_id, cipher));
        payload
    };
    let parsed = parse_server_message(&payload, now)?;
    Ok(Ss2022UdpDecodedPacket {
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: parsed.packet_type,
        packet_id: u64::from_be_bytes(separate_header[8..16].try_into().expect("header len")),
        session_id,
        client_session_id: Some(parsed.client_session_id),
        target: parsed.target,
        target_metadata_len: parsed.target_metadata_len,
        padding_len: parsed.padding_len,
        payload: parsed.payload,
        timestamp: parsed.timestamp,
        identity_header_count: 0,
        identity_header_bytes_len: 0,
        identity_header_validated: true,
    })
}
