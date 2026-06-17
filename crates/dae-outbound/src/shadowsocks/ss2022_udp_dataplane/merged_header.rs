use super::*;
// SS2022 UDP packet encoding mirrors the wire fields explicitly.
#[allow(clippy::too_many_arguments)]
pub(super) fn encode_merged_header_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    packet_nonce: Option<&[u8]>,
    packet_type: u8,
    session_id: [u8; 8],
    packet_id: u64,
    client_session_id: Option<[u8; 8]>,
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let nonce = packet_nonce.ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 UDP XChaCha packet nonce is required".to_owned())
    })?;
    if nonce.len() != conf.packet_nonce_len {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP packet nonce length must be {}, got {}",
            conf.packet_nonce_len,
            nonce.len()
        )));
    }
    let mut message = Vec::new();
    message.extend_from_slice(&session_id);
    message.extend_from_slice(&packet_id.to_be_bytes());
    match packet_type {
        HEADER_TYPE_CLIENT_PACKET => {
            message.extend_from_slice(&encode_client_message(target, payload, timestamp)?);
        }
        HEADER_TYPE_SERVER_PACKET => {
            let client_session_id = client_session_id.ok_or_else(|| {
                OutboundError::BadShadowsocks(
                    "SS2022 UDP server packet requires client session id".to_owned(),
                )
            })?;
            message.extend_from_slice(&encode_server_message(
                client_session_id,
                target,
                payload,
                timestamp,
            )?);
        }
        _ => {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 UDP unsupported packet type: {packet_type}"
            )));
        }
    }
    let packet_cipher = XChaCha20Poly1305::new_from_slice(upsk)
        .map_err(|_| OutboundError::BadShadowsocks("bad SS2022 XChaCha packet key".to_owned()))?;
    let mut out = Vec::new();
    out.extend_from_slice(nonce);
    out.extend_from_slice(
        &packet_cipher
            .encrypt(
                chacha20poly1305::XNonce::from_slice(nonce),
                message.as_slice(),
            )
            .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP encrypt failed".to_owned()))?,
    );
    Ok(Ss2022UdpEncodedPacket {
        wire: out,
        cipher: cipher.to_owned(),
        branch: "merged-header-xchacha20-poly1305",
        packet_type,
        packet_id,
        session_id,
        client_session_id,
        target: Socks5Address::parse(target)?.authority(),
        payload_len: payload.len(),
        timestamp,
        separate_header_len: 0,
        packet_nonce_len: conf.packet_nonce_len,
        identity_header_count: 0,
        identity_header_bytes_len: 0,
    })
}

pub(super) fn decode_merged_header_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    if input.len() < conf.packet_nonce_len + conf.tag_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP XChaCha packet too short".to_owned(),
        ));
    }
    let (nonce, payload) = input.split_at(conf.packet_nonce_len);
    let packet_cipher = XChaCha20Poly1305::new_from_slice(upsk)
        .map_err(|_| OutboundError::BadShadowsocks("bad SS2022 XChaCha packet key".to_owned()))?;
    let plain = packet_cipher
        .decrypt(chacha20poly1305::XNonce::from_slice(nonce), payload)
        .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP decrypt failed".to_owned()))?;
    if plain.len() < 16 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP merged header too short".to_owned(),
        ));
    }
    let mut session_id = [0_u8; 8];
    session_id.copy_from_slice(&plain[..8]);
    let packet_id = u64::from_be_bytes(plain[8..16].try_into().expect("header len"));
    let message = &plain[16..];
    let packet_type = *message.first().ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 UDP merged message missing type".to_owned())
    })?;
    match packet_type {
        HEADER_TYPE_CLIENT_PACKET => {
            let parsed = parse_client_message(message, now)?;
            Ok(Ss2022UdpDecodedPacket {
                cipher: cipher.to_owned(),
                branch: "merged-header-xchacha20-poly1305",
                packet_type: parsed.packet_type,
                packet_id,
                session_id,
                client_session_id: None,
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
        HEADER_TYPE_SERVER_PACKET => {
            let parsed = parse_server_message(message, now)?;
            Ok(Ss2022UdpDecodedPacket {
                cipher: cipher.to_owned(),
                branch: "merged-header-xchacha20-poly1305",
                packet_type: parsed.packet_type,
                packet_id,
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
        _ => Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP unexpected packet type: {packet_type}"
        ))),
    }
}
