use super::*;
pub fn decode_client_packet(
    cipher: &str,
    password: &str,
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    let upsk = psk_list
        .last()
        .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?;
    let decoded = if conf.packet_cipher {
        decode_merged_header_packet(&conf, cipher, upsk, input, now)?
    } else {
        decode_separate_header_client_packet(&conf, cipher, &psk_list, input, now)?
    };
    if decoded.packet_type != HEADER_TYPE_CLIENT_PACKET {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP expected client packet type {}, got {}",
            HEADER_TYPE_CLIENT_PACKET, decoded.packet_type
        )));
    }
    Ok(decoded)
}

// SS2022 UDP packet encoding mirrors the wire fields explicitly.
#[allow(clippy::too_many_arguments)]
pub fn encode_server_packet(
    cipher: &str,
    password: &str,
    server_session_id: [u8; 8],
    packet_id: u64,
    client_session_id: [u8; 8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
    packet_nonce: Option<&[u8]>,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    let upsk = psk_list
        .last()
        .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?;
    if conf.packet_cipher {
        encode_merged_header_packet(
            &conf,
            cipher,
            upsk,
            packet_nonce,
            HEADER_TYPE_SERVER_PACKET,
            server_session_id,
            packet_id,
            Some(client_session_id),
            target,
            payload,
            timestamp,
        )
    } else {
        encode_separate_header_server_packet(
            &conf,
            cipher,
            upsk,
            server_session_id,
            packet_id,
            client_session_id,
            target,
            payload,
            timestamp,
        )
    }
}

pub fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
