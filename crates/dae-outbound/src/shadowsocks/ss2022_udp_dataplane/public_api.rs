use super::*;
pub fn decode_client_packet(
    cipher: &str,
    password: &str,
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    decode_client_packet_impl(cipher, password, input, now)
}

pub fn decode_client_packet_with_replay(
    cipher: &str,
    password: &str,
    input: &[u8],
    now: u64,
    replay: &mut Ss2022UdpReplayTracker,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    let decoded = decode_client_packet_impl(cipher, password, input, now)?;
    replay
        .check_at(decoded.session_id, decoded.packet_id, now)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    Ok(decoded)
}

fn decode_client_packet_impl(
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

#[cfg(test)]
mod replay_api_tests {
    use super::{decode_client_packet, decode_client_packet_with_replay};
    use crate::shadowsocks::ss2022_udp_dataplane::{
        Ss2022UdpCodec, Ss2022UdpReplayPolicy, Ss2022UdpReplayTracker, unix_timestamp_now,
    };

    #[test]
    fn replay_aware_decode_rejects_replayed_packet() {
        let cipher = "2022-blake3-aes-128-gcm";
        let password = "AQIDBAUGBwgJCgsMDQ4PEA==";
        let mut codec = Ss2022UdpCodec::new(cipher, password, [0x41; 8]).unwrap();
        let encoded = codec
            .encode_client_packet(
                "replay.fixture.invalid:443",
                b"payload",
                unix_timestamp_now(),
                None,
            )
            .unwrap();
        let packet = encoded.wire;
        let mut replay =
            Ss2022UdpReplayTracker::with_policy(Ss2022UdpReplayPolicy::default()).unwrap();
        assert!(
            decode_client_packet_with_replay(
                cipher,
                password,
                &packet,
                unix_timestamp_now(),
                &mut replay
            )
            .is_ok()
        );
        assert!(
            decode_client_packet_with_replay(
                cipher,
                password,
                &packet,
                unix_timestamp_now(),
                &mut replay
            )
            .is_err()
        );
        assert!(decode_client_packet(cipher, password, &packet, unix_timestamp_now()).is_ok());
    }
}
