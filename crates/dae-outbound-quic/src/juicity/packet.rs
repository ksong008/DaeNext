use dae_outbound_core::error::OutboundError;
use dae_outbound_core::trojan::TrojanMetadata;

use dae_outbound_core::juicity::contract::UNDERLAY_AUTH_CHANNEL_CAPACITY;

pub use super::stream_packet::*;

pub const JUICITY_UNDERLAY_AUTH_IV_LEN: usize = 32;
pub const JUICITY_UNDERLAY_AUTH_PSK_LEN: usize = 32;
pub const JUICITY_TRANSPORT_PACKET_CONN_CIPHER: &str = "chacha20-poly1305";
pub const JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO: &str = "juicity-reused-info";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JuicityUdpPacketConnKind {
    TransportPacketConn,
    StreamPacketConn,
}

impl JuicityUdpPacketConnKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransportPacketConn => "transport_packet_conn",
            Self::StreamPacketConn => "stream_packet_conn",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityUdpPacketConnDecision {
    pub target: String,
    pub target_port: u16,
    pub kind: JuicityUdpPacketConnKind,
    pub requires_dialauth: bool,
    pub requires_underlay_key: bool,
    pub uses_stream_packet_frame: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityDialAuthRecord {
    pub target: String,
    pub metadata_host: String,
    pub metadata_port: u16,
    pub metadata_len: usize,
    pub iv: [u8; JUICITY_UNDERLAY_AUTH_IV_LEN],
    pub psk: [u8; JUICITY_UNDERLAY_AUTH_PSK_LEN],
    pub packed: Vec<u8>,
    pub iv_zero_prefix_valid: bool,
    pub psk_nonzero: bool,
    pub underlay_auth_channel_capacity: u64,
    pub transport_packet_conn_cipher: String,
    pub transport_packet_conn_reused_info: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityPacketStateSmokeReport {
    pub port_zero_target: String,
    pub stream_target: String,
    pub payload_len: usize,
    pub port_zero_kind: String,
    pub stream_kind: String,
    pub dialauth_metadata_len: usize,
    pub dialauth_packed_len: usize,
    pub dialauth_iv_len: usize,
    pub dialauth_psk_len: usize,
    pub dialauth_iv_zero_prefix_valid: bool,
    pub dialauth_psk_nonzero: bool,
    pub underlay_auth_channel_capacity: u64,
    pub stream_packet_metadata_len: usize,
    pub stream_packet_frame_len: usize,
    pub stream_packet_payload_len: usize,
    pub stream_packet_payload_len_prefix_valid: bool,
    pub stream_packet_roundtrip_validated: bool,
    pub juicity_dialauth_record_protocol_state_admitted: bool,
    pub juicity_udp_port_zero_transport_packet_conn_route_admitted: bool,
    pub juicity_stream_packet_conn_frame_admitted: bool,
    pub juicity_dialauth_over_h3_admitted: bool,
    pub juicity_transport_packet_conn_dataplane_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

pub fn select_udp_packet_conn(target: &str) -> Result<JuicityUdpPacketConnDecision, OutboundError> {
    let metadata = TrojanMetadata::parse("udp", target)?;
    let target_port = metadata.port();
    let kind = if target_port == 0 {
        JuicityUdpPacketConnKind::TransportPacketConn
    } else {
        JuicityUdpPacketConnKind::StreamPacketConn
    };
    Ok(JuicityUdpPacketConnDecision {
        target: metadata.authority(),
        target_port,
        kind,
        requires_dialauth: kind == JuicityUdpPacketConnKind::TransportPacketConn,
        requires_underlay_key: kind == JuicityUdpPacketConnKind::TransportPacketConn,
        uses_stream_packet_frame: kind == JuicityUdpPacketConnKind::StreamPacketConn,
    })
}

pub fn build_dialauth_record_for_port_zero(
    target: &str,
) -> Result<JuicityDialAuthRecord, OutboundError> {
    let decision = select_udp_packet_conn(target)?;
    if decision.kind != JuicityUdpPacketConnKind::TransportPacketConn {
        return Err(OutboundError::BadJuicity(format!(
            "juicity DialAuth record requires UDP target port 0, got {}",
            decision.target_port
        )));
    }
    let metadata = TrojanMetadata::parse("udp", target)?;
    let metadata_bytes = metadata.encode()?;
    let mut iv = [0_u8; JUICITY_UNDERLAY_AUTH_IV_LEN];
    for (offset, byte) in iv[2..].iter_mut().enumerate() {
        *byte = deterministic_byte(0xa1, offset);
    }
    let mut psk = [0_u8; JUICITY_UNDERLAY_AUTH_PSK_LEN];
    for (offset, byte) in psk.iter_mut().enumerate() {
        *byte = deterministic_byte(0x41, offset);
    }
    let mut packed = Vec::with_capacity(iv.len() + psk.len() + metadata_bytes.len());
    packed.extend_from_slice(&iv);
    packed.extend_from_slice(&psk);
    packed.extend_from_slice(&metadata_bytes);
    Ok(JuicityDialAuthRecord {
        target: metadata.authority(),
        metadata_host: metadata.hostname(),
        metadata_port: metadata.port(),
        metadata_len: metadata_bytes.len(),
        iv,
        psk,
        packed,
        iv_zero_prefix_valid: iv[0] == 0 && iv[1] == 0,
        psk_nonzero: psk.iter().any(|byte| *byte != 0),
        underlay_auth_channel_capacity: UNDERLAY_AUTH_CHANNEL_CAPACITY,
        transport_packet_conn_cipher: JUICITY_TRANSPORT_PACKET_CONN_CIPHER.to_owned(),
        transport_packet_conn_reused_info: JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO.to_owned(),
    })
}

pub fn packet_state_smoke(
    port_zero_target: &str,
    stream_target: &str,
    payload: &[u8],
) -> Result<JuicityPacketStateSmokeReport, OutboundError> {
    let port_zero_decision = select_udp_packet_conn(port_zero_target)?;
    let stream_decision = select_udp_packet_conn(stream_target)?;
    let dialauth = build_dialauth_record_for_port_zero(port_zero_target)?;
    let frame = seal_stream_packet_frame(stream_target, payload)?;
    let decoded = decode_stream_packet_frame(&frame.encoded)?;
    let payload_len_prefix_valid = frame
        .encoded
        .get(frame.metadata_len..frame.metadata_len + 2)
        .map(|prefix| prefix == (payload.len() as u16).to_be_bytes().as_slice())
        .unwrap_or(false);
    let stream_packet_roundtrip_validated = decoded.target == frame.target
        && decoded.metadata_len == frame.metadata_len
        && decoded.payload() == payload
        && decoded.payload_len == payload.len();
    let dialauth_record_admitted = port_zero_decision.kind
        == JuicityUdpPacketConnKind::TransportPacketConn
        && dialauth.iv_zero_prefix_valid
        && dialauth.psk_nonzero
        && dialauth.packed.len() == dialauth.iv.len() + dialauth.psk.len() + dialauth.metadata_len;
    let route_admitted = port_zero_decision.requires_dialauth
        && port_zero_decision.requires_underlay_key
        && !port_zero_decision.uses_stream_packet_frame;
    let stream_frame_admitted = stream_decision.kind == JuicityUdpPacketConnKind::StreamPacketConn
        && stream_decision.uses_stream_packet_frame
        && payload_len_prefix_valid
        && stream_packet_roundtrip_validated;
    Ok(JuicityPacketStateSmokeReport {
        port_zero_target: port_zero_decision.target,
        stream_target: stream_decision.target,
        payload_len: payload.len(),
        port_zero_kind: port_zero_decision.kind.as_str().to_owned(),
        stream_kind: stream_decision.kind.as_str().to_owned(),
        dialauth_metadata_len: dialauth.metadata_len,
        dialauth_packed_len: dialauth.packed.len(),
        dialauth_iv_len: dialauth.iv.len(),
        dialauth_psk_len: dialauth.psk.len(),
        dialauth_iv_zero_prefix_valid: dialauth.iv_zero_prefix_valid,
        dialauth_psk_nonzero: dialauth.psk_nonzero,
        underlay_auth_channel_capacity: dialauth.underlay_auth_channel_capacity,
        stream_packet_metadata_len: frame.metadata_len,
        stream_packet_frame_len: frame.encoded.len(),
        stream_packet_payload_len: frame.payload_len,
        stream_packet_payload_len_prefix_valid: payload_len_prefix_valid,
        stream_packet_roundtrip_validated,
        juicity_dialauth_record_protocol_state_admitted: dialauth_record_admitted,
        juicity_udp_port_zero_transport_packet_conn_route_admitted: route_admitted,
        juicity_stream_packet_conn_frame_admitted: stream_frame_admitted,
        juicity_dialauth_over_h3_admitted: false,
        juicity_transport_packet_conn_dataplane_admitted: false,
        juicity_stream_packet_conn_dataplane_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

fn deterministic_byte(seed: u8, offset: usize) -> u8 {
    seed.wrapping_add((offset as u8).wrapping_mul(17))
        .wrapping_add(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_packet_prefix_decoder_preserves_trailing_frame() {
        let first = seal_stream_packet_frame("192.0.2.10:53", b"first").unwrap();
        let second = seal_stream_packet_frame("[2001:db8::10]:5353", b"second").unwrap();
        let mut joined = first.encoded.clone();
        joined.extend_from_slice(&second.encoded);

        let (decoded_first, first_len) =
            decode_stream_packet_frame_prefix(&joined).unwrap().unwrap();
        assert_eq!(decoded_first.target, "192.0.2.10:53");
        assert_eq!(decoded_first.payload(), b"first");
        assert_eq!(first_len, first.encoded.len());

        let (decoded_second, second_len) = decode_stream_packet_frame_prefix(&joined[first_len..])
            .unwrap()
            .unwrap();
        assert_eq!(decoded_second.target, "[2001:db8::10]:5353");
        assert_eq!(decoded_second.payload(), b"second");
        assert_eq!(second_len, second.encoded.len());
    }

    #[test]
    fn stream_packet_prefix_decoder_waits_for_every_wire_shape() {
        for target in ["192.0.2.20:443", "[2001:db8::20]:443", "packet.example:443"] {
            let frame = seal_stream_packet_frame(target, b"payload").unwrap();
            for prefix_len in 0..frame.encoded.len() {
                assert_eq!(
                    decode_stream_packet_frame_prefix(&frame.encoded[..prefix_len]).unwrap(),
                    None,
                    "prefix_len={prefix_len} target={target}"
                );
            }
            let (decoded, consumed) = decode_stream_packet_frame_prefix(&frame.encoded)
                .unwrap()
                .unwrap();
            assert_eq!(decoded.target, target);
            assert_eq!(decoded.payload(), b"payload");
            assert_eq!(consumed, frame.encoded.len());
        }
    }

    #[test]
    fn stream_packet_frame_bound_is_derived_from_wire_widths() {
        assert_eq!(JUICITY_STREAM_PACKET_MAX_METADATA_LEN, 259);
        assert_eq!(
            JUICITY_STREAM_PACKET_MAX_FRAME_LEN,
            JUICITY_STREAM_PACKET_MAX_METADATA_LEN + 2 + u16::MAX as usize
        );
    }

    #[test]
    fn production_codec_avoids_the_report_frame_payload_copy() {
        let target = "192.0.2.30:53";
        let payload = b"payload";
        let report_frame = seal_stream_packet_frame(target, payload).unwrap();
        assert_eq!(
            encode_stream_packet_frame(target, payload).unwrap(),
            report_frame.encoded
        );

        let mut joined = report_frame.encoded.clone();
        joined.extend_from_slice(b"trailing");
        let (decoded, consumed) = decode_stream_packet_payload_prefix(&joined)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.payload, payload);
        assert_eq!(consumed, report_frame.encoded.len());
    }
}
