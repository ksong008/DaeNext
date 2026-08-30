use dae_outbound_core::error::OutboundError;

pub const HYSTERIA2_FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const HYSTERIA2_MAX_UDP_ADDRESS_LENGTH: usize = 2048;
/// Maximum serialized Hysteria2 UDP message size, including its wire header.
pub const HYSTERIA2_MAX_UDP_MESSAGE_LENGTH: usize = 4096;
/// Absolute payload ceiling for the shortest encodable target.
///
/// Call [`hysteria2_udp_payload_capacity`] when a concrete target is available.
pub const HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH: usize = HYSTERIA2_MAX_UDP_MESSAGE_LENGTH - 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpRequestFrame {
    pub target: String,
    pub payload: Vec<u8>,
    pub consumed_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpResponseFrame {
    pub ok: bool,
    pub message: String,
    pub payload: Vec<u8>,
    pub consumed_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2UdpMessage {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    target: String,
    payload: Vec<u8>,
}

impl Hysteria2UdpMessage {
    pub fn new(
        session_id: u32,
        target: impl AsRef<str>,
        payload: impl AsRef<[u8]>,
    ) -> Result<Self, OutboundError> {
        Self::from_parts(
            session_id,
            0,
            0,
            1,
            target.as_ref().to_owned(),
            payload.as_ref().to_vec(),
        )
    }

    fn from_parts(
        session_id: u32,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        target: String,
        payload: Vec<u8>,
    ) -> Result<Self, OutboundError> {
        validate_udp_message_fields(packet_id, fragment_id, fragment_count, &target, &payload)?;
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            target,
            payload,
        })
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn packet_id(&self) -> u16 {
        self.packet_id
    }

    pub fn fragment_id(&self) -> u8 {
        self.fragment_id
    }

    pub fn fragment_count(&self) -> u8 {
        self.fragment_count
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn encoded_len(&self) -> usize {
        8 + quic_varint_len(self.target.len() as u64) + self.target.len() + self.payload.len()
    }
}

/// Returns the application payload capacity for a serialized UDP target.
pub fn hysteria2_udp_payload_capacity(target: &str) -> Result<usize, OutboundError> {
    if target.is_empty() || target.len() > HYSTERIA2_MAX_UDP_ADDRESS_LENGTH {
        return Err(bad_wire("invalid Hysteria2 UDP target length"));
    }
    let header_len = 8_usize
        .checked_add(quic_varint_len(target.len() as u64))
        .and_then(|length| length.checked_add(target.len()))
        .ok_or_else(|| bad_wire("Hysteria2 UDP header length overflow"))?;
    HYSTERIA2_MAX_UDP_MESSAGE_LENGTH
        .checked_sub(header_len)
        .filter(|capacity| *capacity > 0)
        .ok_or_else(|| bad_wire("Hysteria2 UDP target leaves no payload capacity"))
}

pub fn build_tcp_request_stream(target: &str, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    build_tcp_request_stream_with_padding(target, payload, &[])
}

pub fn build_tcp_request_stream_with_padding(
    target: &str,
    payload: &[u8],
    padding: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if target.is_empty() {
        return Err(bad_wire("Hysteria2 TCP target cannot be empty"));
    }
    if padding.len() > 4_096 {
        return Err(bad_wire(
            "Hysteria2 TCP request padding exceeds protocol limit",
        ));
    }
    let mut out = Vec::with_capacity(16 + target.len() + padding.len() + payload.len());
    append_quic_varint(&mut out, HYSTERIA2_FRAME_TYPE_TCP_REQUEST)?;
    append_quic_varint(&mut out, target.len() as u64)?;
    out.extend_from_slice(target.as_bytes());
    append_quic_varint(&mut out, padding.len() as u64)?;
    out.extend_from_slice(padding);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn parse_tcp_request_stream(input: &[u8]) -> Result<TcpRequestFrame, OutboundError> {
    let (frame_type, mut offset) = read_quic_varint(input, 0)?;
    if frame_type != HYSTERIA2_FRAME_TYPE_TCP_REQUEST {
        return Err(bad_wire(format!(
            "bad Hysteria2 TCP request frame type: {frame_type:#x}"
        )));
    }
    let (addr_len, consumed) = read_quic_varint(input, offset)?;
    offset = consumed;
    let addr_len = usize::try_from(addr_len)
        .map_err(|_| bad_wire("Hysteria2 TCP request address too large"))?;
    if addr_len == 0 || addr_len > 2048 || input.len() < offset + addr_len {
        return Err(bad_wire("invalid Hysteria2 TCP request address length"));
    }
    let target = String::from_utf8(input[offset..offset + addr_len].to_vec())
        .map_err(|err| bad_wire(format!("Hysteria2 TCP request target utf8: {err}")))?;
    offset += addr_len;
    let (padding_len, consumed) = read_quic_varint(input, offset)?;
    offset = consumed;
    let padding_len = usize::try_from(padding_len)
        .map_err(|_| bad_wire("Hysteria2 TCP request padding too large"))?;
    if padding_len > 4096 || input.len() < offset + padding_len {
        return Err(bad_wire("invalid Hysteria2 TCP request padding"));
    }
    offset += padding_len;
    Ok(TcpRequestFrame {
        target,
        payload: input[offset..].to_vec(),
        consumed_len: offset,
    })
}

pub fn build_tcp_response_stream(
    ok: bool,
    message: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::with_capacity(8 + message.len() + payload.len());
    out.push(u8::from(!ok));
    append_quic_varint(&mut out, message.len() as u64)?;
    out.extend_from_slice(message.as_bytes());
    append_quic_varint(&mut out, 0)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn parse_tcp_response_stream(input: &[u8]) -> Result<TcpResponseFrame, OutboundError> {
    let Some((&status, rest)) = input.split_first() else {
        return Err(bad_wire("Hysteria2 TCP response missing status"));
    };
    let (message_len, mut offset) = read_quic_varint(rest, 0)?;
    offset += 1;
    let message_len = usize::try_from(message_len)
        .map_err(|_| bad_wire("Hysteria2 TCP response message too large"))?;
    if message_len > 2048 || input.len() < offset + message_len {
        return Err(bad_wire("invalid Hysteria2 TCP response message length"));
    }
    let message = String::from_utf8(input[offset..offset + message_len].to_vec())
        .map_err(|err| bad_wire(format!("Hysteria2 TCP response message utf8: {err}")))?;
    offset += message_len;
    let (padding_len, consumed) = read_quic_varint(input, offset)?;
    offset = consumed;
    let padding_len = usize::try_from(padding_len)
        .map_err(|_| bad_wire("Hysteria2 TCP response padding too large"))?;
    if padding_len > 4096 || input.len() < offset + padding_len {
        return Err(bad_wire("invalid Hysteria2 TCP response padding"));
    }
    offset += padding_len;
    Ok(TcpResponseFrame {
        ok: status == 0,
        message,
        payload: input[offset..].to_vec(),
        consumed_len: offset,
    })
}

pub fn encode_hysteria2_udp_message(
    message: &Hysteria2UdpMessage,
) -> Result<Vec<u8>, OutboundError> {
    encode_hysteria2_udp_payload(
        message.session_id,
        message.packet_id,
        message.fragment_id,
        message.fragment_count,
        &message.target,
        &message.payload,
    )
}

pub fn encode_hysteria2_udp_payload(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    validate_udp_message_fields(packet_id, fragment_id, fragment_count, target, payload)?;
    validate_outbound_udp_message_identity(packet_id, fragment_id, fragment_count)?;
    let encoded_len = 8 + quic_varint_len(target.len() as u64) + target.len() + payload.len();
    let mut out = Vec::with_capacity(encoded_len);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_id);
    out.push(fragment_count);
    append_quic_varint(&mut out, target.len() as u64)?;
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_hysteria2_udp_message(input: &[u8]) -> Result<Hysteria2UdpMessage, OutboundError> {
    if input.len() < 9 {
        return Err(bad_wire("short Hysteria2 UDP message"));
    }
    let session_id = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let fragment_id = input[6];
    let fragment_count = input[7];
    let (addr_len, mut offset) = read_quic_varint(input, 8)?;
    let addr_len =
        usize::try_from(addr_len).map_err(|_| bad_wire("Hysteria2 UDP address too large"))?;
    let payload_offset = offset
        .checked_add(addr_len)
        .ok_or_else(|| bad_wire("Hysteria2 UDP address length overflow"))?;
    if addr_len == 0 || addr_len > HYSTERIA2_MAX_UDP_ADDRESS_LENGTH || input.len() <= payload_offset
    {
        return Err(bad_wire("invalid Hysteria2 UDP address length"));
    }
    let target = String::from_utf8(input[offset..payload_offset].to_vec())
        .map_err(|err| bad_wire(format!("Hysteria2 UDP target utf8: {err}")))?;
    offset = payload_offset;
    Hysteria2UdpMessage::from_parts(
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        target,
        input[offset..].to_vec(),
    )
}

pub fn fragment_hysteria2_udp_message(
    message: &Hysteria2UdpMessage,
    packet_id: u16,
    max_wire_size: usize,
) -> Result<Vec<Hysteria2UdpMessage>, OutboundError> {
    if message.fragment_count != 1 || message.fragment_id != 0 || message.packet_id != 0 {
        return Err(bad_wire(
            "only a complete Hysteria2 UDP message can be fragmented",
        ));
    }
    if packet_id == 0 {
        return Err(bad_wire(
            "fragmented Hysteria2 UDP message requires a nonzero packet ID",
        ));
    }
    if message.encoded_len() <= max_wire_size {
        return Err(bad_wire(format!(
            "Hysteria2 UDP message fits max wire size {max_wire_size} without fragmentation"
        )));
    }
    let header_len = message
        .encoded_len()
        .checked_sub(message.payload.len())
        .ok_or_else(|| bad_wire("Hysteria2 UDP header length underflow"))?;
    let max_fragment_payload = max_wire_size.checked_sub(header_len).ok_or_else(|| {
        bad_wire(format!(
            "Hysteria2 UDP header is larger than max wire size {max_wire_size}"
        ))
    })?;
    if max_fragment_payload == 0 {
        return Err(bad_wire(format!(
            "Hysteria2 UDP header leaves no payload at max wire size {max_wire_size}"
        )));
    }
    let fragment_count = message.payload.len().div_ceil(max_fragment_payload);
    let fragment_count = u8::try_from(fragment_count)
        .map_err(|_| bad_wire("Hysteria2 UDP fragment count exceeds 255"))?;
    if fragment_count <= 1 {
        return Err(bad_wire(
            "Hysteria2 UDP fragmentation did not produce multiple fragments",
        ));
    }

    let mut fragments = Vec::with_capacity(fragment_count as usize);
    for (fragment_id, payload) in message.payload.chunks(max_fragment_payload).enumerate() {
        fragments.push(Hysteria2UdpMessage::from_parts(
            message.session_id,
            packet_id,
            fragment_id as u8,
            fragment_count,
            message.target.clone(),
            payload.to_vec(),
        )?);
    }
    Ok(fragments)
}

fn validate_udp_message_fields(
    _packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    target: &str,
    payload: &[u8],
) -> Result<(), OutboundError> {
    let payload_capacity = hysteria2_udp_payload_capacity(target)?;
    if payload.is_empty() || payload.len() > payload_capacity {
        return Err(bad_wire("invalid Hysteria2 UDP payload length"));
    }
    if fragment_count > 1 && fragment_id >= fragment_count {
        return Err(bad_wire(format!(
            "invalid Hysteria2 UDP fragment fields: fragment_id={fragment_id} fragment_count={fragment_count}"
        )));
    }
    Ok(())
}

fn validate_outbound_udp_message_identity(
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
) -> Result<(), OutboundError> {
    if fragment_count == 0 {
        return Err(bad_wire(
            "outbound Hysteria2 UDP message requires a fragment count",
        ));
    }
    if fragment_count == 1 && (fragment_id != 0 || packet_id != 0) {
        return Err(bad_wire(
            "complete Hysteria2 UDP message requires zero packet and fragment IDs",
        ));
    }
    if fragment_count > 1 && packet_id == 0 {
        return Err(bad_wire(
            "fragmented Hysteria2 UDP message requires a nonzero packet ID",
        ));
    }
    Ok(())
}

fn append_quic_varint(out: &mut Vec<u8>, value: u64) -> Result<(), OutboundError> {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => {
            out.push(((value >> 8) as u8) | 0x40);
            out.push(value as u8);
        }
        16_384..=1_073_741_823 => {
            out.push(((value >> 24) as u8) | 0x80);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            out.push(((value >> 56) as u8) | 0xc0);
            out.push((value >> 48) as u8);
            out.push((value >> 40) as u8);
            out.push((value >> 32) as u8);
            out.push((value >> 24) as u8);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        _ => return Err(bad_wire("Hysteria2 QUIC varint too large")),
    }
    Ok(())
}

fn read_quic_varint(input: &[u8], offset: usize) -> Result<(u64, usize), OutboundError> {
    let Some(&first) = input.get(offset) else {
        return Err(bad_wire("short Hysteria2 QUIC varint"));
    };
    let (tag, len) = (first >> 6, 1_usize << (first >> 6));
    if input.len() < offset + len {
        return Err(bad_wire("short Hysteria2 QUIC varint body"));
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[offset + 1..offset + len] {
        value = (value << 8) | u64::from(*byte);
    }
    if tag == 0 && value > 63 {
        return Err(bad_wire("non-canonical Hysteria2 QUIC varint"));
    }
    Ok((value, offset + len))
}

fn quic_varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

fn bad_wire(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_udp_encoder_matches_owned_message_wire() {
        let message = Hysteria2UdpMessage::new(7, "192.0.2.1:53", b"payload").unwrap();
        assert_eq!(
            encode_hysteria2_udp_payload(7, 0, 0, 1, "192.0.2.1:53", b"payload").unwrap(),
            encode_hysteria2_udp_message(&message).unwrap()
        );
    }

    #[test]
    fn tcp_request_padding_is_encoded_and_excluded_from_the_payload() {
        let padding = vec![b'p'; 257];
        let encoded = build_tcp_request_stream_with_padding(
            "target.example:443",
            b"application-payload",
            &padding,
        )
        .unwrap();
        let decoded = parse_tcp_request_stream(&encoded).unwrap();
        assert_eq!(decoded.target, "target.example:443");
        assert_eq!(decoded.payload, b"application-payload");
        assert_eq!(
            decoded.consumed_len,
            encoded.len() - b"application-payload".len()
        );
        assert!(
            build_tcp_request_stream_with_padding("target.example:443", &[], &vec![0; 4_097])
                .is_err()
        );
    }

    #[test]
    fn udp_message_roundtrips_supported_payload_and_address_shapes() {
        for target in ["192.0.2.1:53", "[2001:db8::1]:5353", "dns.example:853"] {
            let payload_capacity = hysteria2_udp_payload_capacity(target).unwrap();
            for payload_len in [1, 1_250, 1_400, 1_500, payload_capacity] {
                let payload = vec![payload_len as u8; payload_len];
                let message =
                    Hysteria2UdpMessage::new(0x1122_3344, target, payload.clone()).unwrap();
                let encoded = encode_hysteria2_udp_message(&message).unwrap();
                if payload_len == payload_capacity {
                    assert_eq!(encoded.len(), HYSTERIA2_MAX_UDP_MESSAGE_LENGTH);
                }
                let decoded = decode_hysteria2_udp_message(&encoded).unwrap();
                assert_eq!(decoded, message);
                assert_eq!(decoded.packet_id(), 0);
                assert_eq!(decoded.fragment_id(), 0);
                assert_eq!(decoded.fragment_count(), 1);
                assert_eq!(decoded.payload(), payload);
            }
        }
    }

    #[test]
    fn udp_message_rejects_empty_and_oversized_payloads() {
        assert!(Hysteria2UdpMessage::new(1, "192.0.2.1:53", Vec::new()).is_err());
        for target in ["192.0.2.1:53", "[2001:db8::1]:5353", "dns.example:853"] {
            let payload_capacity = hysteria2_udp_payload_capacity(target).unwrap();
            assert!(
                Hysteria2UdpMessage::new(1, target, vec![0; payload_capacity + 1]).is_err(),
                "{target} must reject a wire message larger than {HYSTERIA2_MAX_UDP_MESSAGE_LENGTH} bytes"
            );
        }
    }

    #[test]
    fn udp_message_limit_includes_the_wire_header() {
        let target = "127.0.0.1:39452";
        assert_eq!(hysteria2_udp_payload_capacity(target).unwrap(), 4_072);
        let maximum = Hysteria2UdpMessage::new(1, target, vec![0; 4_072]).unwrap();
        assert_eq!(
            encode_hysteria2_udp_message(&maximum).unwrap().len(),
            HYSTERIA2_MAX_UDP_MESSAGE_LENGTH
        );
        assert!(Hysteria2UdpMessage::new(1, target, vec![0; 4_073]).is_err());
    }

    #[test]
    fn udp_message_fragments_repeat_identity_and_reassemble_in_order() {
        let target = "[2001:db8::1]:5353";
        let payload_capacity = hysteria2_udp_payload_capacity(target).unwrap();
        let message =
            Hysteria2UdpMessage::new(0x0102_0304, target, vec![7; payload_capacity]).unwrap();
        let fragments = fragment_hysteria2_udp_message(&message, 0x7788, 1_250).unwrap();
        assert!(fragments.len() > 1);
        let mut reassembled = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment.session_id(), message.session_id());
            assert_eq!(fragment.packet_id(), 0x7788);
            assert_eq!(fragment.fragment_id(), index as u8);
            assert_eq!(fragment.fragment_count(), fragments.len() as u8);
            assert_eq!(fragment.target(), message.target());
            assert!(fragment.encoded_len() <= 1_250);
            let decoded =
                decode_hysteria2_udp_message(&encode_hysteria2_udp_message(fragment).unwrap())
                    .unwrap();
            reassembled.extend_from_slice(decoded.payload());
        }
        assert_eq!(reassembled, message.payload());
    }

    #[test]
    fn udp_fragmentation_rejects_invalid_wire_budget_and_packet_identity() {
        let message = Hysteria2UdpMessage::new(7, "dns.example:53", vec![1; 1_500]).unwrap();
        assert!(fragment_hysteria2_udp_message(&message, 0, 1_250).is_err());
        assert!(fragment_hysteria2_udp_message(&message, 1, message.encoded_len()).is_err());
        let header_len = message.encoded_len() - message.payload().len();
        assert!(fragment_hysteria2_udp_message(&message, 1, header_len).is_err());
        assert!(fragment_hysteria2_udp_message(&message, 1, header_len + 1).is_err());
    }

    #[test]
    fn udp_decoder_tolerates_irrelevant_complete_packet_identity() {
        let message = Hysteria2UdpMessage::new(7, "dns.example:53", vec![1]).unwrap();
        let encoded = encode_hysteria2_udp_message(&message).unwrap();

        let mut zero_fragments = encoded.clone();
        zero_fragments[7] = 0;
        let zero_fragments = decode_hysteria2_udp_message(&zero_fragments).unwrap();
        assert_eq!(zero_fragments.fragment_count(), 0);
        assert!(encode_hysteria2_udp_message(&zero_fragments).is_err());

        let mut wrong_fragment_id = encoded.clone();
        wrong_fragment_id[6] = 1;
        let wrong_fragment_id = decode_hysteria2_udp_message(&wrong_fragment_id).unwrap();
        assert_eq!(wrong_fragment_id.fragment_id(), 1);
        assert!(encode_hysteria2_udp_message(&wrong_fragment_id).is_err());

        let mut nonzero_complete_packet = encoded.clone();
        nonzero_complete_packet[5] = 1;
        let nonzero_complete_packet =
            decode_hysteria2_udp_message(&nonzero_complete_packet).unwrap();
        assert_eq!(nonzero_complete_packet.packet_id(), 1);
        assert!(encode_hysteria2_udp_message(&nonzero_complete_packet).is_err());
    }

    #[test]
    fn udp_decoder_accepts_zero_packet_id_for_fragmented_input() {
        let message = Hysteria2UdpMessage::new(7, "dns.example:53", vec![1]).unwrap();
        let mut encoded = encode_hysteria2_udp_message(&message).unwrap();
        encoded[7] = 2;
        let decoded = decode_hysteria2_udp_message(&encoded).unwrap();
        assert_eq!(decoded.packet_id(), 0);
        assert_eq!(decoded.fragment_id(), 0);
        assert_eq!(decoded.fragment_count(), 2);
        assert!(encode_hysteria2_udp_message(&decoded).is_err());
    }

    #[test]
    fn udp_decoder_keeps_fragment_index_and_address_bounds() {
        let message = Hysteria2UdpMessage::new(7, "dns.example:53", vec![1]).unwrap();
        let encoded = encode_hysteria2_udp_message(&message).unwrap();

        let mut invalid_fragment_id = encoded.clone();
        invalid_fragment_id[6] = 2;
        invalid_fragment_id[7] = 2;
        assert!(decode_hysteria2_udp_message(&invalid_fragment_id).is_err());

        let mut invalid_utf8 = encoded;
        invalid_utf8[9] = 0xff;
        assert!(decode_hysteria2_udp_message(&invalid_utf8).is_err());
    }
}
