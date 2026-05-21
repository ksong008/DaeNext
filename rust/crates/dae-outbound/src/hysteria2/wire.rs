use crate::error::OutboundError;

pub const HYSTERIA2_FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TcpRequestFrame {
    pub(super) target: String,
    pub(super) payload: Vec<u8>,
    pub(super) consumed_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TcpResponseFrame {
    pub(super) ok: bool,
    pub(super) message: String,
    pub(super) payload: Vec<u8>,
    pub(super) consumed_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UdpMessageFrame {
    pub(super) session_id: u32,
    pub(super) packet_id: u16,
    pub(super) frag_id: u8,
    pub(super) frag_count: u8,
    pub(super) target: String,
    pub(super) payload: Vec<u8>,
}

pub(super) fn build_tcp_request_stream(
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if target.is_empty() {
        return Err(bad_wire("Hysteria2 TCP target cannot be empty"));
    }
    let mut out = Vec::with_capacity(16 + target.len() + payload.len());
    append_quic_varint(&mut out, HYSTERIA2_FRAME_TYPE_TCP_REQUEST)?;
    append_quic_varint(&mut out, target.len() as u64)?;
    out.extend_from_slice(target.as_bytes());
    append_quic_varint(&mut out, 0)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub(super) fn parse_tcp_request_stream(input: &[u8]) -> Result<TcpRequestFrame, OutboundError> {
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

pub(super) fn build_tcp_response_stream(
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

pub(super) fn parse_tcp_response_stream(input: &[u8]) -> Result<TcpResponseFrame, OutboundError> {
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

pub(super) fn build_udp_message(
    session_id: u32,
    packet_id: u16,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if target.is_empty() {
        return Err(bad_wire("Hysteria2 UDP target cannot be empty"));
    }
    if payload.is_empty() || payload.len() > 4096 {
        return Err(bad_wire("invalid Hysteria2 UDP payload length"));
    }
    let mut out = Vec::with_capacity(16 + target.len() + payload.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(0);
    out.push(1);
    append_quic_varint(&mut out, target.len() as u64)?;
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub(super) fn parse_udp_message(input: &[u8]) -> Result<UdpMessageFrame, OutboundError> {
    if input.len() < 9 {
        return Err(bad_wire("short Hysteria2 UDP message"));
    }
    let session_id = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let frag_id = input[6];
    let frag_count = input[7];
    let (addr_len, mut offset) = read_quic_varint(input, 8)?;
    let addr_len =
        usize::try_from(addr_len).map_err(|_| bad_wire("Hysteria2 UDP address too large"))?;
    if addr_len == 0 || input.len() <= offset + addr_len {
        return Err(bad_wire("invalid Hysteria2 UDP address length"));
    }
    let target = String::from_utf8(input[offset..offset + addr_len].to_vec())
        .map_err(|err| bad_wire(format!("Hysteria2 UDP target utf8: {err}")))?;
    offset += addr_len;
    Ok(UdpMessageFrame {
        session_id,
        packet_id,
        frag_id,
        frag_count,
        target,
        payload: input[offset..].to_vec(),
    })
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

fn bad_wire(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
