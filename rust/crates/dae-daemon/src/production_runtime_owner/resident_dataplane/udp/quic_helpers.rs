use super::*;
pub(super) fn run_quic_udp_exchange<F>(label: &str, future: F) -> Result<UdpExchangeResult, String>
where
    F: std::future::Future<Output = Result<UdpExchangeResult, String>>,
{
    let runtime = runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("build {label} runtime: {err}"))?;
    runtime.block_on(async {
        time::timeout(
            RESIDENT_CONNECT_TIMEOUT + RESIDENT_UDP_RESPONSE_TIMEOUT,
            future,
        )
        .await
        .map_err(|_| format!("{label} timeout"))?
    })
}

#[allow(dead_code)]
pub(super) struct Hysteria2UdpMessage {
    pub(super) session_id: u32,
    pub(super) packet_id: u16,
    pub(super) payload: Vec<u8>,
}

pub(super) fn build_hysteria2_udp_message(
    session_id: u32,
    packet_id: u16,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if payload.is_empty() || payload.len() > 4096 {
        return Err(format!(
            "invalid Hysteria2 UDP payload length: {}",
            payload.len()
        ));
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

pub(super) fn parse_hysteria2_udp_message(input: &[u8]) -> Result<Hysteria2UdpMessage, String> {
    if input.len() < 9 {
        return Err("short Hysteria2 UDP message".to_owned());
    }
    let session_id = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let frag_id = input[6];
    let frag_count = input[7];
    let (addr_len, mut offset) = read_quic_varint(input, 8)?;
    let addr_len =
        usize::try_from(addr_len).map_err(|_| "Hysteria2 UDP address too large".to_owned())?;
    if frag_id != 0 || frag_count != 1 {
        return Err(format!(
            "fragmented Hysteria2 UDP response is unsupported: frag_id={frag_id} frag_count={frag_count}"
        ));
    }
    if addr_len == 0 || input.len() <= offset + addr_len {
        return Err("invalid Hysteria2 UDP address length".to_owned());
    }
    offset += addr_len;
    Ok(Hysteria2UdpMessage {
        session_id,
        packet_id,
        payload: input[offset..].to_vec(),
    })
}

#[allow(dead_code)]
pub(super) struct TuicPacketFrame {
    pub(super) assoc_id: u16,
    pub(super) packet_id: u16,
    pub(super) payload: Vec<u8>,
}

pub(super) fn build_tuic_packet_frame(
    assoc_id: u16,
    packet_id: u16,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return Err(format!(
            "invalid TUIC UDP payload length: {}",
            payload.len()
        ));
    }
    let target = Socks5Address::parse(target).map_err(|err| format!("parse TUIC target: {err}"))?;
    let mut out = Vec::with_capacity(10 + payload.len() + 32);
    out.push(0x05);
    out.push(0x02);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    write_tuic_address(&target, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub(super) fn parse_tuic_packet_frame(input: &[u8]) -> Result<TuicPacketFrame, String> {
    if input.len() < 10 {
        return Err("short TUIC packet frame".to_owned());
    }
    if input[1] != 0x02 {
        return Err(format!("bad TUIC packet command type: {:#x}", input[1]));
    }
    let assoc_id = u16::from_be_bytes([input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let frag_total = input[6];
    let frag_id = input[7];
    let size = u16::from_be_bytes([input[8], input[9]]) as usize;
    if frag_total != 1 || frag_id != 0 {
        return Err(format!(
            "fragmented TUIC UDP response is unsupported: frag_total={frag_total} frag_id={frag_id}"
        ));
    }
    let offset = read_tuic_address(input, 10)?;
    let payload_end = offset + size;
    if input.len() != payload_end {
        return Err("TUIC packet payload length mismatch".to_owned());
    }
    Ok(TuicPacketFrame {
        assoc_id,
        packet_id,
        payload: input[offset..payload_end].to_vec(),
    })
}

pub(super) fn write_tuic_address(address: &Socks5Address, out: &mut Vec<u8>) -> Result<(), String> {
    match address {
        Socks5Address::Ipv4 { addr, port } => {
            out.push(1);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Ipv6 { addr, port } => {
            out.push(2);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Domain { hostname, port } => {
            if hostname.len() > u8::MAX as usize {
                return Err("TUIC domain address too long".to_owned());
            }
            out.push(0);
            out.push(hostname.len() as u8);
            out.extend_from_slice(hostname.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

pub(super) fn read_tuic_address(input: &[u8], offset: usize) -> Result<usize, String> {
    let Some(&atyp) = input.get(offset) else {
        return Err("missing TUIC address type".to_owned());
    };
    let mut cursor = offset + 1;
    match atyp {
        0 => {
            let Some(&len) = input.get(cursor) else {
                return Err("missing TUIC domain length".to_owned());
            };
            cursor += 1 + len as usize;
        }
        1 => cursor += 4,
        2 => cursor += 16,
        255 => return Ok(cursor),
        value => return Err(format!("unsupported TUIC address type: {value}")),
    }
    if input.len() < cursor + 2 {
        return Err("short TUIC address port".to_owned());
    }
    Ok(cursor + 2)
}

pub(super) fn build_juicity_stream_packet_request(
    target: &str,
    frame: &[u8],
) -> Result<Vec<u8>, String> {
    let metadata = dae_outbound::trojan::TrojanMetadata::parse("udp", target)
        .map_err(|err| format!("build Juicity UDP metadata: {err}"))?;
    let metadata = metadata
        .encode()
        .map_err(|err| format!("encode Juicity UDP metadata: {err}"))?;
    let mut out = Vec::with_capacity(1 + metadata.len() + frame.len());
    out.push(3);
    out.extend_from_slice(&metadata);
    out.extend_from_slice(frame);
    Ok(out)
}

pub(super) fn append_quic_varint(out: &mut Vec<u8>, value: u64) -> Result<(), String> {
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
        _ => return Err(format!("QUIC varint too large: {value}")),
    }
    Ok(())
}

pub(super) fn read_quic_varint(input: &[u8], offset: usize) -> Result<(u64, usize), String> {
    let Some(&first) = input.get(offset) else {
        return Err("missing QUIC varint".to_owned());
    };
    match first >> 6 {
        0 => Ok(((first & 0x3f) as u64, offset + 1)),
        1 => {
            if input.len() < offset + 2 {
                return Err("short two-byte QUIC varint".to_owned());
            }
            Ok((
                (((first & 0x3f) as u64) << 8) | input[offset + 1] as u64,
                offset + 2,
            ))
        }
        2 => {
            if input.len() < offset + 4 {
                return Err("short four-byte QUIC varint".to_owned());
            }
            Ok((
                (((first & 0x3f) as u64) << 24)
                    | ((input[offset + 1] as u64) << 16)
                    | ((input[offset + 2] as u64) << 8)
                    | input[offset + 3] as u64,
                offset + 4,
            ))
        }
        _ => Err("eight-byte QUIC varint is not needed for UDP address length".to_owned()),
    }
}
