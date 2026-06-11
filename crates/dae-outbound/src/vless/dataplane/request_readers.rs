use super::*;
pub fn read_tcp_request_from_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessTcpRequest, OutboundError>
where
    S: Read,
{
    let header = read_request_header(stream)?;
    if header.command != VMessNetwork::Tcp.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS TCP command: {}",
            header.command
        )));
    }

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless payload")?;
    Ok(VlessTcpRequest {
        version: header.version,
        key: header.key,
        key_hex: header.key_hex,
        addons_len: header.addons_len,
        command: header.command,
        target: header.target,
        payload,
        header_len: header.header_len,
    })
}

pub fn read_udp_request_from_stream<S>(stream: &mut S) -> Result<VlessUdpRequest, OutboundError>
where
    S: Read,
{
    let header = read_request_header(stream)?;
    if header.command != VMessNetwork::Udp.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS UDP command: {}",
            header.command
        )));
    }

    let mut length = [0_u8; 2];
    read_exact(stream, &mut length, "vless udp payload length")?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless udp payload")?;
    Ok(VlessUdpRequest {
        version: header.version,
        key: header.key,
        key_hex: header.key_hex,
        addons_len: header.addons_len,
        command: header.command,
        target: header.target,
        payload_len,
        payload,
        header_len: header.header_len,
        packet_len: 2 + payload_len,
    })
}

pub fn read_mux_request_from_stream<S>(stream: &mut S) -> Result<VlessMuxRequest, OutboundError>
where
    S: Read,
{
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless mux version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS mux version: {}",
            version[0]
        )));
    }

    let mut key = [0_u8; 16];
    read_exact(stream, &mut key, "vless mux key")?;

    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless mux addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless mux addons")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "vless mux command")?;
    if command[0] != VMessNetwork::Mux.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS mux command: {}",
            command[0]
        )));
    }

    Ok(VlessMuxRequest {
        version: version[0],
        key,
        key_hex: hex_encode(&key),
        addons_len,
        command: command[0],
        header_len: 1 + 16 + 1 + addons_len + 1,
    })
}
