use super::*;
pub(super) fn send_udp_reply(
    original_dst: SocketAddrV4,
    peer: SocketAddrV4,
    payload: &[u8],
) -> Result<(), String> {
    let reply = open_transparent_udp_socket_bound_in_netns(PRODUCTION_NETNS, original_dst)
        .map_err(|err| format!("open transparent UDP reply socket: {err}"))?;
    reply
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| format!("set UDP reply timeout: {err}"))?;
    reply
        .send_to(payload, peer)
        .map_err(|err| format!("send transparent UDP reply: {err}"))?;
    Ok(())
}

pub(super) fn read_vless_udp_response(
    client: &mut VlessTlsClient,
    flow: &str,
    user_uuid: [u8; 16],
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let mut plaintext = Vec::new();
    let mut buf = [0_u8; 2048];
    loop {
        if let Some(payload) = parse_vless_udp_response(&plaintext, flow, user_uuid)? {
            return Ok(payload);
        }
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err("VLESS UDP response timeout".to_owned());
        }
        let _ = drive_tls_io_blocking(client);
        loop {
            match client.read_plain(&mut buf) {
                Ok(0) => break,
                Ok(read) => plaintext.extend_from_slice(&buf[..read]),
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(format!("read VLESS UDP plaintext: {err}")),
            }
        }
        thread::sleep(RESIDENT_IDLE_SLEEP);
    }
}

pub(super) fn parse_vless_udp_response(
    input: &[u8],
    flow: &str,
    user_uuid: [u8; 16],
) -> Result<Option<Vec<u8>>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[0] != VLESS_RESPONSE_VERSION {
        return Err(format!("unexpected VLESS response version: {}", input[0]));
    }
    let header_len = 2 + input[1] as usize;
    if input.len() < header_len {
        return Ok(None);
    }
    if flow == XTLS_RPRX_VISION {
        if input.len() == header_len {
            return Ok(None);
        }
        let mut unpadder = VisionUnpadder::new(user_uuid);
        let payload = unpadder.consume(&input[header_len..])?;
        if payload.is_empty() && !matches!(unpadder.state, VisionUnpadState::Raw) {
            return Ok(None);
        }
        return parse_xudp_response_payload(&payload);
    }
    if input.len() < header_len + 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([input[header_len], input[header_len + 1]]) as usize;
    if input.len() < header_len + 2 + payload_len {
        return Ok(None);
    }
    Ok(Some(
        input[header_len + 2..header_len + 2 + payload_len].to_vec(),
    ))
}

pub(super) fn parse_xudp_response_payload(input: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    let metadata_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    let payload_len_offset = 2 + metadata_len;
    if input.len() < payload_len_offset + 2 {
        return Ok(None);
    }
    let payload_len =
        u16::from_be_bytes([input[payload_len_offset], input[payload_len_offset + 1]]) as usize;
    let payload_offset = payload_len_offset + 2;
    if input.len() < payload_offset + payload_len {
        return Ok(None);
    }
    Ok(Some(
        input[payload_offset..payload_offset + payload_len].to_vec(),
    ))
}
