use super::*;
#[derive(Debug)]
pub(super) struct Ss2022ServerResponse {
    pub(super) server_salt_len: usize,
    pub(super) response_header_type: u8,
    pub(super) request_salt_echo_validated: bool,
    pub(super) payload: Vec<u8>,
}

pub(super) fn read_server_stream<S>(
    stream: &mut S,
    conf: &CipherConf2022,
    psk: &[u8],
    request_salt: &[u8],
) -> Result<Ss2022ServerResponse, OutboundError>
where
    S: Read,
{
    let mut server_salt = vec![0_u8; conf.salt_len];
    stream
        .read_exact(&mut server_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut codec = Ss2022StreamCodec::new(conf, psk, &server_salt)?;
    let header_len = 1 + 8 + conf.salt_len + 2;
    let header = read_encrypted_exact(stream, &mut codec, header_len)?;
    let response_header_type = header[0];
    if response_header_type != HEADER_TYPE_SERVER_STREAM {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 unexpected server header type: {response_header_type}"
        )));
    }
    let salt_start = 1 + 8;
    let salt_end = salt_start + conf.salt_len;
    let echoed_salt = &header[salt_start..salt_end];
    let payload_len = u16::from_be_bytes([header[salt_end], header[salt_end + 1]]) as usize;
    if payload_len == 0 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 server payload length cannot be zero".to_owned(),
        ));
    }
    let payload = read_encrypted_exact(stream, &mut codec, payload_len)?;
    Ok(Ss2022ServerResponse {
        server_salt_len: server_salt.len(),
        response_header_type,
        request_salt_echo_validated: echoed_salt == request_salt,
        payload,
    })
}

pub(super) fn read_encrypted_exact<S>(
    stream: &mut S,
    codec: &mut Ss2022StreamCodec,
    plaintext_len: usize,
) -> Result<Vec<u8>, OutboundError>
where
    S: Read,
{
    let mut encrypted = vec![0_u8; plaintext_len + codec.tag_len];
    stream
        .read_exact(&mut encrypted)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    codec.decrypt_next(&encrypted)
}

pub(super) fn encode_server_response_with_psk(
    conf: &CipherConf2022,
    psk: &[u8],
    server_salt: &[u8],
    request_salt: &[u8],
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let mut codec = Ss2022StreamCodec::new(conf, psk, server_salt)?;
    let mut header = Vec::with_capacity(11 + request_salt.len());
    header.push(HEADER_TYPE_SERVER_STREAM);
    header.extend_from_slice(&timestamp.to_be_bytes());
    header.extend_from_slice(request_salt);
    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());

    let mut out = Vec::with_capacity(server_salt.len() + header.len() + payload.len() + 32);
    out.extend_from_slice(server_salt);
    out.extend_from_slice(&codec.encrypt_next(&header)?);
    out.extend_from_slice(&codec.encrypt_next(payload)?);
    Ok(out)
}
