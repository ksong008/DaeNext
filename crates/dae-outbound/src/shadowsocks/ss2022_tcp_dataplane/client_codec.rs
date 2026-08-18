use super::*;
/// F-08: SS2022 请求时间戳可接受的最大偏差（秒）。
pub(crate) const SS2022_TIMESTAMP_TOLERANCE_SECS: i64 = 90;

pub(super) fn encode_client_initial_with_timestamp(
    conf: &CipherConf2022,
    psk: &[u8],
    salt: &[u8],
    target: &Socks5Address,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    encode_client_initial_with_psks(conf, &[psk.to_vec()], salt, target, payload, timestamp)
}

pub(super) fn encode_client_initial_with_psks(
    conf: &CipherConf2022,
    psk_list: &[Vec<u8>],
    salt: &[u8],
    target: &Socks5Address,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let upsk = psk_list.last().ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 PSK list cannot be empty".to_owned())
    })?;
    let mut var_header = target.encode()?;
    let padding_len = if payload.is_empty() { 1 } else { 0 };
    var_header.extend_from_slice(&(padding_len as u16).to_be_bytes());
    if padding_len > 0 {
        var_header.push(0);
    }
    let initial_payload_len = payload
        .len()
        .min(TCP_CHUNK_MAX_LEN.saturating_sub(var_header.len()));
    var_header.extend_from_slice(&payload[..initial_payload_len]);
    if var_header.len() > TCP_CHUNK_MAX_LEN {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 initial variable header too large: {}",
            var_header.len()
        )));
    }

    let mut fixed_header = Vec::with_capacity(11);
    fixed_header.push(HEADER_TYPE_CLIENT_STREAM);
    fixed_header.extend_from_slice(&timestamp.to_be_bytes());
    fixed_header.extend_from_slice(&(var_header.len() as u16).to_be_bytes());

    let identity_headers = encode_identity_headers(conf, psk_list, salt)?;
    let mut codec = Ss2022StreamCodec::new(conf, upsk, salt)?;
    let mut out = Vec::with_capacity(salt.len() + fixed_header.len() + var_header.len() + 32);
    out.extend_from_slice(salt);
    out.extend_from_slice(&identity_headers);
    out.extend_from_slice(&codec.encrypt_next(&fixed_header)?);
    out.extend_from_slice(&codec.encrypt_next(&var_header)?);
    for chunk in payload[initial_payload_len..].chunks(TCP_CHUNK_MAX_LEN) {
        out.extend_from_slice(&codec.encrypt_next(&(chunk.len() as u16).to_be_bytes())?);
        out.extend_from_slice(&codec.encrypt_next(chunk)?);
    }
    Ok(out)
}

pub(super) fn decode_client_request_after_salt<S>(
    stream: &mut S,
    conf: &CipherConf2022,
    psk: &[u8],
    request_salt: &[u8],
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError>
where
    S: Read,
{
    decode_client_request_after_salt_with_psks(
        stream,
        conf,
        &[psk.to_vec()],
        request_salt,
        expected_payload_len,
    )
}

pub(super) fn decode_client_request_after_salt_with_psks<S>(
    stream: &mut S,
    conf: &CipherConf2022,
    psk_list: &[Vec<u8>],
    request_salt: &[u8],
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError>
where
    S: Read,
{
    decode_client_request_after_salt_with_psks_and_freshness(
        stream,
        conf,
        psk_list,
        request_salt,
        expected_payload_len,
        unix_timestamp_now() as i64,
        SS2022_TIMESTAMP_TOLERANCE_SECS,
    )
}

/// F-08: 服务端请求解码含 timestamp freshness 校验（重放窗口收窄）。
pub(super) fn decode_client_request_after_salt_with_psks_and_freshness<S>(
    stream: &mut S,
    conf: &CipherConf2022,
    psk_list: &[Vec<u8>],
    request_salt: &[u8],
    expected_payload_len: usize,
    now_unix: i64,
    tolerance_secs: i64,
) -> Result<Ss2022TcpClientRequest, OutboundError>
where
    S: Read,
{
    let upsk = psk_list.last().ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 PSK list cannot be empty".to_owned())
    })?;
    let identity = read_and_validate_identity_headers(stream, conf, psk_list, request_salt)?;
    let mut codec = Ss2022StreamCodec::new(conf, upsk, request_salt)?;
    let fixed_header = read_encrypted_exact(stream, &mut codec, 11)?;
    if fixed_header.len() != 11 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 fixed header length mismatch".to_owned(),
        ));
    }
    let request_header_type = fixed_header[0];
    if request_header_type != HEADER_TYPE_CLIENT_STREAM {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 unexpected client header type: {request_header_type}"
        )));
    }
    let timestamp = u64::from_be_bytes([
        fixed_header[1],
        fixed_header[2],
        fixed_header[3],
        fixed_header[4],
        fixed_header[5],
        fixed_header[6],
        fixed_header[7],
        fixed_header[8],
    ]);
    // F-08: freshness 校验——超出容差的重放请求直接拒绝。
    let timestamp_diff = (now_unix as i128 - timestamp as i128).unsigned_abs();
    if timestamp_diff > tolerance_secs as u128 {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 request timestamp out of tolerance: |now - ts| = {timestamp_diff}s > {tolerance_secs}s"
        )));
    }
    let var_header_len = u16::from_be_bytes([fixed_header[9], fixed_header[10]]) as usize;
    let var_header = read_encrypted_exact(stream, &mut codec, var_header_len)?;
    let (target, consumed) = Socks5Address::decode(&var_header)?;
    if var_header.len() < consumed + 2 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 variable header missing padding length".to_owned(),
        ));
    }
    let padding_len = u16::from_be_bytes([var_header[consumed], var_header[consumed + 1]]) as usize;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 padding too large: {padding_len}"
        )));
    }
    let payload_offset = consumed + 2 + padding_len;
    if var_header.len() < payload_offset {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 variable header padding overflows".to_owned(),
        ));
    }
    let mut payload = var_header[payload_offset..].to_vec();
    while payload.len() < expected_payload_len {
        let len_plain = read_encrypted_exact(stream, &mut codec, 2)?;
        let chunk_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        let chunk = read_encrypted_exact(stream, &mut codec, chunk_len)?;
        payload.extend_from_slice(&chunk);
    }

    Ok(Ss2022TcpClientRequest {
        target: target.authority(),
        request_salt_len: request_salt.len(),
        psk_count: psk_list.len(),
        upsk_index: psk_list.len() - 1,
        request_header_type,
        timestamp,
        fixed_header_len: fixed_header.len(),
        variable_header_len: var_header_len,
        target_metadata_len: consumed,
        padding_len,
        identity_header_count: identity.count,
        identity_header_bytes_len: identity.bytes_len,
        identity_header_validated: identity.validated,
        payload,
    })
}
