pub fn encode_client_initial(
    cipher: &str,
    password: &str,
    salt: &[u8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("client", salt, conf.salt_len)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    let target_addr = Socks5Address::parse(target)?;
    encode_client_initial_with_timestamp(&conf, &psk, salt, &target_addr, payload, timestamp)
}

pub fn encode_multi_psk_client_initial(
    cipher: &str,
    password: &str,
    salt: &[u8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("client", salt, conf.salt_len)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    if psk_list.len() < 2 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 multi-PSK client initial requires at least two PSKs".to_owned(),
        ));
    }
    let target_addr = Socks5Address::parse(target)?;
    encode_client_initial_with_psks(&conf, &psk_list, salt, &target_addr, payload, timestamp)
}

pub fn client_stream_encoder(
    cipher: &str,
    password: &str,
    salt: &[u8],
    target: &str,
    initial_payload: &[u8],
    timestamp: u64,
) -> Result<(Ss2022TcpClientStreamEncoder, Vec<u8>), OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("client", salt, conf.salt_len)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    let upsk = psk_list.last().ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 PSK list cannot be empty".to_owned())
    })?;
    let target_addr = Socks5Address::parse(target)?;
    let mut var_header = target_addr.encode()?;
    let padding_len = if initial_payload.is_empty() { 1 } else { 0 };
    var_header.extend_from_slice(&(padding_len as u16).to_be_bytes());
    if padding_len > 0 {
        var_header.push(0);
    }
    let initial_payload_len = initial_payload
        .len()
        .min(TCP_CHUNK_MAX_LEN.saturating_sub(var_header.len()));
    var_header.extend_from_slice(&initial_payload[..initial_payload_len]);

    let mut fixed_header = Vec::with_capacity(11);
    fixed_header.push(HEADER_TYPE_CLIENT_STREAM);
    fixed_header.extend_from_slice(&timestamp.to_be_bytes());
    fixed_header.extend_from_slice(&(var_header.len() as u16).to_be_bytes());

    let identity_headers = encode_identity_headers(&conf, &psk_list, salt)?;
    let mut codec = Ss2022StreamCodec::new(&conf, upsk, salt)?;
    let mut out = Vec::with_capacity(salt.len() + fixed_header.len() + var_header.len() + 32);
    out.extend_from_slice(salt);
    out.extend_from_slice(&identity_headers);
    out.extend_from_slice(&codec.encrypt_next(&fixed_header)?);
    out.extend_from_slice(&codec.encrypt_next(&var_header)?);

    let mut encoder = Ss2022TcpClientStreamEncoder { codec };
    if initial_payload_len < initial_payload.len() {
        out.extend_from_slice(&encoder.encode_chunk(&initial_payload[initial_payload_len..])?);
    }
    Ok((encoder, out))
}
