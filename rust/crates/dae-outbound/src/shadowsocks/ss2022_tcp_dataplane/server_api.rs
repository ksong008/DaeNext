pub fn server_stream_decoder<S>(
    stream: &mut S,
    cipher: &str,
    password: &str,
    request_salt: &[u8],
) -> Result<(Ss2022TcpServerStreamDecoder, Ss2022TcpServerStreamStart), OutboundError>
where
    S: Read,
{
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("request", request_salt, conf.salt_len)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    let upsk = psk_list.last().ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 PSK list cannot be empty".to_owned())
    })?;

    let mut server_salt = vec![0_u8; conf.salt_len];
    stream
        .read_exact(&mut server_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut codec = Ss2022StreamCodec::new(&conf, upsk, &server_salt)?;
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
    Ok((
        Ss2022TcpServerStreamDecoder { codec },
        Ss2022TcpServerStreamStart {
            server_salt_len: server_salt.len(),
            response_header_type,
            request_salt_echo_validated: echoed_salt == request_salt,
            payload,
        },
    ))
}

pub fn read_client_request_from_stream<S>(
    stream: &mut S,
    cipher: &str,
    password: &str,
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError>
where
    S: Read,
{
    let conf = require_cipher_conf(cipher)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    let mut request_salt = vec![0_u8; conf.salt_len];
    stream
        .read_exact(&mut request_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    decode_client_request_after_salt(stream, &conf, &psk, &request_salt, expected_payload_len)
}

pub fn read_multi_psk_client_request_from_stream<S>(
    stream: &mut S,
    cipher: &str,
    password: &str,
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError>
where
    S: Read,
{
    let conf = require_cipher_conf(cipher)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    if psk_list.len() < 2 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 multi-PSK request reader requires at least two PSKs".to_owned(),
        ));
    }
    let mut request_salt = vec![0_u8; conf.salt_len];
    stream
        .read_exact(&mut request_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    decode_client_request_after_salt_with_psks(
        stream,
        &conf,
        &psk_list,
        &request_salt,
        expected_payload_len,
    )
}

pub fn encode_server_response(
    cipher: &str,
    password: &str,
    server_salt: &[u8],
    request_salt: &[u8],
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("server", server_salt, conf.salt_len)?;
    validate_salt_len("request", request_salt, conf.salt_len)?;
    if payload.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 server stream payload cannot be empty".to_owned(),
        ));
    }
    let psk = parse_single_psk(password, conf.key_len)?;
    encode_server_response_with_psk(&conf, &psk, server_salt, request_salt, payload, timestamp)
}

pub fn encode_multi_psk_server_response(
    cipher: &str,
    password: &str,
    server_salt: &[u8],
    request_salt: &[u8],
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("server", server_salt, conf.salt_len)?;
    validate_salt_len("request", request_salt, conf.salt_len)?;
    if payload.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 server stream payload cannot be empty".to_owned(),
        ));
    }
    let psk_list = parse_psk_list(password, conf.key_len)?;
    let upsk = psk_list.last().expect("validated psk list");
    encode_server_response_with_psk(&conf, upsk, server_salt, request_salt, payload, timestamp)
}

pub fn decode_client_request(
    cipher: &str,
    password: &str,
    input: &[u8],
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    if input.len() < conf.salt_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 client request missing salt".to_owned(),
        ));
    }
    let (salt, encrypted) = input.split_at(conf.salt_len);
    decode_client_request_after_salt(
        &mut std::io::Cursor::new(encrypted),
        &conf,
        &psk,
        salt,
        expected_payload_len,
    )
}
