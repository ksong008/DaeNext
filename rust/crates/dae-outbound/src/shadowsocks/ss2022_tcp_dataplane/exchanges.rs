use super::*;
pub fn tcp_exchange(
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: Ss2022TcpSalts<'_>,
    timeout: Duration,
) -> Result<Ss2022TcpExchangeReport, OutboundError> {
    let mut stream =
        TcpStream::connect(server).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;

    tcp_exchange_over_stream(
        &mut stream,
        server,
        cipher,
        password,
        target,
        payload,
        salts,
    )
}

pub fn tcp_exchange_over_stream<S>(
    stream: &mut S,
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: Ss2022TcpSalts<'_>,
) -> Result<Ss2022TcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("client", salts.client, conf.salt_len)?;
    validate_salt_len("server", salts.server, conf.salt_len)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    let target_addr = Socks5Address::parse(target)?;
    let target_metadata_len = target_addr.encode()?.len();
    let initial_payload_len = payload
        .len()
        .min(TCP_CHUNK_MAX_LEN.saturating_sub(target_metadata_len + 2));
    let variable_header_len =
        target_metadata_len + 2 + if payload.is_empty() { 1 } else { 0 } + initial_payload_len;
    let request = encode_client_initial_with_timestamp(
        &conf,
        &psk,
        salts.client,
        &target_addr,
        payload,
        unix_timestamp_now(),
    )?;

    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let response = read_server_stream(stream, &conf, &psk, salts.client)?;

    Ok(Ss2022TcpExchangeReport {
        server: server.to_owned(),
        target: target_addr.authority(),
        cipher: conf.cipher.to_owned(),
        psk_count: 1,
        upsk_index: 0,
        key_len: conf.key_len,
        client_salt_len: salts.client.len(),
        server_salt_len: response.server_salt_len,
        request_header_type: HEADER_TYPE_CLIENT_STREAM,
        response_header_type: response.response_header_type,
        fixed_header_len: 11,
        variable_header_len,
        target_metadata_len,
        request_salt_echo_validated: response.request_salt_echo_validated,
        identity_header_count: 0,
        identity_header_bytes_len: 0,
        identity_header_validated: true,
        payload_len: payload.len(),
        echoed_payload: response.payload,
        multi_psk_identity_header_dataplane_admitted: false,
        ss2022_udp_true_dataplane_admitted: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_multi_psk_exchange_over_stream<S>(
    stream: &mut S,
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: Ss2022TcpSalts<'_>,
) -> Result<Ss2022TcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("client", salts.client, conf.salt_len)?;
    validate_salt_len("server", salts.server, conf.salt_len)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    if psk_list.len() < 2 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 TCP multi-PSK dataplane requires at least two PSKs".to_owned(),
        ));
    }
    let upsk = psk_list.last().expect("validated psk list");
    let target_addr = Socks5Address::parse(target)?;
    let target_metadata_len = target_addr.encode()?.len();
    let initial_payload_len = payload
        .len()
        .min(TCP_CHUNK_MAX_LEN.saturating_sub(target_metadata_len + 2));
    let variable_header_len =
        target_metadata_len + 2 + if payload.is_empty() { 1 } else { 0 } + initial_payload_len;
    let identity_header_count = psk_list.len() - 1;
    let request = encode_client_initial_with_psks(
        &conf,
        &psk_list,
        salts.client,
        &target_addr,
        payload,
        unix_timestamp_now(),
    )?;

    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let response = read_server_stream(stream, &conf, upsk, salts.client)?;

    Ok(Ss2022TcpExchangeReport {
        server: server.to_owned(),
        target: target_addr.authority(),
        cipher: conf.cipher.to_owned(),
        psk_count: psk_list.len(),
        upsk_index: psk_list.len() - 1,
        key_len: conf.key_len,
        client_salt_len: salts.client.len(),
        server_salt_len: response.server_salt_len,
        request_header_type: HEADER_TYPE_CLIENT_STREAM,
        response_header_type: response.response_header_type,
        fixed_header_len: 11,
        variable_header_len,
        target_metadata_len,
        request_salt_echo_validated: response.request_salt_echo_validated,
        identity_header_count,
        identity_header_bytes_len: identity_header_count * 16,
        identity_header_validated: true,
        payload_len: payload.len(),
        echoed_payload: response.payload,
        multi_psk_identity_header_dataplane_admitted: true,
        ss2022_udp_true_dataplane_admitted: false,
        true_dataplane: true,
        default_go_path: true,
    })
}
