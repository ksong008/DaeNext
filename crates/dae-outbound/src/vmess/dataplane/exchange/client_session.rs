use super::*;
pub fn aead_tcp_client_session_start(
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadTcpClientSessionStart, OutboundError> {
    aead_tcp_client_session_start_with_security(uuid, target, payload, VMessBodySecurity::Aes128Gcm)
}

pub fn aead_tcp_client_session_start_with_security(
    uuid: &str,
    target: &str,
    payload: &[u8],
    security: VMessBodySecurity,
) -> Result<VMessAeadTcpClientSessionStart, OutboundError> {
    aead_client_session_start(uuid, target, VMessNetwork::Tcp, payload, security)
}

pub fn aead_udp_over_tcp_client_session_start(
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadTcpClientSessionStart, OutboundError> {
    aead_udp_over_tcp_client_session_start_with_security(
        uuid,
        target,
        payload,
        VMessBodySecurity::Aes128Gcm,
    )
}

pub fn aead_udp_over_tcp_client_session_start_with_security(
    uuid: &str,
    target: &str,
    payload: &[u8],
    security: VMessBodySecurity,
) -> Result<VMessAeadTcpClientSessionStart, OutboundError> {
    aead_client_session_start(uuid, target, VMessNetwork::Udp, payload, security)
}

fn aead_client_session_start(
    uuid: &str,
    target: &str,
    network: VMessNetwork,
    payload: &[u8],
    security: VMessBodySecurity,
) -> Result<VMessAeadTcpClientSessionStart, OutboundError> {
    let material = VMessAeadMaterial::random();
    let normalized_uuid = normalize_vmess_uuid(uuid);
    let cmd_key = vmess_cmd_key_from_uuid(&normalized_uuid)?;
    let eauth_id = put_eauth_id(&cmd_key, unix_timestamp_now()?, material.eauth_random)?;
    let instruction = request_instruction(&material, target, network, security)?;
    let header = encrypt_request_header(
        &cmd_key,
        &eauth_id,
        &material.connection_nonce,
        &instruction,
    )?;
    let parsed = parse_instruction(&instruction)?;
    let mut codec = BodyCodec::new(
        parsed.request_body_key,
        parsed.request_body_iv,
        parsed.request_options,
    )?;
    let chunk = if payload.is_empty() {
        Vec::new()
    } else {
        codec.seal_chunk(payload)?
    };
    let mut first_write = Vec::with_capacity(header.len() + chunk.len());
    first_write.extend_from_slice(&header);
    first_write.extend_from_slice(&chunk);
    let request = VMessAeadTcpRequest {
        version: parsed.version,
        uuid: normalized_uuid,
        cmd_key_hex: hex_encode(&cmd_key),
        eauth_crc_validated: true,
        eauth_timestamp: 0,
        request_options: parsed.request_options,
        security: parsed.security,
        command: parsed.command,
        target: parsed.target,
        payload: payload.to_vec(),
        request_header_len: header.len(),
        request_chunk_len: chunk.len(),
        response_auth: parsed.response_auth,
        request_body_iv: parsed.request_body_iv,
        request_body_key: parsed.request_body_key,
        response_body_iv: parsed.response_body_iv,
        response_body_key: parsed.response_body_key,
    };
    Ok(VMessAeadTcpClientSessionStart {
        first_write,
        request,
        upload: VMessAeadTcpUploadCodec { codec },
    })
}

impl VMessAeadTcpUploadCodec {
    pub fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
        self.codec.seal_chunk(payload)
    }
}

impl VMessAeadTcpResponseReader {
    pub fn read_chunk_from_stream<S>(&mut self, stream: &mut S) -> Result<Vec<u8>, OutboundError>
    where
        S: Read,
    {
        self.codec.open_chunk(stream).map(|(payload, _)| payload)
    }

    pub async fn read_chunk_from_async_stream<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<Vec<u8>, OutboundError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        self.codec
            .open_chunk_async(stream)
            .await
            .map(|(payload, _)| payload)
    }

    pub fn try_read_chunk_from_buffer(
        &mut self,
        input: &mut Vec<u8>,
    ) -> Result<Option<Vec<u8>>, OutboundError> {
        self.codec
            .try_open_chunk_from_buffer(input, &mut self.pending_chunk)
    }
}

pub fn aead_tcp_response_reader_from_stream<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
) -> Result<VMessAeadTcpResponseReader, OutboundError>
where
    S: Read,
{
    let response_header_len = read_aead_response_header(stream, request)?;
    let codec = BodyCodec::new(
        request.response_body_key,
        request.response_body_iv,
        request.request_options,
    )?;
    Ok(VMessAeadTcpResponseReader {
        response_header_len,
        codec,
        pending_chunk: None,
    })
}

pub async fn aead_tcp_response_reader_from_async_stream<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
) -> Result<VMessAeadTcpResponseReader, OutboundError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let response_header_len = read_aead_response_header_async(stream, request).await?;
    let codec = BodyCodec::new(
        request.response_body_key,
        request.response_body_iv,
        request.request_options,
    )?;
    Ok(VMessAeadTcpResponseReader {
        response_header_len,
        codec,
        pending_chunk: None,
    })
}

pub fn aead_tcp_response_reader_from_buffer(
    input: &mut Vec<u8>,
    request: &VMessAeadTcpRequest,
) -> Result<Option<VMessAeadTcpResponseReader>, OutboundError> {
    try_aead_tcp_response_reader_from_buffer(input, request)
}
