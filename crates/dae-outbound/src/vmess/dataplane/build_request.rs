use super::*;

pub(super) fn build_aead_request(
    uuid: &str,
    target: &str,
    network: VMessNetwork,
    payload: &[u8],
) -> Result<VMessAeadRequestPacket, OutboundError> {
    let packet = build_aead_request_chunks(uuid, target, network, &[payload])?;
    let chunk = packet
        .chunks
        .into_iter()
        .next()
        .ok_or_else(|| OutboundError::BadVmess("missing VMess request chunk".to_owned()))?;
    Ok(VMessAeadRequestPacket {
        header: packet.header,
        chunk,
        request: packet.request,
    })
}

pub(super) fn build_aead_request_chunks(
    uuid: &str,
    target: &str,
    network: VMessNetwork,
    payloads: &[&[u8]],
) -> Result<VMessAeadChunkedRequestPacket, OutboundError> {
    let material = VMessAeadMaterial::random()?;
    let normalized_uuid = normalize_vmess_uuid(uuid);
    let cmd_key = vmess_cmd_key_from_uuid(&normalized_uuid)?;
    let eauth_id = put_eauth_id(&cmd_key, unix_timestamp_now()?, material.eauth_random)?;
    let instruction =
        request_instruction(&material, target, network, VMessBodySecurity::Aes128Gcm)?;
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
        parsed.security,
        parsed.request_options,
    )?;
    let mut chunks = Vec::with_capacity(payloads.len());
    let mut request_chunk_len = 0_usize;
    let mut payload = Vec::new();
    for item in payloads {
        let chunk = codec.seal_chunk(item)?;
        request_chunk_len += chunk.len();
        payload.extend_from_slice(item);
        chunks.push(chunk);
    }
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
        payload,
        request_header_len: header.len(),
        request_chunk_len,
        response_auth: parsed.response_auth,
        request_body_iv: parsed.request_body_iv,
        request_body_key: parsed.request_body_key,
        response_body_iv: parsed.response_body_iv,
        response_body_key: parsed.response_body_key,
    };
    Ok(VMessAeadChunkedRequestPacket {
        header,
        chunks,
        request,
    })
}

pub(super) fn read_mux_frame_from_bytes(input: &[u8]) -> Result<mux::MuxFrame, OutboundError> {
    let mut cursor = Cursor::new(input);
    let frame = mux::read_mux_frame(&mut cursor)?;
    if cursor.position() as usize != input.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess mux frame has trailing bytes: {}",
            input.len() - cursor.position() as usize
        )));
    }
    Ok(frame)
}

pub(super) fn request_instruction(
    material: &VMessAeadMaterial,
    target: &str,
    network: VMessNetwork,
    security: VMessBodySecurity,
) -> Result<Vec<u8>, OutboundError> {
    let metadata = VMessMetadata::parse(network.as_str(), target)?;
    let addr_len = metadata.addr_len();
    let header_padding_len = 0_usize;
    let request_options = match security {
        VMessBodySecurity::Aes128Gcm | VMessBodySecurity::Chacha20Poly1305 => REQUEST_OPTIONS_AEAD,
        VMessBodySecurity::None => REQUEST_OPTIONS_NONE,
        VMessBodySecurity::Zero => 0,
    };
    let mut out = vec![0_u8; 45 + addr_len + header_padding_len];
    out[0] = VMESS_VERSION;
    out[1..17].copy_from_slice(&material.request_body_iv);
    out[17..33].copy_from_slice(&material.request_body_key);
    out[33] = material.response_auth;
    out[34] = request_options;
    out[35] = ((header_padding_len as u8) << 4) | security.wire_value();
    out[36] = 0;
    out[37] = network.byte();
    out[38..40].copy_from_slice(&metadata.port().to_be_bytes());
    out[40] = metadata.metadata_type().byte();
    metadata.write_addr_to_slice(&mut out[41..41 + addr_len])?;
    let checksum_offset = out.len() - 4;
    let checksum = fnv1a32(&out[..checksum_offset]);
    out[checksum_offset..].copy_from_slice(&checksum.to_be_bytes());
    Ok(out)
}

pub(super) fn encrypt_request_header(
    cmd_key: &[u8; 16],
    eauth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    instruction: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::with_capacity(58 + instruction.len());
    out.extend_from_slice(eauth_id);
    let length = (instruction.len() as u16).to_be_bytes();
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                eauth_id,
                connection_nonce,
            ],
        ),
        &kdf12(
            cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                eauth_id,
                connection_nonce,
            ],
        ),
        &length,
        eauth_id,
    )?);
    out.extend_from_slice(connection_nonce);
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_AEAD_KEY, eauth_id, connection_nonce],
        ),
        &kdf12(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_AEAD_IV, eauth_id, connection_nonce],
        ),
        instruction,
        eauth_id,
    )?);
    Ok(out)
}

pub(super) fn encrypt_response_header(
    request: &VMessAeadTcpRequest,
) -> Result<Vec<u8>, OutboundError> {
    let header = [request.response_auth, 0, 0, 0];
    let mut out = Vec::with_capacity(38);
    let length = (header.len() as u16).to_be_bytes();
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV],
        ),
        &length,
        &[],
    )?);
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
        ),
        &header,
        &[],
    )?);
    Ok(out)
}
