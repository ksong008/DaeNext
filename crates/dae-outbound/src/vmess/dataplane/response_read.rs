use super::*;
use tokio::io::AsyncReadExt as _;

pub(super) fn read_aead_response_header_and_chunk<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
) -> Result<(usize, Vec<u8>, usize), OutboundError>
where
    S: Read,
{
    let mut encrypted_len = [0_u8; 18];
    read_exact(stream, &mut encrypted_len, "vmess response header length")?;
    let len_plain = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV],
        ),
        &encrypted_len,
        &[],
    )?;
    if len_plain.len() != 2 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess response header length plaintext: {} bytes",
            len_plain.len()
        )));
    }
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_header = vec![0_u8; header_len + 16];
    read_exact(stream, &mut encrypted_header, "vmess response header")?;
    let header = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
        ),
        &encrypted_header,
        &[],
    )?;
    if header.len() < 4 {
        return Err(OutboundError::BadVmess(format!(
            "short VMess response header: {} bytes",
            header.len()
        )));
    }
    if header[0] != request.response_auth {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response auth: got {}, want {}",
            header[0], request.response_auth
        )));
    }
    if header[2] != 0 {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response command: {}",
            header[2]
        )));
    }
    let mut codec = BodyCodec::new(
        request.response_body_key,
        request.response_body_iv,
        request.request_options,
    )?;
    let (payload, chunk_len) = codec.open_chunk(stream)?;
    Ok((18 + encrypted_header.len(), payload, chunk_len))
}

pub(super) fn read_aead_response_header<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
) -> Result<usize, OutboundError>
where
    S: Read,
{
    let mut encrypted_len = [0_u8; 18];
    read_exact(stream, &mut encrypted_len, "vmess response header length")?;
    let len_plain = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV],
        ),
        &encrypted_len,
        &[],
    )?;
    if len_plain.len() != 2 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess response header length plaintext: {} bytes",
            len_plain.len()
        )));
    }
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_header = vec![0_u8; header_len + 16];
    read_exact(stream, &mut encrypted_header, "vmess response header")?;
    let header = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
        ),
        &encrypted_header,
        &[],
    )?;
    if header.len() < 4 {
        return Err(OutboundError::BadVmess(format!(
            "short VMess response header: {} bytes",
            header.len()
        )));
    }
    if header[0] != request.response_auth {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response auth: got {}, want {}",
            header[0], request.response_auth
        )));
    }
    if header[2] != 0 {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response command: {}",
            header[2]
        )));
    }
    Ok(18 + encrypted_header.len())
}

pub(super) async fn read_aead_response_header_async<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
) -> Result<usize, OutboundError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut encrypted_len = [0_u8; 18];
    stream.read_exact(&mut encrypted_len).await.map_err(|err| {
        OutboundError::BadVmess(format!("read vmess response header length: {err}"))
    })?;
    let len_plain = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV],
        ),
        &encrypted_len,
        &[],
    )?;
    if len_plain.len() != 2 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess response header length plaintext: {} bytes",
            len_plain.len()
        )));
    }
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_header = vec![0_u8; header_len + 16];
    stream
        .read_exact(&mut encrypted_header)
        .await
        .map_err(|err| OutboundError::BadVmess(format!("read vmess response header: {err}")))?;
    let header = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
        ),
        &encrypted_header,
        &[],
    )?;
    if header.len() < 4 {
        return Err(OutboundError::BadVmess(format!(
            "short VMess response header: {} bytes",
            header.len()
        )));
    }
    if header[0] != request.response_auth {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response auth: got {}, want {}",
            header[0], request.response_auth
        )));
    }
    if header[2] != 0 {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response command: {}",
            header[2]
        )));
    }
    Ok(18 + encrypted_header.len())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ParsedInstruction {
    pub(super) version: u8,
    pub(super) request_body_iv: [u8; 16],
    pub(super) request_body_key: [u8; 16],
    pub(super) response_body_iv: [u8; 16],
    pub(super) response_body_key: [u8; 16],
    pub(super) response_auth: u8,
    pub(super) request_options: u8,
    pub(super) security: u8,
    pub(super) command: u8,
    pub(super) target: String,
}

pub(super) fn parse_instruction(instruction: &[u8]) -> Result<ParsedInstruction, OutboundError> {
    if instruction.len() < 45 {
        return Err(OutboundError::BadVmess(format!(
            "short VMess instruction: {} bytes",
            instruction.len()
        )));
    }
    let header_padding_len = (instruction[35] >> 4) as usize;
    let security = instruction[35] & 0x0f;
    if security != VMESS_AEAD_SECURITY_AES_128_GCM {
        return Err(OutboundError::BadVmess(format!(
            "unsupported VMess AEAD security: {security}"
        )));
    }
    let (host, addr_len) = read_instruction_host(instruction, instruction[40])?;
    let expected_len = 45 + addr_len + header_padding_len;
    if instruction.len() != expected_len {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess instruction length: got {}, want {}",
            instruction.len(),
            expected_len
        )));
    }
    let checksum_offset = instruction.len() - 4;
    let got_checksum = u32::from_be_bytes([
        instruction[checksum_offset],
        instruction[checksum_offset + 1],
        instruction[checksum_offset + 2],
        instruction[checksum_offset + 3],
    ]);
    let want_checksum = fnv1a32(&instruction[..checksum_offset]);
    if got_checksum != want_checksum {
        return Err(OutboundError::BadVmess(format!(
            "VMess instruction checksum mismatch: got {got_checksum:#x}, want {want_checksum:#x}"
        )));
    }

    let mut request_body_iv = [0_u8; 16];
    request_body_iv.copy_from_slice(&instruction[1..17]);
    let mut request_body_key = [0_u8; 16];
    request_body_key.copy_from_slice(&instruction[17..33]);
    let response_body_iv = sha256_16(&request_body_iv);
    let response_body_key = sha256_16(&request_body_key);
    let port = u16::from_be_bytes([instruction[38], instruction[39]]);
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(ParsedInstruction {
        version: instruction[0],
        request_body_iv,
        request_body_key,
        response_body_iv,
        response_body_key,
        response_auth: instruction[33],
        request_options: instruction[34],
        security,
        command: instruction[37],
        target,
    })
}

pub(super) fn read_instruction_host(
    instruction: &[u8],
    atyp: u8,
) -> Result<(String, usize), OutboundError> {
    match atyp {
        value if value == VMessMetadataType::Ipv4.byte() => {
            if instruction.len() < 45 {
                return Err(OutboundError::BadVmess(
                    "short VMess IPv4 instruction".to_owned(),
                ));
            }
            let mut octets = [0_u8; 4];
            octets.copy_from_slice(&instruction[41..45]);
            Ok((Ipv4Addr::from(octets).to_string(), 4))
        }
        value if value == VMessMetadataType::Domain.byte() => {
            let len = *instruction
                .get(41)
                .ok_or_else(|| OutboundError::BadVmess("missing VMess domain length".to_owned()))?
                as usize;
            if instruction.len() < 42 + len {
                return Err(OutboundError::BadVmess(format!(
                    "short VMess domain instruction: got {}, need {}",
                    instruction.len(),
                    42 + len
                )));
            }
            let host = String::from_utf8(instruction[42..42 + len].to_vec())
                .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
            Ok((host, 1 + len))
        }
        value if value == VMessMetadataType::Ipv6.byte() => {
            if instruction.len() < 57 {
                return Err(OutboundError::BadVmess(
                    "short VMess IPv6 instruction".to_owned(),
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&instruction[41..57]);
            Ok((Ipv6Addr::from(octets).to_string(), 16))
        }
        value => Err(OutboundError::BadVmess(format!(
            "bad VMess address type: {value}"
        ))),
    }
}
