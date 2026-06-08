#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentityHeaderValidation {
    count: usize,
    bytes_len: usize,
    validated: bool,
}

fn encode_identity_headers(
    conf: &CipherConf2022,
    psk_list: &[Vec<u8>],
    salt: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if psk_list.len() <= 1 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity((psk_list.len() - 1) * 16);
    for window in psk_list.windows(2) {
        out.extend_from_slice(&encode_identity_header(conf, &window[0], &window[1], salt)?);
    }
    Ok(out)
}

fn read_and_validate_identity_headers<S>(
    stream: &mut S,
    conf: &CipherConf2022,
    psk_list: &[Vec<u8>],
    salt: &[u8],
) -> Result<IdentityHeaderValidation, OutboundError>
where
    S: Read,
{
    if psk_list.len() <= 1 {
        return Ok(IdentityHeaderValidation {
            count: 0,
            bytes_len: 0,
            validated: true,
        });
    }
    let mut count = 0;
    for window in psk_list.windows(2) {
        let expected = encode_identity_header(conf, &window[0], &window[1], salt)?;
        let mut observed = [0_u8; 16];
        stream
            .read_exact(&mut observed)
            .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
        if observed != expected {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 identity header mismatch".to_owned(),
            ));
        }
        count += 1;
    }
    Ok(IdentityHeaderValidation {
        count,
        bytes_len: count * 16,
        validated: true,
    })
}

fn encode_identity_header(
    conf: &CipherConf2022,
    current_psk: &[u8],
    next_psk: &[u8],
    salt: &[u8],
) -> Result<[u8; 16], OutboundError> {
    let identity_subkey = derive_subkey(current_psk, salt, conf.key_len, IDENTITY_SUBKEY_CONTEXT);
    let mut next_hash = [0_u8; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(next_psk);
    hasher.finalize_xof().fill(&mut next_hash);
    encrypt_aes_block(&identity_subkey, &next_hash[..16])
}

fn encrypt_aes_block(key: &[u8], plaintext: &[u8]) -> Result<[u8; 16], OutboundError> {
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(plaintext);
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-128 identity key".to_owned())
            })?;
            cipher.encrypt_block(&mut block);
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-256 identity key".to_owned())
            })?;
            cipher.encrypt_block(&mut block);
        }
        _ => {
            return Err(OutboundError::BadShadowsocks(format!(
                "unsupported SS2022 identity key length: {}",
                key.len()
            )));
        }
    }
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}
