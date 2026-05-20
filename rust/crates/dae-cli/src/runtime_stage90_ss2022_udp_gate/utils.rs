use super::*;

pub(super) fn validate_stage90_options(opts: &Stage90Options) -> Result<(), RunnerOutput> {
    validate_cipher_branch("stage90 AES", &opts.aes_cipher, &opts.aes_password, false)?;
    validate_cipher_branch(
        "stage90 Chacha",
        &opts.chacha_cipher,
        &opts.chacha_password,
        true,
    )?;
    shadowsocks::ShadowsocksMetadata::parse(&opts.target)
        .map_err(|err| RunnerOutput::usage(format!("stage90 target is invalid: {err}")))?;
    shadowsocks::ShadowsocksMetadata::parse(&opts.response_target)
        .map_err(|err| RunnerOutput::usage(format!("stage90 response target is invalid: {err}")))?;
    Ok(())
}

fn validate_cipher_branch(
    label: &str,
    cipher: &str,
    password: &str,
    want_packet_cipher: bool,
) -> Result<(), RunnerOutput> {
    let conf = shadowsocks::ss2022::cipher_conf(cipher)
        .ok_or_else(|| RunnerOutput::usage(format!("{label} requires SS2022 cipher: {cipher}")))?;
    if conf.packet_cipher != want_packet_cipher {
        return Err(RunnerOutput::usage(format!(
            "{label} packet cipher mode mismatch for {cipher}"
        )));
    }
    shadowsocks::ss2022::validate_psk_list(cipher, password)
        .map_err(|err| RunnerOutput::usage(format!("{label} PSK invalid: {err}")))?;
    Ok(())
}

pub(super) fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    context: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {context}")))
}

pub(super) fn parse_usize(value: &str, context: &str) -> Result<usize, RunnerOutput> {
    value
        .parse::<usize>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}

pub(super) fn parse_u64(value: &str, context: &str) -> Result<u64, RunnerOutput> {
    value
        .parse::<u64>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}

pub(super) fn parse_u32(value: &str, context: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}

pub(super) fn nonce_for(index: usize, len: usize, base: u8) -> Vec<u8> {
    (0..len)
        .map(|offset| base.wrapping_add(index as u8).wrapping_add(offset as u8))
        .collect()
}

pub(super) fn session_hex(session_id: [u8; 8]) -> String {
    hex_encode(&session_id)
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
