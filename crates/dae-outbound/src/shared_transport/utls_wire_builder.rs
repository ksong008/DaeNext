use crate::error::OutboundError;

use super::UtlsClientHelloProfile;

pub fn build_synthetic_utls_client_hello_record(
    profile: &UtlsClientHelloProfile,
) -> Result<Vec<u8>, OutboundError> {
    if profile.random_len != 32 {
        return Err(bad_builder(
            "only 32-byte TLS ClientHello random is supported",
        ));
    }
    if profile.session_id_len > u8::MAX as usize {
        return Err(bad_builder("session id length exceeds u8"));
    }

    let mut hello_prefix = Vec::new();
    hello_prefix.extend_from_slice(&hex_u16_bytes(&profile.legacy_version)?);
    hello_prefix.extend(std::iter::repeat_n(0xa5, profile.random_len));
    hello_prefix.push(profile.session_id_len as u8);
    for index in 0..profile.session_id_len {
        hello_prefix.push((index & 0xff) as u8);
    }
    let cipher_suites = hex_u16_values(&profile.cipher_suites)?;
    push_u16_len(&mut hello_prefix, cipher_suites.len(), "cipher suites")?;
    hello_prefix.extend_from_slice(&cipher_suites);
    let compression_methods = hex_u8_values(&profile.compression_methods)?;
    push_u8_len(
        &mut hello_prefix,
        compression_methods.len(),
        "compression methods",
    )?;
    hello_prefix.extend_from_slice(&compression_methods);

    let mut extensions = build_extension_entries(profile)?;
    fit_padding_to_target(profile, hello_prefix.len(), &mut extensions)?;

    let extension_len = extensions.iter().try_fold(0usize, |len, (_, body)| {
        len.checked_add(4 + body.len())
            .ok_or_else(|| bad_builder("extension length overflow"))
    })?;
    let mut hello = hello_prefix;
    push_u16_len(&mut hello, extension_len, "extensions")?;
    for (extension_type, body) in extensions {
        hello.extend_from_slice(&extension_type);
        push_u16_len(&mut hello, body.len(), "extension body")?;
        hello.extend_from_slice(&body);
    }

    if hello.len() != profile.handshake_len {
        return Err(bad_builder(format!(
            "synthetic ClientHello length {} does not match target {}",
            hello.len(),
            profile.handshake_len
        )));
    }

    let mut handshake = Vec::new();
    handshake.push(hex_u8_byte(&profile.handshake_type)?);
    push_u24_len(&mut handshake, hello.len(), "handshake")?;
    handshake.extend_from_slice(&hello);
    if handshake.len() != profile.record_len {
        return Err(bad_builder(format!(
            "synthetic TLS record body length {} does not match target {}",
            handshake.len(),
            profile.record_len
        )));
    }

    let mut record = Vec::new();
    record.push(hex_u8_byte(&profile.record_content_type)?);
    record.extend_from_slice(&hex_u16_bytes(&profile.record_version)?);
    push_u16_len(&mut record, handshake.len(), "record")?;
    record.extend_from_slice(&handshake);
    Ok(record)
}

pub fn build_synthetic_utls_client_hello_record_hex(
    profile: &UtlsClientHelloProfile,
) -> Result<String, OutboundError> {
    Ok(hex_encode(&build_synthetic_utls_client_hello_record(
        profile,
    )?))
}

fn build_extension_entries(
    profile: &UtlsClientHelloProfile,
) -> Result<Vec<([u8; 2], Vec<u8>)>, OutboundError> {
    profile
        .extension_types
        .iter()
        .map(|extension_type| {
            let body = match extension_type.as_str() {
                "0000" => sni_body(profile.sni.as_deref().unwrap_or_default())?,
                "000a" => u16_vector_body(profile.supported_groups.as_deref().unwrap_or(&[]))?,
                "000b" => u8_vector_body(profile.ec_point_formats.as_deref().unwrap_or(&[]))?,
                "000d" => u16_vector_body(profile.signature_schemes.as_deref().unwrap_or(&[]))?,
                "0010" => alpn_body(profile.alpn.as_deref().unwrap_or(&[]))?,
                "002b" => {
                    u8_len_u16_vector_body(profile.supported_versions.as_deref().unwrap_or(&[]))?
                }
                "0033" => key_share_body(profile.key_share_groups.as_deref().unwrap_or(&[]))?,
                "ff01" => vec![0],
                "0005" => vec![1, 0, 0, 0, 0],
                "002d" => vec![1, 1],
                "001b" => vec![2, 0, 2],
                "4469" => alps_h2_body(profile),
                "0015" | "0017" | "0023" | "0012" => Vec::new(),
                _ => Vec::new(),
            };
            Ok((hex_u16_bytes(extension_type)?, body))
        })
        .collect()
}

fn fit_padding_to_target(
    profile: &UtlsClientHelloProfile,
    hello_prefix_len: usize,
    extensions: &mut [([u8; 2], Vec<u8>)],
) -> Result<(), OutboundError> {
    let current_len = hello_prefix_len
        .checked_add(2)
        .and_then(|len| {
            extensions
                .iter()
                .try_fold(len, |acc, (_, body)| acc.checked_add(4 + body.len()))
        })
        .ok_or_else(|| bad_builder("synthetic ClientHello length overflow"))?;
    if current_len == profile.handshake_len {
        return Ok(());
    }
    if current_len > profile.handshake_len {
        return Err(bad_builder(format!(
            "synthetic ClientHello length {current_len} exceeds target {}",
            profile.handshake_len
        )));
    }
    let Some((_, padding_body)) = extensions
        .iter_mut()
        .find(|(extension_type, _)| extension_type == &[0x00, 0x15])
    else {
        return Err(bad_builder(format!(
            "synthetic ClientHello needs {} padding bytes but profile has no padding extension",
            profile.handshake_len - current_len
        )));
    };
    padding_body.resize(profile.handshake_len - current_len, 0);
    Ok(())
}

fn sni_body(server_name: &str) -> Result<Vec<u8>, OutboundError> {
    let name = server_name.as_bytes();
    let mut entry = Vec::new();
    entry.push(0);
    push_u16_len(&mut entry, name.len(), "sni name")?;
    entry.extend_from_slice(name);
    let mut body = Vec::new();
    push_u16_len(&mut body, entry.len(), "sni list")?;
    body.extend_from_slice(&entry);
    Ok(body)
}

fn alpn_body(protocols: &[String]) -> Result<Vec<u8>, OutboundError> {
    let mut list = Vec::new();
    for protocol in protocols {
        let bytes = protocol.as_bytes();
        push_u8_len(&mut list, bytes.len(), "alpn item")?;
        list.extend_from_slice(bytes);
    }
    let mut body = Vec::new();
    push_u16_len(&mut body, list.len(), "alpn list")?;
    body.extend_from_slice(&list);
    Ok(body)
}

fn alps_h2_body(profile: &UtlsClientHelloProfile) -> Vec<u8> {
    if profile
        .alpn
        .as_ref()
        .is_some_and(|protocols| protocols.iter().any(|protocol| protocol == "h2"))
    {
        vec![0, 3, 2, b'h', b'2']
    } else {
        Vec::new()
    }
}

fn u16_vector_body(values: &[String]) -> Result<Vec<u8>, OutboundError> {
    let bytes = hex_u16_values(values)?;
    let mut body = Vec::new();
    push_u16_len(&mut body, bytes.len(), "u16 vector")?;
    body.extend_from_slice(&bytes);
    Ok(body)
}

fn u8_len_u16_vector_body(values: &[String]) -> Result<Vec<u8>, OutboundError> {
    let bytes = hex_u16_values(values)?;
    let mut body = Vec::new();
    push_u8_len(&mut body, bytes.len(), "u8-len u16 vector")?;
    body.extend_from_slice(&bytes);
    Ok(body)
}

fn u8_vector_body(values: &[String]) -> Result<Vec<u8>, OutboundError> {
    let bytes = hex_u8_values(values)?;
    let mut body = Vec::new();
    push_u8_len(&mut body, bytes.len(), "u8 vector")?;
    body.extend_from_slice(&bytes);
    Ok(body)
}

fn key_share_body(values: &[String]) -> Result<Vec<u8>, OutboundError> {
    let mut entries = Vec::new();
    for value in values {
        let group = hex_u16_bytes(value)?;
        entries.extend_from_slice(&group);
        let key_len = if is_grease_u16(group) { 1 } else { 32 };
        push_u16_len(&mut entries, key_len, "key share")?;
        entries.extend(std::iter::repeat_n(0x42, key_len));
    }
    let mut body = Vec::new();
    push_u16_len(&mut body, entries.len(), "key share list")?;
    body.extend_from_slice(&entries);
    Ok(body)
}

fn is_grease_u16(value: [u8; 2]) -> bool {
    value[0] == value[1] && value[0] & 0x0f == 0x0a
}

fn hex_u16_values(values: &[String]) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::with_capacity(values.len() * 2);
    for value in values {
        out.extend_from_slice(&hex_u16_bytes(value)?);
    }
    Ok(out)
}

fn hex_u8_values(values: &[String]) -> Result<Vec<u8>, OutboundError> {
    values.iter().map(|value| hex_u8_byte(value)).collect()
}

fn hex_u16_bytes(value: &str) -> Result<[u8; 2], OutboundError> {
    let value = value.as_bytes();
    if value.len() != 4 {
        return Err(bad_builder("expected four hex characters for u16"));
    }
    Ok([
        (hex_nibble(value[0])? << 4) | hex_nibble(value[1])?,
        (hex_nibble(value[2])? << 4) | hex_nibble(value[3])?,
    ])
}

fn hex_u8_byte(value: &str) -> Result<u8, OutboundError> {
    let value = value.as_bytes();
    if value.len() != 2 {
        return Err(bad_builder("expected two hex characters for u8"));
    }
    Ok((hex_nibble(value[0])? << 4) | hex_nibble(value[1])?)
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(bad_builder(format!("bad hex byte: {byte}"))),
    }
}

fn push_u8_len(out: &mut Vec<u8>, len: usize, label: &str) -> Result<(), OutboundError> {
    if len > u8::MAX as usize {
        return Err(bad_builder(format!("{label} length exceeds u8")));
    }
    out.push(len as u8);
    Ok(())
}

fn push_u16_len(out: &mut Vec<u8>, len: usize, label: &str) -> Result<(), OutboundError> {
    if len > u16::MAX as usize {
        return Err(bad_builder(format!("{label} length exceeds u16")));
    }
    out.extend_from_slice(&(len as u16).to_be_bytes());
    Ok(())
}

fn push_u24_len(out: &mut Vec<u8>, len: usize, label: &str) -> Result<(), OutboundError> {
    if len > 0x00ff_ffff {
        return Err(bad_builder(format!("{label} length exceeds u24")));
    }
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn bad_builder(message: impl Into<String>) -> OutboundError {
    OutboundError::BadSharedTransport(format!(
        "bad synthetic uTLS ClientHello builder: {}",
        message.into()
    ))
}
