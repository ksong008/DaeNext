use crate::error::OutboundError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtlsClientHelloProfile {
    pub record_content_type: String,
    pub record_version: String,
    pub record_len: usize,
    pub handshake_type: String,
    pub handshake_len: usize,
    pub legacy_version: String,
    pub random_len: usize,
    pub session_id_len: usize,
    pub cipher_suites: Vec<String>,
    pub compression_methods: Vec<String>,
    pub extension_types: Vec<String>,
    pub sni: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub supported_versions: Option<Vec<String>>,
    pub supported_groups: Option<Vec<String>>,
    pub ec_point_formats: Option<Vec<String>>,
    pub signature_schemes: Option<Vec<String>>,
    pub key_share_groups: Option<Vec<String>>,
}

pub fn parse_utls_client_hello_record_hex(
    input: &str,
) -> Result<UtlsClientHelloProfile, OutboundError> {
    let record = decode_hex(input)?;
    parse_utls_client_hello_record(&record)
}

pub fn parse_utls_client_hello_record(
    record: &[u8],
) -> Result<UtlsClientHelloProfile, OutboundError> {
    if record.len() < 9 {
        return Err(bad_utls_wire("TLS record too short"));
    }

    let record_len = u16_at(record, 3)? as usize;
    if record.len() != 5 + record_len {
        return Err(bad_utls_wire(format!(
            "TLS record length mismatch: header={record_len}, actual={}",
            record.len().saturating_sub(5)
        )));
    }

    let body = &record[5..];
    let handshake_len = u24_at(body, 1)? as usize;
    if body.len() != 4 + handshake_len {
        return Err(bad_utls_wire(format!(
            "TLS handshake length mismatch: header={handshake_len}, actual={}",
            body.len().saturating_sub(4)
        )));
    }

    let hello = &body[4..];
    if hello.len() < 38 {
        return Err(bad_utls_wire("TLS ClientHello body too short"));
    }

    let mut offset = 34;
    let session_id_len = read_u8_len(hello, &mut offset, "session id")?;
    skip_exact(hello, &mut offset, session_id_len, "session id")?;

    let cipher_len = read_u16_len(hello, &mut offset, "cipher suites")?;
    if cipher_len % 2 != 0 {
        return Err(bad_utls_wire("TLS cipher suites length is not even"));
    }
    let cipher_suites = read_u16_vec(hello, &mut offset, cipher_len, "cipher suites")?;

    let compression_len = read_u8_len(hello, &mut offset, "compression methods")?;
    let compression_methods =
        read_u8_vec(hello, &mut offset, compression_len, "compression methods")?;

    let mut profile = UtlsClientHelloProfile {
        record_content_type: hex_byte(record[0]),
        record_version: hex_u16(&record[1..3]),
        record_len,
        handshake_type: hex_byte(body[0]),
        handshake_len,
        legacy_version: hex_u16(&hello[0..2]),
        random_len: 32,
        session_id_len,
        cipher_suites,
        compression_methods,
        extension_types: Vec::new(),
        sni: None,
        alpn: None,
        supported_versions: None,
        supported_groups: None,
        ec_point_formats: None,
        signature_schemes: None,
        key_share_groups: None,
    };

    if offset == hello.len() {
        return Ok(profile);
    }

    let extensions_len = read_u16_len(hello, &mut offset, "extensions")?;
    let extensions_end = checked_end(offset, extensions_len, hello.len(), "extensions")?;
    while offset < extensions_end {
        if offset + 4 > extensions_end {
            return Err(bad_utls_wire("TLS extension header truncated"));
        }
        let extension_type = hex_u16(&hello[offset..offset + 2]);
        let extension_len = u16_at(hello, offset + 2)? as usize;
        offset += 4;
        let data_end = checked_end(offset, extension_len, extensions_end, "extension body")?;
        let data = &hello[offset..data_end];
        profile.extension_types.push(extension_type.clone());
        match extension_type.as_str() {
            "0000" => profile.sni = parse_sni(data)?,
            "000a" => profile.supported_groups = parse_u16_vector(data)?,
            "000b" => profile.ec_point_formats = parse_u8_vector(data)?,
            "000d" => profile.signature_schemes = parse_u16_vector(data)?,
            "0010" => profile.alpn = parse_alpn(data)?,
            "002b" => profile.supported_versions = parse_u8_len_u16_vector(data)?,
            "0033" => profile.key_share_groups = parse_key_share_groups(data)?,
            _ => {}
        }
        offset = data_end;
    }

    Ok(profile)
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, OutboundError> {
    if data.len() < 5 {
        return Ok(None);
    }
    let list_len = u16_at(data, 0)? as usize;
    if 2 + list_len > data.len() || data[2] != 0 {
        return Ok(None);
    }
    let name_len = u16_at(data, 3)? as usize;
    if 5 + name_len > data.len() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&data[5..5 + name_len]).into_owned(),
    ))
}

fn parse_alpn(data: &[u8]) -> Result<Option<Vec<String>>, OutboundError> {
    if data.len() < 2 {
        return Ok(None);
    }
    let list_len = u16_at(data, 0)? as usize;
    let mut offset = 2;
    let end = checked_end(offset, list_len, data.len(), "ALPN list")?;
    let mut out = Vec::new();
    while offset < end {
        let len = read_u8_len(data, &mut offset, "ALPN item")?;
        let item_end = checked_end(offset, len, end, "ALPN item body")?;
        out.push(String::from_utf8_lossy(&data[offset..item_end]).into_owned());
        offset = item_end;
    }
    Ok(Some(out))
}

fn parse_u16_vector(data: &[u8]) -> Result<Option<Vec<String>>, OutboundError> {
    if data.len() < 2 {
        return Ok(None);
    }
    let len = u16_at(data, 0)? as usize;
    if !len.is_multiple_of(2) {
        return Err(bad_utls_wire("TLS u16 vector length is not even"));
    }
    let end = checked_end(2, len, data.len(), "u16 vector")?;
    Ok(Some(hex_u16_list(&data[2..end])))
}

fn parse_u8_len_u16_vector(data: &[u8]) -> Result<Option<Vec<String>>, OutboundError> {
    if data.is_empty() {
        return Ok(None);
    }
    let len = data[0] as usize;
    if !len.is_multiple_of(2) {
        return Err(bad_utls_wire("TLS u8-len u16 vector length is not even"));
    }
    let end = checked_end(1, len, data.len(), "u8-len u16 vector")?;
    Ok(Some(hex_u16_list(&data[1..end])))
}

fn parse_u8_vector(data: &[u8]) -> Result<Option<Vec<String>>, OutboundError> {
    if data.is_empty() {
        return Ok(None);
    }
    let len = data[0] as usize;
    let end = checked_end(1, len, data.len(), "u8 vector")?;
    Ok(Some(
        data[1..end].iter().map(|value| hex_byte(*value)).collect(),
    ))
}

fn parse_key_share_groups(data: &[u8]) -> Result<Option<Vec<String>>, OutboundError> {
    if data.len() < 2 {
        return Ok(None);
    }
    let len = u16_at(data, 0)? as usize;
    let mut offset = 2;
    let end = checked_end(offset, len, data.len(), "key share list")?;
    let mut out = Vec::new();
    while offset < end {
        if offset + 4 > end {
            return Err(bad_utls_wire("TLS key share entry truncated"));
        }
        out.push(hex_u16(&data[offset..offset + 2]));
        let key_len = u16_at(data, offset + 2)? as usize;
        offset = checked_end(offset + 4, key_len, end, "key share body")?;
    }
    Ok(Some(out))
}

fn read_u8_len(data: &[u8], offset: &mut usize, label: &str) -> Result<usize, OutboundError> {
    if *offset >= data.len() {
        return Err(bad_utls_wire(format!("TLS {label} length missing")));
    }
    let len = data[*offset] as usize;
    *offset += 1;
    Ok(len)
}

fn read_u16_len(data: &[u8], offset: &mut usize, label: &str) -> Result<usize, OutboundError> {
    if *offset + 2 > data.len() {
        return Err(bad_utls_wire(format!("TLS {label} length missing")));
    }
    let len = u16_at(data, *offset)? as usize;
    *offset += 2;
    Ok(len)
}

fn read_u8_vec(
    data: &[u8],
    offset: &mut usize,
    len: usize,
    label: &str,
) -> Result<Vec<String>, OutboundError> {
    let end = checked_end(*offset, len, data.len(), label)?;
    let out = data[*offset..end]
        .iter()
        .map(|value| hex_byte(*value))
        .collect();
    *offset = end;
    Ok(out)
}

fn read_u16_vec(
    data: &[u8],
    offset: &mut usize,
    len: usize,
    label: &str,
) -> Result<Vec<String>, OutboundError> {
    let end = checked_end(*offset, len, data.len(), label)?;
    let out = hex_u16_list(&data[*offset..end]);
    *offset = end;
    Ok(out)
}

fn skip_exact(
    data: &[u8],
    offset: &mut usize,
    len: usize,
    label: &str,
) -> Result<(), OutboundError> {
    *offset = checked_end(*offset, len, data.len(), label)?;
    Ok(())
}

fn checked_end(
    offset: usize,
    len: usize,
    limit: usize,
    label: &str,
) -> Result<usize, OutboundError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| bad_utls_wire(format!("TLS {label} length overflow")))?;
    if end > limit {
        return Err(bad_utls_wire(format!("TLS {label} truncated")));
    }
    Ok(end)
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, OutboundError> {
    if offset + 2 > data.len() {
        return Err(bad_utls_wire("TLS u16 truncated"));
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn u24_at(data: &[u8], offset: usize) -> Result<u32, OutboundError> {
    if offset + 3 > data.len() {
        return Err(bad_utls_wire("TLS u24 truncated"));
    }
    Ok(((data[offset] as u32) << 16) | ((data[offset + 1] as u32) << 8) | data[offset + 2] as u32)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, OutboundError> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        return Err(bad_utls_wire("hex ClientHello record has odd length"));
    }
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| Ok((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(bad_utls_wire(format!("bad hex byte: {byte}"))),
    }
}

fn hex_u16_list(data: &[u8]) -> Vec<String> {
    data.chunks_exact(2).map(hex_u16).collect()
}

fn hex_byte(value: u8) -> String {
    format!("{value:02x}")
}

fn hex_u16(value: &[u8]) -> String {
    format!("{:02x}{:02x}", value[0], value[1])
}

fn bad_utls_wire(message: impl Into<String>) -> OutboundError {
    OutboundError::BadSharedTransport(format!(
        "bad uTLS ClientHello wire profile: {}",
        message.into()
    ))
}
