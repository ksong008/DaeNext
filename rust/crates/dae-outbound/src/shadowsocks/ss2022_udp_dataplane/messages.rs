use super::*;
pub(super) fn encode_client_message(
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let target = Socks5Address::parse(target)?;
    let mut message = Vec::new();
    message.push(HEADER_TYPE_CLIENT_PACKET);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    target.write_to(&mut message)?;
    message.extend_from_slice(payload);
    Ok(message)
}

pub(super) fn encode_server_message(
    client_session_id: [u8; 8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let target = Socks5Address::parse(target)?;
    let mut message = Vec::new();
    message.push(HEADER_TYPE_SERVER_PACKET);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(&client_session_id);
    message.extend_from_slice(&0_u16.to_be_bytes());
    target.write_to(&mut message)?;
    message.extend_from_slice(payload);
    Ok(message)
}

#[derive(Debug)]
pub(super) struct ParsedClientMessage {
    pub(super) packet_type: u8,
    pub(super) timestamp: u64,
    pub(super) target: String,
    pub(super) target_metadata_len: usize,
    pub(super) padding_len: usize,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct ParsedServerMessage {
    pub(super) packet_type: u8,
    pub(super) timestamp: u64,
    pub(super) client_session_id: [u8; 8],
    pub(super) target: String,
    pub(super) target_metadata_len: usize,
    pub(super) padding_len: usize,
    pub(super) payload: Vec<u8>,
}

pub(super) fn parse_client_message(
    input: &[u8],
    now: u64,
) -> Result<ParsedClientMessage, OutboundError> {
    let (packet_type, timestamp, mut offset) = parse_type_timestamp(input, now)?;
    let padding_len = read_padding_len(input, &mut offset)?;
    skip_padding(input, &mut offset, padding_len)?;
    let (target, consumed) = Socks5Address::decode(&input[offset..])?;
    offset += consumed;
    Ok(ParsedClientMessage {
        packet_type,
        timestamp,
        target: target.authority(),
        target_metadata_len: consumed,
        padding_len,
        payload: input[offset..].to_vec(),
    })
}

pub(super) fn parse_server_message(
    input: &[u8],
    now: u64,
) -> Result<ParsedServerMessage, OutboundError> {
    let (packet_type, timestamp, mut offset) = parse_type_timestamp(input, now)?;
    if input.len() < offset + 8 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP server message missing client session id".to_owned(),
        ));
    }
    let mut client_session_id = [0_u8; 8];
    client_session_id.copy_from_slice(&input[offset..offset + 8]);
    offset += 8;
    let padding_len = read_padding_len(input, &mut offset)?;
    skip_padding(input, &mut offset, padding_len)?;
    let (target, consumed) = Socks5Address::decode(&input[offset..])?;
    offset += consumed;
    Ok(ParsedServerMessage {
        packet_type,
        timestamp,
        client_session_id,
        target: target.authority(),
        target_metadata_len: consumed,
        padding_len,
        payload: input[offset..].to_vec(),
    })
}

pub(super) fn parse_type_timestamp(
    input: &[u8],
    now: u64,
) -> Result<(u8, u64, usize), OutboundError> {
    if input.len() < 9 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP message too short".to_owned(),
        ));
    }
    let packet_type = input[0];
    let timestamp = u64::from_be_bytes(input[1..9].try_into().expect("timestamp len"));
    if timestamp_out_of_tolerance(timestamp, now) {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP replay attack: timestamp out of tolerance".to_owned(),
        ));
    }
    Ok((packet_type, timestamp, 9))
}

pub(super) fn read_padding_len(input: &[u8], offset: &mut usize) -> Result<usize, OutboundError> {
    if input.len() < *offset + 2 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP message missing padding length".to_owned(),
        ));
    }
    let padding_len = u16::from_be_bytes([input[*offset], input[*offset + 1]]) as usize;
    *offset += 2;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP padding too large: {padding_len}"
        )));
    }
    Ok(padding_len)
}

pub(super) fn skip_padding(
    input: &[u8],
    offset: &mut usize,
    padding_len: usize,
) -> Result<(), OutboundError> {
    if input.len() < *offset + padding_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP padding overflows packet".to_owned(),
        ));
    }
    *offset += padding_len;
    Ok(())
}
