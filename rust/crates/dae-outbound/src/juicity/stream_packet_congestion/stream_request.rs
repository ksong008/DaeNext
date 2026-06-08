use super::*;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StreamConnRequest {
    pub(super) encoded: Vec<u8>,
    pub(super) network_byte: u8,
    pub(super) initial_metadata_len: usize,
}

pub(super) fn build_stream_conn_request(
    initial_target: &str,
    frame: &JuicityStreamPacketFrame,
) -> Result<StreamConnRequest, OutboundError> {
    let metadata = TrojanMetadata::parse("udp", initial_target)?;
    let initial_metadata = metadata.encode()?;
    let mut encoded = Vec::with_capacity(1 + initial_metadata.len() + frame.encoded.len());
    encoded.push(TrojanNetwork::Udp.byte());
    encoded.extend_from_slice(&initial_metadata);
    encoded.extend_from_slice(&frame.encoded);
    Ok(StreamConnRequest {
        encoded,
        network_byte: TrojanNetwork::Udp.byte(),
        initial_metadata_len: initial_metadata.len(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ParsedStreamConnRequest {
    pub(super) network_byte: u8,
    pub(super) initial_target: String,
    pub(super) frame: JuicityStreamPacketFrame,
}

pub(super) fn parse_stream_conn_request(
    input: &[u8],
) -> Result<ParsedStreamConnRequest, OutboundError> {
    let Some((&network_byte, rest)) = input.split_first() else {
        return Err(bad_stream_packet_congestion(
            "stream congestion request missing network byte",
        ));
    };
    let (initial_address, initial_metadata_len) = Socks5Address::decode(rest)?;
    let frame = decode_stream_packet_frame(&rest[initial_metadata_len..])?;
    Ok(ParsedStreamConnRequest {
        network_byte,
        initial_target: initial_address.authority(),
        frame,
    })
}
