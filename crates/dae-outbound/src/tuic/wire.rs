use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;

pub const TUIC_VERSION5: u8 = 0x05;
pub const TUIC_AUTHENTICATE_TYPE: u8 = 0x00;
pub const TUIC_CONNECT_TYPE: u8 = 0x01;
pub const TUIC_PACKET_TYPE: u8 = 0x02;
pub const TUIC_DISSOCIATE_TYPE: u8 = 0x03;
pub const TUIC_HEARTBEAT_TYPE: u8 = 0x04;
pub const TUIC_AUTH_TOKEN_LEN: usize = 32;
pub const TUIC_AUTHENTICATE_FRAME_LEN: usize = 2 + 16 + TUIC_AUTH_TOKEN_LEN;
pub const TUIC_DISSOCIATE_FRAME_LEN: usize = 4;
pub const TUIC_HEARTBEAT_FRAME_LEN: usize = 2;
pub const TUIC_MAX_UDP_PAYLOAD_LENGTH: usize = u16::MAX as usize;

const ATYP_DOMAIN_NAME: u8 = 0;
const ATYP_IPV4: u8 = 1;
const ATYP_IPV6: u8 = 2;
const ATYP_NONE: u8 = 255;

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(test, feature = "test-support"))]
pub(super) struct TuicAuthenticateFrame {
    pub(super) version: u8,
    pub(super) uuid: [u8; 16],
    pub(super) token: [u8; TUIC_AUTH_TOKEN_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicUdpPacket {
    assoc_id: u16,
    packet_id: u16,
    fragment_count: u8,
    fragment_id: u8,
    target: Option<String>,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TuicAddress {
    atyp: u8,
    addr: Vec<u8>,
    port: u16,
    target: String,
}

pub(super) fn parse_uuid(input: &str) -> Result<[u8; 16], OutboundError> {
    let compact = input.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(bad_wire(format!("parse UUID: {input}")));
    }
    let mut out = [0_u8; 16];
    for index in 0..16 {
        out[index] = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .map_err(|err| bad_wire(format!("parse UUID byte: {err}")))?;
    }
    Ok(out)
}

pub(super) fn build_authenticate_frame(
    uuid: [u8; 16],
    token: [u8; TUIC_AUTH_TOKEN_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TUIC_AUTHENTICATE_FRAME_LEN);
    out.push(TUIC_VERSION5);
    out.push(TUIC_AUTHENTICATE_TYPE);
    out.extend_from_slice(&uuid);
    out.extend_from_slice(&token);
    out
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn parse_authenticate_frame(
    input: &[u8],
) -> Result<TuicAuthenticateFrame, OutboundError> {
    if input.len() != TUIC_AUTHENTICATE_FRAME_LEN {
        return Err(bad_wire(format!(
            "invalid TUIC authenticate frame length: {}",
            input.len()
        )));
    }
    validate_command_head(input, TUIC_AUTHENTICATE_TYPE, "authenticate")?;
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&input[2..18]);
    let mut token = [0_u8; TUIC_AUTH_TOKEN_LEN];
    token.copy_from_slice(&input[18..50]);
    Ok(TuicAuthenticateFrame {
        version: input[0],
        uuid,
        token,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn build_packet_frame(
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let target = (frag_id == 0).then(|| target.to_owned());
    encode_tuic_udp_packet(&TuicUdpPacket::from_parts(
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        target,
        payload.to_vec(),
    )?)
}

pub(super) fn build_connect_frame(target: &str) -> Result<Vec<u8>, OutboundError> {
    let address = build_address(target)?;
    let mut out = Vec::with_capacity(2 + address.encoded_len());
    out.push(TUIC_VERSION5);
    out.push(TUIC_CONNECT_TYPE);
    address.write_to(&mut out);
    Ok(out)
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn parse_packet_frame(input: &[u8]) -> Result<TuicUdpPacket, OutboundError> {
    decode_tuic_udp_packet(input)
}

pub fn encode_tuic_udp_packet(packet: &TuicUdpPacket) -> Result<Vec<u8>, OutboundError> {
    validate_udp_packet_fields(
        packet.fragment_count,
        packet.fragment_id,
        packet.target.as_deref(),
        &packet.payload,
    )?;
    let address = address_for_optional_target(packet.target.as_deref())?;
    let mut out = Vec::with_capacity(10 + address.encoded_len() + packet.payload.len());
    out.push(TUIC_VERSION5);
    out.push(TUIC_PACKET_TYPE);
    out.extend_from_slice(&packet.assoc_id.to_be_bytes());
    out.extend_from_slice(&packet.packet_id.to_be_bytes());
    out.push(packet.fragment_count);
    out.push(packet.fragment_id);
    out.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
    address.write_to(&mut out);
    out.extend_from_slice(&packet.payload);
    Ok(out)
}

pub fn decode_tuic_udp_packet(input: &[u8]) -> Result<TuicUdpPacket, OutboundError> {
    if input.len() < 10 {
        return Err(bad_wire("short TUIC packet frame"));
    }
    validate_command_head(input, TUIC_PACKET_TYPE, "packet")?;
    let assoc_id = u16::from_be_bytes([input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let fragment_count = input[6];
    let fragment_id = input[7];
    let size = u16::from_be_bytes([input[8], input[9]]) as usize;
    let (address, offset) = read_address(input, 10)?;
    let payload_end = offset
        .checked_add(size)
        .ok_or_else(|| bad_wire("TUIC packet payload length overflow"))?;
    if input.len() != payload_end {
        return Err(bad_wire("TUIC packet payload length mismatch"));
    }
    let target = (address.atyp != ATYP_NONE).then_some(address.target);
    TuicUdpPacket::from_parts(
        assoc_id,
        packet_id,
        fragment_count,
        fragment_id,
        target,
        input[offset..payload_end].to_vec(),
    )
}

pub fn fragment_tuic_udp_packet(
    packet: &TuicUdpPacket,
    packet_id: u16,
    max_wire_size: usize,
) -> Result<Vec<TuicUdpPacket>, OutboundError> {
    if packet.fragment_count != 1 || packet.fragment_id != 0 || packet.target.is_none() {
        return Err(bad_wire(
            "only a complete TUIC UDP packet can be fragmented",
        ));
    }
    if packet.encoded_len()? <= max_wire_size {
        return Err(bad_wire(format!(
            "TUIC UDP packet fits max wire size {max_wire_size} without fragmentation"
        )));
    }
    let first_header_len = packet
        .encoded_len()?
        .checked_sub(packet.payload.len())
        .ok_or_else(|| bad_wire("TUIC UDP header length underflow"))?;
    let max_fragment_payload = max_wire_size.checked_sub(first_header_len).ok_or_else(|| {
        bad_wire(format!(
            "TUIC UDP header is larger than max wire size {max_wire_size}"
        ))
    })?;
    if max_fragment_payload == 0 {
        return Err(bad_wire(format!(
            "TUIC UDP header leaves no payload at max wire size {max_wire_size}"
        )));
    }
    let fragment_count = packet.payload.len().div_ceil(max_fragment_payload);
    let fragment_count = u8::try_from(fragment_count)
        .map_err(|_| bad_wire("TUIC UDP fragment count exceeds 255"))?;
    if fragment_count <= 1 {
        return Err(bad_wire(
            "TUIC UDP fragmentation did not produce multiple fragments",
        ));
    }

    let mut fragments = Vec::with_capacity(fragment_count as usize);
    for (fragment_id, payload) in packet.payload.chunks(max_fragment_payload).enumerate() {
        fragments.push(TuicUdpPacket::from_parts(
            packet.assoc_id,
            packet_id,
            fragment_count,
            fragment_id as u8,
            (fragment_id == 0).then(|| {
                packet
                    .target
                    .as_ref()
                    .expect("complete TUIC packet target was checked")
                    .clone()
            }),
            payload.to_vec(),
        )?);
    }
    Ok(fragments)
}

pub fn build_tuic_dissociate_frame(association_id: u16) -> [u8; TUIC_DISSOCIATE_FRAME_LEN] {
    let bytes = association_id.to_be_bytes();
    [TUIC_VERSION5, TUIC_DISSOCIATE_TYPE, bytes[0], bytes[1]]
}

pub const fn build_tuic_heartbeat_frame() -> [u8; TUIC_HEARTBEAT_FRAME_LEN] {
    [TUIC_VERSION5, TUIC_HEARTBEAT_TYPE]
}

fn build_address(target: &str) -> Result<TuicAddress, OutboundError> {
    let (host, port) = split_host_port(target)?;
    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        return Ok(TuicAddress {
            atyp: ATYP_IPV4,
            addr: ipv4.octets().to_vec(),
            port,
            target: format!("{ipv4}:{port}"),
        });
    }
    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        return Ok(TuicAddress {
            atyp: ATYP_IPV6,
            addr: ipv6.octets().to_vec(),
            port,
            target: format!("[{ipv6}]:{port}"),
        });
    }
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(bad_wire("invalid TUIC domain address length"));
    }
    let mut addr = Vec::with_capacity(host.len() + 1);
    addr.push(host.len() as u8);
    addr.extend_from_slice(host.as_bytes());
    Ok(TuicAddress {
        atyp: ATYP_DOMAIN_NAME,
        addr,
        port,
        target: format!("{host}:{port}"),
    })
}

fn read_address(input: &[u8], offset: usize) -> Result<(TuicAddress, usize), OutboundError> {
    let Some(&atyp) = input.get(offset) else {
        return Err(bad_wire("missing TUIC address type"));
    };
    if atyp == ATYP_NONE {
        return Ok((
            TuicAddress {
                atyp,
                addr: Vec::new(),
                port: 0,
                target: String::new(),
            },
            offset + 1,
        ));
    }
    let mut cursor = offset + 1;
    let addr = match atyp {
        ATYP_IPV4 => {
            if input.len() < cursor + 4 {
                return Err(bad_wire("short TUIC IPv4 address"));
            }
            let addr = input[cursor..cursor + 4].to_vec();
            cursor += 4;
            addr
        }
        ATYP_IPV6 => {
            if input.len() < cursor + 16 {
                return Err(bad_wire("short TUIC IPv6 address"));
            }
            let addr = input[cursor..cursor + 16].to_vec();
            cursor += 16;
            addr
        }
        ATYP_DOMAIN_NAME => {
            let Some(&len) = input.get(cursor) else {
                return Err(bad_wire("missing TUIC domain length"));
            };
            let domain_len = len as usize;
            if domain_len == 0 || input.len() < cursor + 1 + domain_len {
                return Err(bad_wire("invalid TUIC domain length"));
            }
            let addr = input[cursor..cursor + 1 + domain_len].to_vec();
            cursor += 1 + domain_len;
            addr
        }
        _ => return Err(bad_wire(format!("unsupported TUIC address type: {atyp}"))),
    };
    if input.len() < cursor + 2 {
        return Err(bad_wire("missing TUIC address port"));
    }
    let port = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
    cursor += 2;
    let target = target_from_address(atyp, &addr, port)?;
    Ok((
        TuicAddress {
            atyp,
            addr,
            port,
            target,
        },
        cursor,
    ))
}

fn split_host_port(target: &str) -> Result<(String, u16), OutboundError> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| bad_wire(format!("invalid TUIC target: {target}")))?;
        return Ok((host.to_owned(), parse_port(port)?));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| bad_wire(format!("invalid TUIC target: {target}")))?;
    Ok((host.to_owned(), parse_port(port)?))
}

fn parse_port(input: &str) -> Result<u16, OutboundError> {
    input
        .parse::<u16>()
        .map_err(|err| bad_wire(format!("invalid TUIC target port: {err}")))
}

fn target_from_address(atyp: u8, addr: &[u8], port: u16) -> Result<String, OutboundError> {
    match atyp {
        ATYP_IPV4 => {
            if addr.len() != 4 {
                return Err(bad_wire("invalid TUIC IPv4 address length"));
            }
            Ok(format!(
                "{}.{}.{}.{}:{}",
                addr[0], addr[1], addr[2], addr[3], port
            ))
        }
        ATYP_IPV6 => {
            if addr.len() != 16 {
                return Err(bad_wire("invalid TUIC IPv6 address length"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(addr);
            Ok(format!("[{}]:{}", Ipv6Addr::from(octets), port))
        }
        ATYP_DOMAIN_NAME => {
            if addr.is_empty() {
                return Err(bad_wire("invalid TUIC domain address"));
            }
            let domain = std::str::from_utf8(&addr[1..])
                .map_err(|err| bad_wire(format!("TUIC domain utf8: {err}")))?;
            Ok(format!("{domain}:{port}"))
        }
        _ => Err(bad_wire(format!("unsupported TUIC address type: {atyp}"))),
    }
}

impl TuicAddress {
    fn encoded_len(&self) -> usize {
        if self.atyp == ATYP_NONE {
            1
        } else {
            1 + self.addr.len() + 2
        }
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.push(self.atyp);
        if self.atyp != ATYP_NONE {
            out.extend_from_slice(&self.addr);
            out.extend_from_slice(&self.port.to_be_bytes());
        }
    }
}

impl TuicUdpPacket {
    pub fn new(
        assoc_id: u16,
        packet_id: u16,
        target: impl AsRef<str>,
        payload: impl AsRef<[u8]>,
    ) -> Result<Self, OutboundError> {
        Self::from_parts(
            assoc_id,
            packet_id,
            1,
            0,
            Some(target.as_ref().to_owned()),
            payload.as_ref().to_vec(),
        )
    }

    fn from_parts(
        assoc_id: u16,
        packet_id: u16,
        fragment_count: u8,
        fragment_id: u8,
        target: Option<String>,
        payload: Vec<u8>,
    ) -> Result<Self, OutboundError> {
        validate_udp_packet_fields(fragment_count, fragment_id, target.as_deref(), &payload)?;
        Ok(Self {
            assoc_id,
            packet_id,
            fragment_count,
            fragment_id,
            target,
            payload,
        })
    }

    pub fn association_id(&self) -> u16 {
        self.assoc_id
    }

    pub fn packet_id(&self) -> u16 {
        self.packet_id
    }

    pub fn fragment_count(&self) -> u8 {
        self.fragment_count
    }

    pub fn fragment_id(&self) -> u8 {
        self.fragment_id
    }

    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn encoded_len(&self) -> Result<usize, OutboundError> {
        let address = address_for_optional_target(self.target.as_deref())?;
        Ok(10 + address.encoded_len() + self.payload.len())
    }
}

fn address_for_optional_target(target: Option<&str>) -> Result<TuicAddress, OutboundError> {
    match target {
        Some(target) => build_address(target),
        None => Ok(TuicAddress {
            atyp: ATYP_NONE,
            addr: Vec::new(),
            port: 0,
            target: String::new(),
        }),
    }
}

fn validate_command_head(
    input: &[u8],
    command_type: u8,
    command_name: &str,
) -> Result<(), OutboundError> {
    if input.first().copied() != Some(TUIC_VERSION5) {
        return Err(bad_wire(format!("unsupported TUIC {command_name} version")));
    }
    if input.get(1).copied() != Some(command_type) {
        return Err(bad_wire(format!("bad TUIC {command_name} command type")));
    }
    Ok(())
}

fn validate_udp_packet_fields(
    fragment_count: u8,
    fragment_id: u8,
    target: Option<&str>,
    payload: &[u8],
) -> Result<(), OutboundError> {
    if payload.is_empty() || payload.len() > TUIC_MAX_UDP_PAYLOAD_LENGTH {
        return Err(bad_wire("invalid TUIC UDP payload length"));
    }
    if fragment_count == 0 || fragment_id >= fragment_count {
        return Err(bad_wire(format!(
            "invalid TUIC UDP fragment fields: fragment_id={fragment_id} fragment_count={fragment_count}"
        )));
    }
    if fragment_id == 0 {
        let target = target
            .ok_or_else(|| bad_wire("TUIC UDP first fragment requires a target/source address"))?;
        if target.is_empty() {
            return Err(bad_wire("TUIC UDP first fragment address cannot be empty"));
        }
    } else if target.is_some() {
        return Err(bad_wire(
            "TUIC UDP non-first fragment requires the None address type",
        ));
    }
    Ok(())
}

fn bad_wire(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_roundtrips_supported_address_families() {
        for target in ["192.0.2.1:53", "[2001:db8::1]:5353", "dns.example:443"] {
            let packet = TuicUdpPacket::new(7, 11, target, b"payload").unwrap();
            let encoded = encode_tuic_udp_packet(&packet).unwrap();
            assert_eq!(encoded.len(), packet.encoded_len().unwrap());
            let decoded = decode_tuic_udp_packet(&encoded).unwrap();
            assert_eq!(decoded, packet);
        }
    }

    #[test]
    fn fragmentation_uses_address_only_on_first_fragment() {
        for target in ["192.0.2.1:53", "[2001:db8::1]:5353"] {
            for payload_len in [1_400, 1_500, 4_096] {
                let payload = vec![payload_len as u8; payload_len];
                let packet = TuicUdpPacket::new(9, 1, target, &payload).unwrap();
                let fragments = fragment_tuic_udp_packet(&packet, 17, 1_200).unwrap();
                assert!(fragments.len() > 1);
                assert_eq!(fragments[0].target(), Some(target));
                assert!(
                    fragments
                        .iter()
                        .skip(1)
                        .all(|fragment| fragment.target().is_none())
                );
                assert!(
                    fragments.iter().all(|fragment| {
                        encode_tuic_udp_packet(fragment).unwrap().len() <= 1_200
                    })
                );
                let reassembled = fragments
                    .iter()
                    .flat_map(|fragment| fragment.payload().iter().copied())
                    .collect::<Vec<_>>();
                assert_eq!(reassembled, payload);
                for fragment in fragments {
                    let encoded = encode_tuic_udp_packet(&fragment).unwrap();
                    assert_eq!(decode_tuic_udp_packet(&encoded).unwrap(), fragment);
                }
            }
        }
    }

    #[test]
    fn parser_rejects_wrong_version_and_fragment_address_shape() {
        let packet = TuicUdpPacket::new(5, 8, "192.0.2.1:53", vec![1; 1_500]).unwrap();
        let fragments = fragment_tuic_udp_packet(&packet, 9, 1_200).unwrap();

        let mut wrong_version = encode_tuic_udp_packet(&fragments[0]).unwrap();
        wrong_version[0] = TUIC_VERSION5 - 1;
        assert!(decode_tuic_udp_packet(&wrong_version).is_err());

        let mut address_on_non_first = encode_tuic_udp_packet(&fragments[0]).unwrap();
        address_on_non_first[7] = 1;
        assert!(decode_tuic_udp_packet(&address_on_non_first).is_err());

        let mut missing_first_address = encode_tuic_udp_packet(&fragments[1]).unwrap();
        missing_first_address[7] = 0;
        assert!(decode_tuic_udp_packet(&missing_first_address).is_err());
    }

    #[test]
    fn control_commands_match_the_version_five_wire_shape() {
        assert_eq!(
            build_tuic_dissociate_frame(0x1234),
            [TUIC_VERSION5, TUIC_DISSOCIATE_TYPE, 0x12, 0x34]
        );
        assert_eq!(
            build_tuic_heartbeat_frame(),
            [TUIC_VERSION5, TUIC_HEARTBEAT_TYPE]
        );
        let mut auth = build_authenticate_frame([1; 16], [2; TUIC_AUTH_TOKEN_LEN]);
        assert!(parse_authenticate_frame(&auth).is_ok());
        auth[0] = TUIC_VERSION5 - 1;
        assert!(parse_authenticate_frame(&auth).is_err());
    }
}
