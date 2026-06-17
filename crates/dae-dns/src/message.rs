use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::cache_key::canonical_name_lowercase;
use crate::error::{DnsError, DnsValidationError};

mod packet_answer_view;
mod packet_view;

pub use packet_answer_view::{DnsPacketAnswerIter, DnsPacketAnswerView, DnsPacketNameView};
pub use packet_view::{
    DnsPacketQuestionIter, DnsPacketQuestionView, DnsPacketView,
    validate_dns_packet_response_for_request, validate_dns_packet_response_for_request_fast,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn new(qname: impl AsRef<str>, qtype: u16, qclass: u16) -> Self {
        Self {
            qname: canonical_name_lowercase(qname.as_ref()),
            qtype,
            qclass,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsAnswer {
    A {
        name: String,
        ttl: u32,
        addr: Ipv4Addr,
    },
    Aaaa {
        name: String,
        ttl: u32,
        addr: Ipv6Addr,
    },
    Cname {
        name: String,
        ttl: u32,
        target: String,
    },
    Other {
        name: String,
        qtype: u16,
        ttl: u32,
    },
}

impl DnsAnswer {
    pub fn ttl(&self) -> u32 {
        match self {
            Self::A { ttl, .. }
            | Self::Aaaa { ttl, .. }
            | Self::Cname { ttl, .. }
            | Self::Other { ttl, .. } => *ttl,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::A { addr, .. } => Some(IpAddr::V4(*addr)),
            Self::Aaaa { addr, .. } => Some(IpAddr::V6(*addr)),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::A { .. } => "A",
            Self::Aaaa { .. } => "AAAA",
            Self::Cname { .. } => "CNAME",
            Self::Other { .. } => "OTHER",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsMessage {
    pub fn new(id: u16, response: bool, questions: Vec<DnsQuestion>) -> Self {
        Self {
            id,
            response,
            questions,
            answers: Vec::new(),
        }
    }
}

pub fn dns_data_with_zero_id(data: &[u8]) -> Vec<u8> {
    let mut cloned = data.to_vec();
    if cloned.len() >= 2 {
        cloned[0] = 0;
        cloned[1] = 0;
    }
    cloned
}

pub fn restore_packed_response_request_id(packed: &[u8], request_id: u16) -> Option<Vec<u8>> {
    if packed.len() < 2 {
        return None;
    }
    let mut restored = packed.to_vec();
    restored[0] = (request_id >> 8) as u8;
    restored[1] = request_id as u8;
    Some(restored)
}

pub fn restore_packed_response_request_id_into(
    packed: &[u8],
    request_id: u16,
    out: &mut Vec<u8>,
) -> Option<()> {
    if packed.len() < 2 {
        return None;
    }
    out.clear();
    out.extend_from_slice(packed);
    out[0] = (request_id >> 8) as u8;
    out[1] = request_id as u8;
    Some(())
}

pub fn validate_dns_response_for_request(
    req: &DnsMessage,
    resp: Option<&DnsMessage>,
    require_matching_id: bool,
) -> Result<(), DnsError> {
    validate_dns_response_for_request_fast(req, resp, require_matching_id)
        .map_err(|err| validation_error_to_dns_error(err, req, resp))
}

pub fn validate_dns_response_for_request_fast(
    req: &DnsMessage,
    resp: Option<&DnsMessage>,
    require_matching_id: bool,
) -> Result<(), DnsValidationError> {
    let resp = resp.ok_or(DnsValidationError::DnsResponseNil)?;
    if !resp.response {
        return Err(DnsValidationError::DnsRequestReceived);
    }
    if require_matching_id && resp.id != req.id {
        return Err(DnsValidationError::IdMismatch {
            got: resp.id,
            want: req.id,
        });
    }
    if req.questions.is_empty() {
        return Ok(());
    }
    if resp.questions.is_empty() {
        return Err(DnsValidationError::MissingQuestion);
    }
    if resp.questions.len() != req.questions.len() {
        return Err(DnsValidationError::QuestionCountMismatch {
            got: resp.questions.len(),
            want: req.questions.len(),
        });
    }
    for (index, (want, got)) in req.questions.iter().zip(resp.questions.iter()).enumerate() {
        if want == got {
            continue;
        }
        return Err(DnsValidationError::QuestionMismatch { index });
    }
    Ok(())
}

fn validation_error_to_dns_error(
    error: DnsValidationError,
    req: &DnsMessage,
    resp: Option<&DnsMessage>,
) -> DnsError {
    match error {
        DnsValidationError::DnsResponseNil => DnsError::DnsResponseNil,
        DnsValidationError::DnsRequestReceived => DnsError::DnsRequestReceived,
        DnsValidationError::MissingQuestion => DnsError::MissingQuestion,
        DnsValidationError::QuestionCountMismatch { got, want } => {
            DnsError::QuestionCountMismatch { got, want }
        }
        DnsValidationError::QuestionMismatch { index } => {
            let got = resp
                .and_then(|message| message.questions.get(index))
                .map(format_dns_question)
                .unwrap_or_default();
            let want = req
                .questions
                .get(index)
                .map(format_dns_question)
                .unwrap_or_default();
            DnsError::QuestionMismatch { index, got, want }
        }
        DnsValidationError::IdMismatch { got, want } => DnsError::IdMismatch { got, want },
    }
}

pub fn parse_message(packet: &[u8]) -> Result<DnsMessage, DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let qdcount = read_u16(packet, 4)? as usize;
    let ancount = read_u16(packet, 6)? as usize;
    let mut offset = 12;

    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let (qname, next) = read_name(packet, offset, 0)?;
        offset = next;
        let qtype = read_u16(packet, offset)?;
        let qclass = read_u16(packet, offset + 2)?;
        offset += 4;
        questions.push(DnsQuestion::new(qname, qtype, qclass));
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (name, next) = read_name(packet, offset, 0)?;
        offset = next;
        let qtype = read_u16(packet, offset)?;
        let qclass = read_u16(packet, offset + 2)?;
        let ttl = read_u32(packet, offset + 4)?;
        let rdlen = read_u16(packet, offset + 8)? as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let answer = match (qtype, qclass, rdlen) {
            (1, 1, 4) => DnsAnswer::A {
                name: canonical_name_lowercase(&name),
                ttl,
                addr: Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                ),
            },
            (28, 1, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[offset..offset + 16]);
                DnsAnswer::Aaaa {
                    name: canonical_name_lowercase(&name),
                    ttl,
                    addr: Ipv6Addr::from(octets),
                }
            }
            (5, 1, _) => {
                let (target, _) = read_name(packet, offset, 0)?;
                DnsAnswer::Cname {
                    name: canonical_name_lowercase(&name),
                    ttl,
                    target: canonical_name_lowercase(&target),
                }
            }
            _ => DnsAnswer::Other {
                name: canonical_name_lowercase(&name),
                qtype,
                ttl,
            },
        };
        answers.push(answer);
        offset += rdlen;
    }

    Ok(DnsMessage {
        id,
        response: flags & 0x8000 != 0,
        questions,
        answers,
    })
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, DnsError> {
    if !input.len().is_multiple_of(2) {
        return Err(DnsError::InvalidHex(input.to_owned()));
    }

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

pub fn encode_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn format_dns_question(q: &DnsQuestion) -> String {
    format!(
        "{} {} class={}",
        q.qname.to_ascii_lowercase(),
        qtype_to_string(q.qtype),
        q.qclass
    )
}

pub fn qtype_to_string(qtype: u16) -> String {
    match qtype {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        28 => "AAAA".to_owned(),
        _ => qtype.to_string(),
    }
}

fn read_name(packet: &[u8], mut offset: usize, depth: usize) -> Result<(String, usize), DnsError> {
    if depth > 16 {
        return Err(DnsError::CompressionLoop);
    }
    let start = offset;
    let mut name = String::with_capacity(packet.len().saturating_sub(offset).min(255));
    loop {
        if offset >= packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let len = packet[offset];
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err(DnsError::UnexpectedEof);
            }
            let ptr = (((len & 0x3f) as usize) << 8) | packet[offset + 1] as usize;
            let (suffix, _) = read_name(packet, ptr, depth + 1)?;
            if suffix != "." {
                name.push_str(&suffix);
            }
            return Ok((finish_name(name), offset + 2));
        }
        if len & 0xc0 != 0 {
            return Err(DnsError::InvalidDnsName);
        }
        offset += 1;
        if len == 0 {
            return Ok((finish_name(name), offset));
        }
        let end = offset + len as usize;
        if end > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let label =
            std::str::from_utf8(&packet[offset..end]).map_err(|_| DnsError::InvalidDnsName)?;
        if label.is_empty() || start == end {
            return Err(DnsError::InvalidDnsName);
        }
        name.push_str(label);
        name.push('.');
        offset = end;
    }
}

fn finish_name(name: String) -> String {
    if name.is_empty() {
        ".".to_owned()
    } else {
        name
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    if offset + 2 > packet.len() {
        return Err(DnsError::UnexpectedEof);
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, DnsError> {
    if offset + 4 > packet.len() {
        return Err(DnsError::UnexpectedEof);
    }
    Ok(u32::from_be_bytes([
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    ]))
}

fn hex_nibble(ch: u8) -> Result<u8, DnsError> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(DnsError::InvalidHex((ch as char).to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_response_and_validation_match_golden_fixture() {
        let fixture = dae_golden::load_json("dns/packed_response/basic.json").unwrap();
        let restore = &fixture["restore_request_id"];
        let packed = decode_hex(restore["packed_zero_id_hex"].as_str().unwrap()).unwrap();
        let request_id = restore["request_id"].as_u64().unwrap() as u16;
        let restored = restore_packed_response_request_id(&packed, request_id).unwrap();
        assert_eq!(
            encode_hex(&restored),
            restore["restored_hex"].as_str().unwrap()
        );
        assert_eq!(
            &encode_hex(&restored[..2]),
            restore["restored_prefix"].as_str().unwrap()
        );

        let cname = &fixture["cname_restore"];
        let msg = parse_message(&decode_hex(cname["packed_hex"].as_str().unwrap()).unwrap())
            .expect("parse cname packed response");
        let kinds: Vec<&str> = msg.answers.iter().map(DnsAnswer::kind).collect();
        let want_kinds: Vec<&str> = cname["answer_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(kinds, want_kinds);
        assert!(msg.answers.iter().any(|answer| {
            answer.ip().map(|ip| ip.to_string())
                == Some(cname["target_ip"].as_str().unwrap().to_owned())
        }));
    }

    #[test]
    fn dns_response_validation_matches_golden_fixture() {
        let fixture = dae_golden::load_json("dns/validation/question_and_id.json").unwrap();
        let req_json = &fixture["request"];
        let req = DnsMessage::new(
            req_json["id"].as_u64().unwrap() as u16,
            false,
            vec![question_from_json(req_json)],
        );

        for case in fixture["cases"].as_array().unwrap() {
            let questions = case["questions"]
                .as_array()
                .unwrap()
                .iter()
                .map(question_from_json)
                .collect();
            let resp = DnsMessage::new(
                case["response_id"].as_u64().unwrap() as u16,
                true,
                questions,
            );
            let got = validate_dns_response_for_request(
                &req,
                Some(&resp),
                case["require_id"].as_bool().unwrap(),
            );
            assert_eq!(
                got.is_ok(),
                case["ok"].as_bool().unwrap(),
                "{}",
                case["name"].as_str().unwrap()
            );
            if let Err(err) = got {
                assert_eq!(err.to_string(), case["error"].as_str().unwrap());
            }
        }
    }

    fn question_from_json(value: &serde_json::Value) -> DnsQuestion {
        DnsQuestion::new(
            value["qname"].as_str().unwrap(),
            value["qtype"].as_u64().unwrap() as u16,
            value["qclass"].as_u64().unwrap() as u16,
        )
    }
}
