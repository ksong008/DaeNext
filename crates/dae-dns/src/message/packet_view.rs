use crate::error::{DnsError, DnsValidationError};

use super::{packet_answer_view::DnsPacketAnswerIter, qtype_to_string};

const DNS_HEADER_LEN: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPacketView<'a> {
    packet: &'a [u8],
    id: u16,
    response: bool,
    question_count: u16,
    answer_count: u16,
    answer_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPacketQuestionView<'a> {
    qname_wire: &'a [u8],
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Debug)]
pub struct DnsPacketQuestionIter<'a> {
    packet: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> DnsPacketView<'a> {
    pub fn parse(packet: &'a [u8]) -> Result<Self, DnsError> {
        if packet.len() < DNS_HEADER_LEN {
            return Err(DnsError::PacketTooShort);
        }
        let question_count = read_u16(packet, 4)?;
        let answer_offset = validate_question_section(packet, question_count)?;
        Ok(Self {
            packet,
            id: read_u16(packet, 0)?,
            response: read_u16(packet, 2)? & 0x8000 != 0,
            question_count,
            answer_count: read_u16(packet, 6)?,
            answer_offset,
        })
    }

    pub const fn id(&self) -> u16 {
        self.id
    }

    pub const fn response(&self) -> bool {
        self.response
    }

    pub const fn question_count(&self) -> usize {
        self.question_count as usize
    }

    pub const fn answer_count(&self) -> usize {
        self.answer_count as usize
    }

    pub const fn answer_offset(&self) -> usize {
        self.answer_offset
    }

    pub fn questions(&self) -> DnsPacketQuestionIter<'a> {
        DnsPacketQuestionIter {
            packet: self.packet,
            offset: DNS_HEADER_LEN,
            remaining: self.question_count,
        }
    }

    pub fn answers(&self) -> DnsPacketAnswerIter<'a> {
        DnsPacketAnswerIter::new(self.packet, self.answer_offset, self.answer_count)
    }
}

impl DnsPacketQuestionView<'_> {
    pub fn matches(&self, other: &Self) -> bool {
        self.qtype == other.qtype
            && self.qclass == other.qclass
            && wire_name_eq_ignore_ascii_case(self.qname_wire, other.qname_wire)
    }

    pub const fn qtype(&self) -> u16 {
        self.qtype
    }

    pub const fn qclass(&self) -> u16 {
        self.qclass
    }

    pub const fn qname_wire(&self) -> &[u8] {
        self.qname_wire
    }

    pub fn qname_to_canonical_string(&self) -> Result<String, DnsError> {
        wire_name_to_canonical_string(self.qname_wire)
    }

    pub fn qname_canonical_eq_ignore_ascii_case(&self, candidate: &str) -> Result<bool, DnsError> {
        wire_name_eq_canonical_ignore_ascii_case(self.qname_wire, candidate)
    }

    pub fn format_question(&self) -> Result<String, DnsError> {
        Ok(format!(
            "{} {} class={}",
            self.qname_to_canonical_string()?,
            qtype_to_string(self.qtype),
            self.qclass
        ))
    }
}

impl<'a> Iterator for DnsPacketQuestionIter<'a> {
    type Item = DnsPacketQuestionView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let qname_start = self.offset;
        let qname_end = scan_uncompressed_name(self.packet, qname_start).ok()?;
        let qtype = read_u16(self.packet, qname_end).ok()?;
        let qclass = read_u16(self.packet, qname_end + 2).ok()?;
        self.offset = qname_end + 4;
        self.remaining -= 1;
        Some(DnsPacketQuestionView {
            qname_wire: &self.packet[qname_start..qname_end],
            qtype,
            qclass,
        })
    }
}

pub fn validate_dns_packet_response_for_request_fast(
    req: &DnsPacketView<'_>,
    resp: Option<&DnsPacketView<'_>>,
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
    if req.question_count == 0 {
        return Ok(());
    }
    if resp.question_count == 0 {
        return Err(DnsValidationError::MissingQuestion);
    }
    if resp.question_count != req.question_count {
        return Err(DnsValidationError::QuestionCountMismatch {
            got: resp.question_count as usize,
            want: req.question_count as usize,
        });
    }
    for (index, (want, got)) in req.questions().zip(resp.questions()).enumerate() {
        if want.matches(&got) {
            continue;
        }
        return Err(DnsValidationError::QuestionMismatch { index });
    }
    Ok(())
}

pub fn validate_dns_packet_response_for_request(
    req_packet: &[u8],
    resp_packet: Option<&[u8]>,
    require_matching_id: bool,
) -> Result<(), DnsError> {
    let Some(resp_packet) = resp_packet else {
        return Err(DnsError::DnsResponseNil);
    };

    let req = DnsPacketView::parse(req_packet)?;
    let resp = DnsPacketView::parse(resp_packet)?;
    validate_dns_packet_response_for_request_fast(&req, Some(&resp), require_matching_id)
        .map_err(|err| packet_validation_error_to_dns_error(err, &req, Some(&resp)))
}

fn validate_question_section(packet: &[u8], question_count: u16) -> Result<usize, DnsError> {
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..question_count {
        offset = scan_uncompressed_name(packet, offset)?;
        read_u16(packet, offset)?;
        read_u16(packet, offset + 2)?;
        offset += 4;
    }
    Ok(offset)
}

fn scan_uncompressed_name(packet: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    loop {
        if offset >= packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let len = packet[offset];
        if len & 0xc0 != 0 {
            return Err(DnsError::InvalidDnsName);
        }
        if len > 63 {
            return Err(DnsError::InvalidDnsName);
        }
        offset += 1;
        if len == 0 {
            return Ok(offset);
        }
        let end = offset + len as usize;
        if end > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        offset = end;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    if offset + 2 > packet.len() {
        return Err(DnsError::UnexpectedEof);
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn wire_name_eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn wire_name_to_canonical_string(wire: &[u8]) -> Result<String, DnsError> {
    let mut offset = 0;
    let mut out = String::new();
    loop {
        if offset >= wire.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let len = wire[offset];
        if len & 0xc0 != 0 || len > 63 {
            return Err(DnsError::InvalidDnsName);
        }
        offset += 1;
        if len == 0 {
            if out.is_empty() {
                out.push('.');
            } else {
                out.push('.');
            }
            return Ok(out);
        }
        let end = offset + len as usize;
        if end > wire.len() {
            return Err(DnsError::UnexpectedEof);
        }
        if !out.is_empty() {
            out.push('.');
        }
        let label =
            std::str::from_utf8(&wire[offset..end]).map_err(|_| DnsError::InvalidDnsName)?;
        for ch in label.chars() {
            out.push(ch.to_ascii_lowercase());
        }
        offset = end;
    }
}

fn wire_name_eq_canonical_ignore_ascii_case(
    wire: &[u8],
    candidate: &str,
) -> Result<bool, DnsError> {
    let trimmed = candidate.trim().trim_end_matches('.');
    let mut candidate_labels = trimmed.split('.');
    let mut saw_candidate_label = false;
    let mut offset = 0;
    loop {
        if offset >= wire.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let len = wire[offset];
        if len & 0xc0 != 0 || len > 63 {
            return Err(DnsError::InvalidDnsName);
        }
        offset += 1;
        if len == 0 {
            return Ok(
                candidate_labels.next().is_none() && (saw_candidate_label || trimmed.is_empty())
            );
        }
        let end = offset + len as usize;
        if end > wire.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let Some(candidate_label) = candidate_labels.next() else {
            return Ok(false);
        };
        saw_candidate_label = true;
        if !wire[offset..end].eq_ignore_ascii_case(candidate_label.as_bytes()) {
            return Ok(false);
        }
        offset = end;
    }
}

fn packet_validation_error_to_dns_error(
    error: DnsValidationError,
    req: &DnsPacketView<'_>,
    resp: Option<&DnsPacketView<'_>>,
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
                .and_then(|message| message.questions().nth(index))
                .and_then(|question| question.format_question().ok())
                .unwrap_or_default();
            let want = req
                .questions()
                .nth(index)
                .and_then(|question| question.format_question().ok())
                .unwrap_or_default();
            DnsError::QuestionMismatch { index, got, want }
        }
        DnsValidationError::IdMismatch { got, want } => DnsError::IdMismatch { got, want },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_view_validates_question_and_id_without_owned_parse() {
        let request = [
            0x11, 0x11, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let matching = [
            0x11, 0x11, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'E',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'C', b'O', b'M', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let mismatched_id = [
            0x22, 0x22, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let mismatched_question = [
            0x11, 0x11, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, b'o',
            b't', b'h', b'e', b'r', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let request = DnsPacketView::parse(&request).unwrap();
        let matching = DnsPacketView::parse(&matching).unwrap();
        let mismatched_id = DnsPacketView::parse(&mismatched_id).unwrap();
        let mismatched_question = DnsPacketView::parse(&mismatched_question).unwrap();

        assert!(
            validate_dns_packet_response_for_request_fast(&request, Some(&matching), true).is_ok()
        );
        assert_eq!(
            validate_dns_packet_response_for_request_fast(&request, Some(&mismatched_id), true),
            Err(DnsValidationError::IdMismatch {
                got: 0x2222,
                want: 0x1111
            })
        );
        assert!(
            validate_dns_packet_response_for_request_fast(&request, Some(&mismatched_id), false)
                .is_ok()
        );
        assert_eq!(
            validate_dns_packet_response_for_request_fast(
                &request,
                Some(&mismatched_question),
                true
            ),
            Err(DnsValidationError::QuestionMismatch { index: 0 })
        );
        assert_eq!(request.question_count(), 1);
        let question = matching.questions().next().unwrap();
        assert_eq!(question.qtype(), 1);
        assert_eq!(
            question.qname_to_canonical_string().unwrap(),
            "example.com."
        );
        assert!(
            question
                .qname_canonical_eq_ignore_ascii_case("Example.COM")
                .unwrap()
        );
        assert_eq!(
            question.format_question().unwrap(),
            "example.com. A class=1"
        );
        assert!(
            validate_dns_packet_response_for_request(request.packet, Some(matching.packet), true)
                .is_ok()
        );
    }
}
