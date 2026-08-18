use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::DnsError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsPacketNameView<'a> {
    packet: &'a [u8],
    offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPacketAnswerView<'a> {
    A {
        name: DnsPacketNameView<'a>,
        ttl: u32,
        addr: Ipv4Addr,
    },
    Aaaa {
        name: DnsPacketNameView<'a>,
        ttl: u32,
        addr: Ipv6Addr,
    },
    Cname {
        name: DnsPacketNameView<'a>,
        ttl: u32,
        target: DnsPacketNameView<'a>,
    },
    Other {
        name: DnsPacketNameView<'a>,
        qtype: u16,
        ttl: u32,
        rdata: &'a [u8],
    },
}

#[derive(Clone, Debug)]
pub struct DnsPacketAnswerIter<'a> {
    packet: &'a [u8],
    offset: usize,
    remaining: u16,
}

#[derive(Clone, Debug)]
struct DnsPacketNameLabelIter<'a> {
    packet: &'a [u8],
    offset: usize,
    depth: usize,
    done: bool,
}

impl<'a> DnsPacketAnswerIter<'a> {
    pub(super) const fn new(packet: &'a [u8], offset: usize, remaining: u16) -> Self {
        Self {
            packet,
            offset,
            remaining,
        }
    }
}

impl<'a> DnsPacketNameView<'a> {
    pub(super) const fn new(packet: &'a [u8], offset: usize) -> Self {
        Self { packet, offset }
    }

    pub fn canonical_eq_ignore_ascii_case(&self, candidate: &str) -> Result<bool, DnsError> {
        let trimmed = candidate.trim().trim_end_matches('.');
        let mut candidate_labels = trimmed.split('.');
        let mut saw_candidate_label = false;
        for label in self.labels() {
            let label = label?;
            let Some(candidate_label) = candidate_labels.next() else {
                return Ok(false);
            };
            saw_candidate_label = true;
            if !label.eq_ignore_ascii_case(candidate_label.as_bytes()) {
                return Ok(false);
            }
        }
        Ok(candidate_labels.next().is_none() && (saw_candidate_label || trimmed.is_empty()))
    }

    pub fn to_canonical_string(self) -> Result<String, DnsError> {
        let mut out = String::new();
        for label in self.labels() {
            let label = label?;
            if !out.is_empty() {
                out.push('.');
            }
            let label = std::str::from_utf8(label).map_err(|_| DnsError::InvalidDnsName)?;
            for ch in label.chars() {
                out.push(ch.to_ascii_lowercase());
            }
        }
        out.push('.');
        Ok(out)
    }

    fn labels(self) -> DnsPacketNameLabelIter<'a> {
        DnsPacketNameLabelIter {
            packet: self.packet,
            offset: self.offset,
            depth: 0,
            done: false,
        }
    }
}

impl DnsPacketAnswerView<'_> {
    pub const fn ttl(&self) -> u32 {
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

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::A { .. } => "A",
            Self::Aaaa { .. } => "AAAA",
            Self::Cname { .. } => "CNAME",
            Self::Other { .. } => "OTHER",
        }
    }

    pub const fn qtype(&self) -> u16 {
        match self {
            Self::A { .. } => 1,
            Self::Aaaa { .. } => 28,
            Self::Cname { .. } => 5,
            Self::Other { qtype, .. } => *qtype,
        }
    }

    pub const fn name(&self) -> DnsPacketNameView<'_> {
        match self {
            Self::A { name, .. }
            | Self::Aaaa { name, .. }
            | Self::Cname { name, .. }
            | Self::Other { name, .. } => *name,
        }
    }

    pub const fn cname_target(&self) -> Option<DnsPacketNameView<'_>> {
        match self {
            Self::Cname { target, .. } => Some(*target),
            _ => None,
        }
    }
}

impl<'a> Iterator for DnsPacketAnswerIter<'a> {
    type Item = Result<DnsPacketAnswerView<'a>, DnsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        let name_offset = self.offset;
        let name_end = match scan_name(self.packet, self.offset, 0, self.packet.len()) {
            Ok(offset) => offset,
            Err(err) => return Some(Err(err)),
        };
        let qtype = match read_u16(self.packet, name_end) {
            Ok(value) => value,
            Err(err) => return Some(Err(err)),
        };
        let qclass = match read_u16(self.packet, name_end + 2) {
            Ok(value) => value,
            Err(err) => return Some(Err(err)),
        };
        let ttl = match read_u32(self.packet, name_end + 4) {
            Ok(value) => value,
            Err(err) => return Some(Err(err)),
        };
        let rdlen = match read_u16(self.packet, name_end + 8) {
            Ok(value) => value as usize,
            Err(err) => return Some(Err(err)),
        };
        let rdata_offset = name_end + 10;
        let rdata_end = rdata_offset + rdlen;
        if rdata_end > self.packet.len() {
            return Some(Err(DnsError::UnexpectedEof));
        }
        self.offset = rdata_end;

        let name = DnsPacketNameView::new(self.packet, name_offset);
        let answer = match (qtype, qclass, rdlen) {
            (1, 1, 4) => DnsPacketAnswerView::A {
                name,
                ttl,
                addr: Ipv4Addr::new(
                    self.packet[rdata_offset],
                    self.packet[rdata_offset + 1],
                    self.packet[rdata_offset + 2],
                    self.packet[rdata_offset + 3],
                ),
            },
            (28, 1, 16) => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&self.packet[rdata_offset..rdata_end]);
                DnsPacketAnswerView::Aaaa {
                    name,
                    ttl,
                    addr: Ipv6Addr::from(octets),
                }
            }
            (5, 1, _) => {
                match scan_name(self.packet, rdata_offset, 0, rdata_end) {
                    Ok(consumed) if consumed <= rdata_end => {}
                    Ok(_) | Err(_) => return Some(Err(DnsError::InvalidDnsName)),
                }
                DnsPacketAnswerView::Cname {
                    name,
                    ttl,
                    target: DnsPacketNameView::new(self.packet, rdata_offset),
                }
            }
            _ => DnsPacketAnswerView::Other {
                name,
                qtype,
                ttl,
                rdata: &self.packet[rdata_offset..rdata_end],
            },
        };
        Some(Ok(answer))
    }
}

impl<'a> Iterator for DnsPacketNameLabelIter<'a> {
    type Item = Result<&'a [u8], DnsError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if self.depth > 16 {
                self.done = true;
                return Some(Err(DnsError::CompressionLoop));
            }
            if self.offset >= self.packet.len() {
                self.done = true;
                return Some(Err(DnsError::UnexpectedEof));
            }
            let len = self.packet[self.offset];
            if len & 0xc0 == 0xc0 {
                if self.offset + 1 >= self.packet.len() {
                    self.done = true;
                    return Some(Err(DnsError::UnexpectedEof));
                }
                self.offset =
                    (((len & 0x3f) as usize) << 8) | self.packet[self.offset + 1] as usize;
                self.depth += 1;
                continue;
            }
            if len & 0xc0 != 0 || len > 63 {
                self.done = true;
                return Some(Err(DnsError::InvalidDnsName));
            }
            self.offset += 1;
            if len == 0 {
                self.done = true;
                return None;
            }
            let end = self.offset + len as usize;
            if end > self.packet.len() {
                self.done = true;
                return Some(Err(DnsError::UnexpectedEof));
            }
            let label = &self.packet[self.offset..end];
            self.offset = end;
            return Some(Ok(label));
        }
    }
}

fn scan_name(
    packet: &[u8],
    mut offset: usize,
    depth: usize,
    scope_end: usize,
) -> Result<usize, DnsError> {
    if depth > 16 {
        return Err(DnsError::CompressionLoop);
    }
    loop {
        if offset >= packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let len = packet[offset];
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err(DnsError::UnexpectedEof);
            }
            let consumed = offset + 2;
            if consumed > scope_end {
                return Err(DnsError::InvalidDnsName);
            }
            let ptr = (((len & 0x3f) as usize) << 8) | packet[offset + 1] as usize;
            scan_name(packet, ptr, depth + 1, packet.len())?;
            return Ok(consumed);
        }
        if len & 0xc0 != 0 || len > 63 {
            return Err(DnsError::InvalidDnsName);
        }
        offset += 1;
        if len == 0 {
            if offset > scope_end {
                return Err(DnsError::InvalidDnsName);
            }
            return Ok(offset);
        }
        offset += len as usize;
        if offset > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        if offset > scope_end {
            return Err(DnsError::InvalidDnsName);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active::build_active_dns_a_response;
    use crate::message::packet_view::DnsPacketView;
    use crate::message::{DnsAnswer, decode_hex, parse_message};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn answer_view_matches_packed_cname_golden() {
        let fixture = dae_golden::load_json("dns/packed_response/basic.json").unwrap();
        let cname = &fixture["cname_restore"];
        let packet = decode_hex(cname["packed_hex"].as_str().unwrap()).unwrap();
        assert_answer_view_parity(&packet);

        let view = DnsPacketView::parse(&packet).unwrap();
        let answers: Vec<DnsPacketAnswerView<'_>> = view
            .answers()
            .collect::<Result<Vec<_>, _>>()
            .expect("packet answer view");
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].kind(), "CNAME");
        assert_eq!(answers[0].ttl(), 60);
        assert!(
            answers[0]
                .cname_target()
                .unwrap()
                .canonical_eq_ignore_ascii_case(cname["target"].as_str().unwrap())
                .unwrap()
        );
        assert_eq!(
            answers[1].ip().map(|ip| ip.to_string()),
            Some(cname["target_ip"].as_str().unwrap().to_owned())
        );
    }

    #[test]
    fn answer_view_matches_compressed_a_and_aaaa() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let a_response =
            build_active_dns_a_response(&query, Ipv4Addr::new(203, 0, 113, 54), 30).unwrap();
        assert_answer_view_parity(&a_response);

        let a_view = DnsPacketView::parse(&a_response).unwrap();
        let a_answers: Vec<DnsPacketAnswerView<'_>> =
            a_view.answers().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(a_answers[0].kind(), "A");
        assert_eq!(a_answers[0].ttl(), 30);
        assert_eq!(
            a_answers[0].ip(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 54)))
        );

        let aaaa_response = [
            0x33, 0x33, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10, 0x20,
            0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01,
        ];
        assert_answer_view_parity(&aaaa_response);
        let aaaa_view = DnsPacketView::parse(&aaaa_response).unwrap();
        let aaaa_answers: Vec<DnsPacketAnswerView<'_>> =
            aaaa_view.answers().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(aaaa_answers[0].kind(), "AAAA");
        assert_eq!(aaaa_answers[0].ttl(), 120);
        assert_eq!(aaaa_answers[0].ip().unwrap().to_string(), "2001:db8::1");
    }

    fn assert_answer_view_parity(packet: &[u8]) {
        let owned = parse_message(packet).expect("owned dns parse");
        let view = DnsPacketView::parse(packet).expect("packet dns view");
        assert_eq!(view.answer_count(), owned.answers.len());
        let viewed: Vec<DnsPacketAnswerView<'_>> = view
            .answers()
            .collect::<Result<Vec<_>, _>>()
            .expect("packet answer view");
        assert_eq!(viewed.len(), owned.answers.len());

        for (owned, viewed) in owned.answers.iter().zip(viewed.iter()) {
            assert_eq!(viewed.ttl(), owned.ttl());
            assert_eq!(viewed.ip(), owned.ip());
            assert_eq!(viewed.kind(), owned.kind());
            match owned {
                DnsAnswer::A { name, .. }
                | DnsAnswer::Aaaa { name, .. }
                | DnsAnswer::Other { name, .. } => {
                    assert!(viewed.name().canonical_eq_ignore_ascii_case(name).unwrap());
                }
                DnsAnswer::Cname { name, target, .. } => {
                    assert!(viewed.name().canonical_eq_ignore_ascii_case(name).unwrap());
                    assert!(
                        viewed
                            .cname_target()
                            .unwrap()
                            .canonical_eq_ignore_ascii_case(target)
                            .unwrap()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod rdlength_boundary_tests {
    use super::*;
    use crate::message::packet_view::DnsPacketView;

    #[test]
    fn cname_name_consumption_beyond_rdlength_is_rejected() {
        // header: id=0x1234 flags=0x8180 qd=1 an=1 ns=0 ar=0
        let mut packet = Vec::new();
        packet.extend_from_slice(&[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        // question: a.example (1 label + 1 label + 0), qtype=1, qclass=1
        packet.extend_from_slice(b"\x01a\x07example\x00");
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // answer: name ptr 0xc00c, type CNAME(5), class 1, ttl 60
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(b"\x01b\x07example\x00");

        let view = DnsPacketView::parse(&packet).expect("packet parses");
        let answers: Result<Vec<_>, _> = view.answers().collect();
        let err = answers.expect_err("over-running CNAME must be rejected");
        assert!(matches!(err, DnsError::InvalidDnsName));
    }
}
