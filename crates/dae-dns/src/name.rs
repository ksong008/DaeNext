use crate::DnsError;

/// Scan an encoded name, bounding its expanded wire representation (RFC 1035).
/// `scope_end` bounds bytes consumed at the original location, not pointer targets.
#[inline]
pub fn scan_dns_name(
    packet: &[u8],
    mut offset: usize,
    mut scope_end: usize,
    compressed: bool,
) -> Result<usize, DnsError> {
    let mut consumed = None;
    // Count contiguous label bytes with offsets; compression pointer bytes
    // consume packet space but never consume the expanded-name budget.
    let mut expanded = 0usize;
    let mut segment_start = offset;
    let mut segment_end = offset.saturating_add(255).min(scope_end).min(packet.len());
    let mut jumps = 0;
    loop {
        let len = *packet.get(offset).ok_or(DnsError::UnexpectedEof)?;
        if len & 0xc0 == 0xc0 {
            if !compressed {
                return Err(DnsError::InvalidDnsName);
            }
            let second = *packet.get(offset + 1).ok_or(DnsError::UnexpectedEof)?;
            if offset + 2 > scope_end {
                return Err(DnsError::InvalidDnsName);
            }
            expanded += offset - segment_start;
            if expanded >= 255 {
                return Err(DnsError::InvalidDnsName);
            }
            consumed.get_or_insert(offset + 2);
            offset = (usize::from(len & 0x3f) << 8) | usize::from(second);
            scope_end = packet.len();
            segment_start = offset;
            segment_end = offset.saturating_add(255 - expanded).min(packet.len());
            jumps += 1;
            if jumps > 16 {
                return Err(DnsError::CompressionLoop);
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(DnsError::InvalidDnsName);
        }
        offset += 1 + usize::from(len);
        if offset > segment_end {
            return Err(if offset > packet.len() {
                DnsError::UnexpectedEof
            } else {
                DnsError::InvalidDnsName
            });
        }
        if len == 0 {
            return Ok(consumed.unwrap_or(offset));
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NameLabels<'a> {
    packet: &'a [u8],
    offset: usize,
    scope_end: usize,
    compressed: bool,
    jumps: usize,
    expanded: usize,
    consumed: Option<usize>,
    done: bool,
}

impl<'a> NameLabels<'a> {
    pub(crate) const fn new(
        packet: &'a [u8],
        offset: usize,
        scope_end: usize,
        compressed: bool,
    ) -> Self {
        Self {
            packet,
            offset,
            scope_end,
            compressed,
            jumps: 0,
            expanded: 1,
            consumed: None,
            done: false,
        }
    }

    fn next_label(&mut self) -> Result<Option<&'a [u8]>, DnsError> {
        loop {
            let len = *self
                .packet
                .get(self.offset)
                .ok_or(DnsError::UnexpectedEof)?;
            if len & 0xc0 == 0xc0 {
                if !self.compressed {
                    return Err(DnsError::InvalidDnsName);
                }
                let second = *self
                    .packet
                    .get(self.offset + 1)
                    .ok_or(DnsError::UnexpectedEof)?;
                if self.offset + 2 > self.scope_end {
                    return Err(DnsError::InvalidDnsName);
                }
                self.consumed.get_or_insert(self.offset + 2);
                self.offset = (usize::from(len & 0x3f) << 8) | usize::from(second);
                self.scope_end = self.packet.len();
                self.jumps += 1;
                if self.jumps > 16 {
                    return Err(DnsError::CompressionLoop);
                }
                continue;
            }
            if len & 0xc0 != 0 {
                return Err(DnsError::InvalidDnsName);
            }
            self.offset += 1;
            let end = self.offset + usize::from(len);
            if end > self.packet.len() {
                return Err(DnsError::UnexpectedEof);
            }
            if end > self.scope_end {
                return Err(DnsError::InvalidDnsName);
            }
            if len == 0 {
                self.consumed.get_or_insert(end);
                return Ok(None);
            }
            self.expanded += 1 + usize::from(len);
            if self.expanded > 255 {
                return Err(DnsError::InvalidDnsName);
            }
            let label = &self.packet[self.offset..end];
            self.offset = end;
            return Ok(Some(label));
        }
    }
}

impl<'a> Iterator for NameLabels<'a> {
    type Item = Result<&'a [u8], DnsError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.next_label() {
            Ok(Some(label)) => Some(Ok(label)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

/// Presentation-format names use decimal escapes inside labels, keeping dots
/// and arbitrary octets distinct from label separators and cache-key delimiters.
pub(crate) fn literal_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e) && !matches!(byte, b'.' | b'\\' | b'|')
}

pub(crate) fn append_label(out: &mut String, label: &[u8]) {
    for &byte in label {
        let byte = byte.to_ascii_lowercase();
        if literal_byte(byte) {
            out.push(char::from(byte));
        } else {
            out.push('\\');
            out.push(char::from(b'0' + byte / 100));
            out.push(char::from(b'0' + byte / 10 % 10));
            out.push(char::from(b'0' + byte % 10));
        }
    }
}

/// Encode a presentation name. Escaped octets belong to the current label.
/// The destination is unchanged on invalid input.
pub fn encode_dns_name_into(out: &mut Vec<u8>, name: &str) -> Result<(), DnsError> {
    let input = name.as_bytes();
    let mut wire = [0_u8; 255];
    let mut length = 1;
    let mut label_start = 0;
    let mut index = 0;
    if input.is_empty() || input == b"." {
        out.push(0);
        return Ok(());
    }
    while index < input.len() {
        let mut byte = input[index];
        index += 1;
        if byte == b'.' {
            let label_len = length - label_start - 1;
            if label_len == 0 {
                return Err(DnsError::InvalidDnsName);
            }
            wire[label_start] = label_len as u8;
            if length >= 255 {
                return Err(DnsError::InvalidDnsName);
            }
            label_start = length;
            length += 1;
            if index == input.len() {
                out.extend_from_slice(&wire[..length]);
                return Ok(());
            }
            continue;
        }
        if byte == b'\\' {
            byte = *input.get(index).ok_or(DnsError::InvalidDnsName)?;
            if byte.is_ascii_digit() {
                let digits = input
                    .get(index..index + 3)
                    .ok_or(DnsError::InvalidDnsName)?;
                if !digits.iter().all(u8::is_ascii_digit) {
                    return Err(DnsError::InvalidDnsName);
                }
                let value = u16::from(digits[0] - b'0') * 100
                    + u16::from(digits[1] - b'0') * 10
                    + u16::from(digits[2] - b'0');
                byte = u8::try_from(value).map_err(|_| DnsError::InvalidDnsName)?;
                index += 3;
            } else {
                index += 1;
            }
        }
        if length >= 254 || length - label_start > 63 {
            return Err(DnsError::InvalidDnsName);
        }
        wire[length] = byte;
        length += 1;
    }
    wire[label_start] = (length - label_start - 1) as u8;
    // A root octet follows the final nonempty label.
    out.extend_from_slice(&wire[..length]);
    out.push(0);
    Ok(())
}

pub(crate) fn canonical_wire_name(wire: &[u8]) -> Result<String, DnsError> {
    let mut out = String::new();
    for label in NameLabels::new(wire, 0, wire.len(), false) {
        append_label(&mut out, label?);
        out.push('.');
    }
    if out.is_empty() {
        out.push('.');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsPacketView, build_response_cache_plan_from_packet, parse_message};

    fn name(last: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for n in [63, 63, 63, last] {
            out.push(n as u8);
            out.extend(vec![b'a'; n]);
        }
        out.push(0);
        out
    }
    #[test]
    fn expanded_name_limits_apply_across_compression_and_scopes() {
        for last in [61, 62, 63] {
            let mut wire = name(last);
            let valid = last == 61; // 255 including root and label lengths
            assert_eq!(scan_dns_name(&wire, 0, wire.len(), false).is_ok(), valid);
            let ptr = wire.len();
            wire.extend([0xc0, 0]);
            assert_eq!(scan_dns_name(&wire, ptr, wire.len(), true).is_ok(), valid);
            assert!(scan_dns_name(&wire, ptr, ptr + 1, true).is_err());
            assert!(scan_dns_name(&wire, ptr, wire.len(), false).is_err());
            // An extra label before a pointer must count towards the same budget.
            let extra = wire.len();
            wire.extend([1, b'x', 0xc0, 0]);
            assert!(scan_dns_name(&wire, extra, wire.len(), true).is_err());
        }
        assert_eq!(scan_dns_name(&[0], 0, 1, false).unwrap(), 1);
        assert!(matches!(
            scan_dns_name(&[0xc0, 0], 0, 2, true),
            Err(DnsError::CompressionLoop)
        ));
        assert!(scan_dns_name(&[0xc0, 99], 0, 2, true).is_err());
    }

    #[test]
    fn compressed_wire_bytes_do_not_consume_the_expanded_name_budget() {
        // Replacing the root with a two-byte pointer makes the encoding 256 B,
        // while the expanded name remains exactly 255 B.
        let mut packet = vec![0];
        packet.extend_from_slice(&name(61)[..254]);
        packet.extend([0xc0, 0]);
        assert_eq!(scan_dns_name(&packet, 1, packet.len(), true).unwrap(), 257);
        assert_eq!(NameLabels::new(&packet, 1, packet.len(), true).count(), 4);

        // Each pointer follows a prefix: the budget must survive every jump.
        let suffix = packet.len();
        packet.extend([1, b'b', 0xc0, 0]);
        let prefix = packet.len();
        packet.extend_from_slice(&name(59)[..252]);
        packet.extend([0xc0 | ((suffix >> 8) as u8), suffix as u8]);
        assert!(scan_dns_name(&packet, prefix, packet.len(), true).is_ok());
        let extra = packet.len();
        packet.extend([1, b'x', 0xc0 | ((prefix >> 8) as u8), prefix as u8]);
        assert!(scan_dns_name(&packet, extra, packet.len(), true).is_err());
        assert!(NameLabels::new(&packet, extra, packet.len(), true).any(|label| label.is_err()));
    }
    #[test]
    fn all_question_and_answer_parsers_reject_overlong_names() {
        for last in [61, 62, 63] {
            let valid = last == 61;
            let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            query.extend(name(last));
            query.extend([0, 1, 0, 1]);
            assert_eq!(DnsPacketView::parse(&query).is_ok(), valid);
            assert_eq!(parse_message(&query).is_ok(), valid);
            // Valid short question, compressed answer owner pointing into RDATA.
            let mut response = vec![
                0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'x', 0, 0, 1, 0, 1, 0xc0, 31, 0, 16,
                0, 1, 0, 0, 0, 60,
            ];
            let wire = name(last);
            response.extend((wire.len() as u16).to_be_bytes());
            response.extend(wire);
            let view = DnsPacketView::parse(&response).unwrap();
            assert_eq!(view.answers().next().unwrap().is_ok(), valid);
            assert_eq!(parse_message(&response).is_ok(), valid);
            assert_eq!(
                build_response_cache_plan_from_packet(0, &response, None).is_ok(),
                valid
            );
            // CNAME target uses the same limit, even with a short owner.
            response[20] = 12;
            response[22] = 5;
            assert_eq!(
                DnsPacketView::parse(&response)
                    .unwrap()
                    .answers()
                    .next()
                    .unwrap()
                    .is_ok(),
                valid
            );
        }
    }
}
