use crate::DnsError;

/// Scan an encoded name, bounding its expanded wire representation (RFC 1035).
/// `scope_end` bounds bytes consumed at the original location, not pointer targets.
pub fn scan_dns_name(
    packet: &[u8],
    offset: usize,
    scope_end: usize,
    compressed: bool,
) -> Result<usize, DnsError> {
    let mut labels = NameLabels::new(packet, offset, scope_end, compressed);
    for label in labels.by_ref() {
        label?;
    }
    Ok(labels.consumed.expect("a completed name has an end"))
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
