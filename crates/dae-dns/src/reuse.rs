use crate::{DnsError, DnsPacketView, validate_dns_packet_response_for_request_fast};

/// Semantics that must agree before a DNS wire response can be reused.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DnsRequestReuse {
    flags: u16,
    edns: Option<(u16, u8, u16)>,
}

impl Default for DnsRequestReuse {
    fn default() -> Self {
        Self {
            flags: 0x0100,
            edns: None,
        }
    }
}

impl DnsRequestReuse {
    /// Unknown options and request layouts are forwarded without reuse.
    pub fn from_request(request: &DnsPacketView<'_>) -> Option<Self> {
        let packet = request.packet();
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if request.question_count() != 1 || flags & !0x0130 != 0 || packet[6..10] != [0; 4] {
            return None;
        }
        let additional = u16::from_be_bytes([packet[10], packet[11]]);
        let offset = request.answer_offset();
        let edns = match additional {
            0 if offset == packet.len() => None,
            1 if packet.len() == offset + 11 => {
                let rr = &packet[offset..];
                // Root owner, OPT, no extended request rcode, reserved flags or options.
                if rr[..3] != [0, 0, 41] || rr[5] != 0 || rr[9..11] != [0, 0] {
                    return None;
                }
                let edns_flags = u16::from_be_bytes([rr[7], rr[8]]);
                if edns_flags & !0x8000 != 0 {
                    return None;
                }
                Some((u16::from_be_bytes([rr[3], rr[4]]), rr[6], edns_flags))
            }
            _ => return None,
        };
        Some(Self { flags, edns })
    }
}

/// Restore request-specific bytes without changing offsets used by compression.
pub fn restore_dns_response_for_request(
    request: &DnsPacketView<'_>,
    response: &mut [u8],
) -> Result<(), DnsError> {
    let view = DnsPacketView::parse(response)?;
    validate_dns_packet_response_for_request_fast(request, Some(&view), false)
        .map_err(|_| DnsError::InvalidDnsName)?;
    if request.answer_offset() != view.answer_offset() {
        return Err(DnsError::InvalidDnsName);
    }
    let end = request.answer_offset();
    response[12..end].copy_from_slice(&request.packet()[12..end]);
    response[..2].copy_from_slice(&request.id().to_be_bytes());
    let flags = (u16::from_be_bytes([response[2], response[3]]) & !0x0110)
        | (u16::from_be_bytes([request.packet()[2], request.packet()[3]]) & 0x0110);
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(flags: u16, edns: Option<(u16, u8, u16)>) -> Vec<u8> {
        let mut q = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'x', 0, 0, 1, 0, 1];
        q[2..4].copy_from_slice(&flags.to_be_bytes());
        if let Some((size, version, flags)) = edns {
            q[11] = 1;
            q.extend([0, 0, 41]);
            q.extend(size.to_be_bytes());
            q.extend([0, version]);
            q.extend(flags.to_be_bytes());
            q.extend([0, 0]);
        }
        q
    }
    #[test]
    fn request_reuse_separates_flags_edns_versions_and_udp_sizes() {
        let mut contexts = std::collections::BTreeSet::new();
        for flags in [0, 0x0100, 0x0110, 0x0120, 0x0130] {
            for edns in [
                None,
                Some((512, 0, 0)),
                Some((1232, 0, 0)),
                Some((1232, 0, 0x8000)),
                Some((1232, 1, 0)),
            ] {
                let q = query(flags, edns);
                assert!(contexts.insert(
                    DnsRequestReuse::from_request(&DnsPacketView::parse(&q).unwrap()).unwrap()
                ));
            }
        }
        for flags in [0x8000, 0x0800, 0x0200, 0x0040, 1] {
            let q = query(flags, None);
            assert!(DnsRequestReuse::from_request(&DnsPacketView::parse(&q).unwrap()).is_none());
        }
        // ECS, COOKIE and unknown options all bypass reuse.
        for code in [8u16, 10, 65000] {
            let mut q = query(0x0100, Some((1232, 0, 0)));
            let end = q.len();
            q[end - 1] = 4;
            q.extend(code.to_be_bytes());
            q.extend([0, 0]);
            assert!(DnsRequestReuse::from_request(&DnsPacketView::parse(&q).unwrap()).is_none());
        }
    }
    #[test]
    fn reused_response_restores_case_id_and_flags_without_moving_answers() {
        let mut q = query(0x0110, None);
        q[13] = b'X';
        let mut response = query(0x0100, None);
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1;
        response.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 1]);
        let answer = response[19..].to_vec();
        restore_dns_response_for_request(&DnsPacketView::parse(&q).unwrap(), &mut response)
            .unwrap();
        assert_eq!(&response[12..19], &q[12..19]);
        assert_eq!(&response[19..], answer);
        assert_eq!(response[3] & 0x10, 0x10);
        assert_eq!(response[13], b'X');
        assert_eq!(
            DnsPacketView::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .unwrap()
                .name()
                .to_canonical_string()
                .unwrap(),
            "x."
        );
    }
}
