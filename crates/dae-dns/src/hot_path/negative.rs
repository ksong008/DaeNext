use super::*;

pub(super) fn section_cache_metadata(
    response: &DnsPacketView<'_>,
    terminal: &str,
) -> Result<(Option<u32>, bool), DnsError> {
    let packet = response.packet();
    let counts = [
        response.answer_count(),
        usize::from(read_u16(packet, 8)?),
        usize::from(read_u16(packet, 10)?),
    ];
    let qclass = response
        .questions()
        .next()
        .ok_or(DnsError::InvalidDnsName)?
        .qclass();
    let mut offset = response.answer_offset();
    let mut negative_ttl: Option<u32> = None;
    let mut extended_error = false;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let owner_offset = offset;
            let fixed = crate::scan_dns_name(packet, offset, packet.len(), true)?;
            let kind = read_u16(packet, fixed)?;
            let class = read_u16(packet, fixed + 2)?;
            let ttl = read_u32(packet, fixed + 4)?;
            let start = fixed + 10;
            let end = start + usize::from(read_u16(packet, fixed + 8)?);
            if end > packet.len() {
                return Err(DnsError::UnexpectedEof);
            }
            if section == 2 && kind == 41 && ttl >> 24 != 0 {
                extended_error = true;
            }
            if section == 1 && kind == 6 && class == qclass {
                let mut owner = String::new();
                for label in crate::name::NameLabels::new(packet, owner_offset, packet.len(), true)
                {
                    crate::name::append_label(&mut owner, label?);
                    owner.push('.');
                }
                if owner.is_empty() {
                    owner.push('.');
                }
                let in_zone = owner == "."
                    || terminal == owner
                    || terminal
                        .strip_suffix(&owner)
                        .is_some_and(|prefix| prefix.ends_with('.'));
                let mname_end = crate::scan_dns_name(packet, start, end, true)?;
                let rname_end = crate::scan_dns_name(packet, mname_end, end, true)?;
                if rname_end + 20 != end {
                    return Err(DnsError::InvalidDnsName);
                }
                if in_zone {
                    let value = ttl.min(read_u32(packet, rname_end + 16)?);
                    negative_ttl = Some(negative_ttl.map_or(value, |old| old.min(value)));
                }
            }
            offset = end;
        }
    }
    if offset != packet.len() {
        return Err(DnsError::InvalidDnsName);
    }
    Ok((negative_ttl, extended_error))
}

pub(super) fn terminal_name(
    response: &DnsPacketView<'_>,
    qname: &str,
) -> Result<Option<String>, DnsError> {
    let mut name = qname.to_owned();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        if !seen.insert(name.clone()) {
            return Ok(None);
        }
        let mut next = None;
        for answer in response.answers() {
            let answer = answer?;
            if let Some(target) = answer.cname_target()
                && answer.name().canonical_eq_ignore_ascii_case(&name)?
            {
                next = Some(target.to_canonical_string()?);
                break;
            }
        }
        match next {
            Some(target) => name = target,
            None => return Ok(Some(name)),
        }
    }
    Ok(None)
}

pub fn cap_dns_response_ttls(packet: &mut [u8], limit: u32) -> Result<(), DnsError> {
    let view = DnsPacketView::parse(packet)?;
    let mut offset = view.answer_offset();
    let count = view.answer_count()
        + usize::from(read_u16(packet, 8)?)
        + usize::from(read_u16(packet, 10)?);
    for _ in 0..count {
        let fixed = crate::scan_dns_name(packet, offset, packet.len(), true)?;
        let kind = read_u16(packet, fixed)?;
        let end = fixed + 10 + usize::from(read_u16(packet, fixed + 8)?);
        if end > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        if kind != 41 {
            let ttl = read_u32(packet, fixed + 4)?.min(limit);
            packet[fixed + 4..fixed + 8].copy_from_slice(&ttl.to_be_bytes());
        }
        offset = end;
    }
    Ok(())
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, DnsError> {
    let raw = packet
        .get(offset..offset + 4)
        .ok_or(DnsError::UnexpectedEof)?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_700_000_000;
    fn negative(rcode: u8, ttl: u32, minimum: u32, cname: bool) -> Vec<u8> {
        let mut packet = vec![
            0,
            1,
            0x81,
            0x80 | rcode,
            0,
            1,
            0,
            u8::from(cname),
            0,
            1,
            0,
            0,
        ];
        packet.extend_from_slice(b"\x07example\x03com\0\0\x01\0\x01");
        if cname {
            packet.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 10, 0, 4, 1, b'y', 0xc0, 12]);
        }
        packet.extend_from_slice(&[0xc0, 12, 0, 6, 0, 1]);
        packet.extend(ttl.to_be_bytes());
        packet.extend([0, 24, 0xc0, 12, 0xc0, 12]);
        for field in [1, 2, 3, 4, minimum] {
            packet.extend(field.to_be_bytes());
        }
        packet
    }
    #[test]
    fn negative_cache_uses_soa_ttl_and_minimum_and_fixed_ttl_only_shortens() {
        for rcode in [0, 3] {
            for (ttl, minimum) in [(60, 120), (120, 60)] {
                for fixed in [None, Some(-1), Some(0), Some(30), Some(60), Some(600)] {
                    let packet = negative(rcode, ttl, minimum, false);
                    let plan = build_response_cache_plan_from_packet(NOW, &packet, fixed).unwrap();
                    if fixed.is_some_and(|v| v <= 0) {
                        assert!(plan.is_none());
                        continue;
                    }
                    let plan = plan.unwrap();
                    assert_eq!(plan.min_ttl, 60);
                    assert_eq!(plan.entry.original_deadline_unix, NOW + 60);
                    assert_eq!(plan.entry.deadline_unix, NOW + fixed.unwrap_or(60).min(60));
                    assert!(plan.entry.ips.is_empty());
                    assert!(!plan.entry.has_any_ip);
                    let (_, extended) = section_cache_metadata(
                        &DnsPacketView::parse(&plan.entry.packed_response).unwrap(),
                        "example.com.",
                    )
                    .unwrap();
                    assert!(!extended);
                    let mut cache = DnsCacheStore::new(8);
                    cache.insert(NOW, plan.key, plan.entry);
                    let mut query = packet[..29].to_vec();
                    query[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
                    query[6..12].fill(0);
                    let mut response = Vec::new();
                    assert!(
                        restore_cached_response_for_packet_question(
                            &mut cache,
                            NOW + 1,
                            &query,
                            false,
                            &mut response
                        )
                        .unwrap()
                        .is_some()
                    );
                    let view = DnsPacketView::parse(&response).unwrap();
                    assert_eq!(
                        section_cache_metadata(&view, "example.com.").unwrap().0,
                        Some(fixed.unwrap_or(60).min(60) as u32 - 1)
                    );
                    assert!(
                        restore_cached_response_for_packet_question(
                            &mut cache,
                            NOW + 60,
                            &query,
                            false,
                            &mut response
                        )
                        .unwrap()
                        .is_none()
                    );
                }
            }
        }
    }
    #[test]
    fn negative_cache_excludes_referrals_failures_truncation_and_missing_or_zero_soa() {
        for rcode in [0, 3] {
            let packet = negative(rcode, 60, 60, false);
            for (ttl, minimum) in [(0, 60), (60, 0)] {
                assert!(
                    build_response_cache_plan_from_packet(
                        NOW,
                        &negative(rcode, ttl, minimum, false),
                        None
                    )
                    .unwrap()
                    .is_none()
                );
            }
            let mut missing = packet[..29].to_vec();
            missing[9] = 0;
            assert!(
                build_response_cache_plan_from_packet(NOW, &missing, None)
                    .unwrap()
                    .is_none()
            );
            let mut tc = packet.clone();
            tc[2] |= 2;
            assert!(
                build_response_cache_plan_from_packet(NOW, &tc, None)
                    .unwrap()
                    .is_none()
            );
            let mut failure = packet.clone();
            failure[3] = 0x82;
            assert!(
                build_response_cache_plan_from_packet(NOW, &failure, None)
                    .unwrap()
                    .is_none()
            );
            let mut referral = packet.clone();
            referral[32] = 2;
            assert!(
                build_response_cache_plan_from_packet(NOW, &referral, None)
                    .unwrap()
                    .is_none()
            );
            let mut extended = packet.clone();
            extended[11] = 1;
            extended.extend([0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);
            assert!(
                build_response_cache_plan_from_packet(NOW, &extended, None)
                    .unwrap()
                    .is_none()
            );
        }
        for rcode in [0, 3] {
            let plan =
                build_response_cache_plan_from_packet(NOW, &negative(rcode, 120, 60, true), None)
                    .unwrap()
                    .unwrap();
            assert_eq!(plan.min_ttl, 10);
            assert!(!plan.entry.has_any_ip);
        }
    }
}
