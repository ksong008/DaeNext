use std::net::IpAddr;

use crate::cache::{DnsCacheEntry, DnsCacheStore, effective_deadline_from_ttl};
use crate::cache_key::DnsCacheKey;
use crate::error::DnsError;
use crate::message::{DnsPacketView, DnsQuestion};

#[cfg(test)]
const DNS_HEADER_LEN: usize = 12;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_RCODE_MASK: u16 = 0x000f;
const DNS_RCODE_SUCCESS: u16 = 0;
const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsPacketCacheHit {
    pub request_id: u16,
    pub response_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResponseCachePlan {
    pub key: DnsCacheKey,
    pub entry: DnsCacheEntry,
    pub min_ttl: u32,
    pub answer_count: usize,
    pub ip_count: usize,
    pub client_ttl_zeroed: bool,
}

pub fn restore_cached_response_for_packet_question(
    store: &mut DnsCacheStore,
    now_unix: i64,
    request_packet: &[u8],
    ignore_fixed_ttl: bool,
    out: &mut Vec<u8>,
) -> Result<Option<DnsPacketCacheHit>, DnsError> {
    let request = DnsPacketView::parse(request_packet)?;
    let Some(question) = request.questions().next() else {
        return Ok(None);
    };
    let Some(entry) = store.lookup_packet_question(now_unix, &question, ignore_fixed_ttl)? else {
        return Ok(None);
    };
    entry.fill_packed_response_into(request.id(), out);
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(DnsPacketCacheHit {
        request_id: request.id(),
        response_len: out.len(),
    }))
}

pub fn build_response_cache_plan_from_packet(
    now_unix: i64,
    response_packet: &[u8],
    fixed_domain_ttl: Option<i64>,
) -> Result<Option<DnsResponseCachePlan>, DnsError> {
    let flags = read_u16(response_packet, 2)?;
    if flags & DNS_FLAG_RESPONSE == 0 || flags & DNS_RCODE_MASK != DNS_RCODE_SUCCESS {
        return Ok(None);
    }

    let response = DnsPacketView::parse(response_packet)?;
    let Some(question) = response.questions().next() else {
        return Ok(None);
    };
    if response.answer_count() == 0 {
        return Ok(None);
    }

    let qname = question.qname_to_canonical_string()?;
    let cache_host = qname.trim_end_matches('.');
    if cache_host.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }

    let mut min_ttl = None;
    let mut ips = Vec::new();
    let mut has_any_ip = false;
    let mut answer_count = 0_usize;
    for answer in response.answers() {
        let answer = answer?;
        answer_count += 1;
        min_ttl = Some(min_ttl.map_or(answer.ttl(), |ttl: u32| ttl.min(answer.ttl())));
        if let Some(ip) = answer.ip() {
            has_any_ip = true;
            if !ip.is_unspecified() {
                ips.push(ip);
            }
        }
    }
    let Some(min_ttl) = min_ttl else {
        return Ok(None);
    };

    let client_ttl_zeroed = matches!(question.qtype(), DNS_QTYPE_A | DNS_QTYPE_AAAA);
    let packed_response =
        normalized_packed_response(response_packet, &response, client_ttl_zeroed)?;
    let (deadline_unix, original_deadline_unix) =
        effective_deadline_from_ttl(now_unix, i64::from(min_ttl), fixed_domain_ttl);
    let key = DnsCacheKey::new(&qname, question.qtype(), question.qclass());
    let mut entry = DnsCacheEntry::new(deadline_unix, original_deadline_unix);
    entry.route_owner_key = key.to_string();
    entry.ips = ips;
    entry.has_any_ip = has_any_ip;
    entry.packed_response = packed_response;

    Ok(Some(DnsResponseCachePlan {
        ip_count: entry.ips.len(),
        entry,
        key,
        min_ttl,
        answer_count,
        client_ttl_zeroed,
    }))
}

pub fn cache_plan_question(plan: &DnsResponseCachePlan) -> DnsQuestion {
    DnsQuestion::new(&plan.key.qname, plan.key.qtype, plan.key.qclass)
}

fn normalized_packed_response(
    packet: &[u8],
    view: &DnsPacketView<'_>,
    zero_answer_ttl: bool,
) -> Result<Vec<u8>, DnsError> {
    let mut out = packet.to_vec();
    if out.len() < 2 {
        return Err(DnsError::PacketTooShort);
    }
    out[0] = 0;
    out[1] = 0;
    if zero_answer_ttl {
        zero_answer_ttls(&mut out, view.answer_offset(), view.answer_count())?;
    }
    Ok(out)
}

fn zero_answer_ttls(
    packet: &mut [u8],
    mut offset: usize,
    answer_count: usize,
) -> Result<(), DnsError> {
    for _ in 0..answer_count {
        let name_end = scan_name(packet, offset, 0)?;
        let ttl_offset = name_end + 4;
        let rdlen_offset = name_end + 8;
        if rdlen_offset + 2 > packet.len() || ttl_offset + 4 > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
        packet[ttl_offset..ttl_offset + 4].copy_from_slice(&0_u32.to_be_bytes());
        let rdlen = read_u16(packet, rdlen_offset)? as usize;
        offset = name_end + 10 + rdlen;
        if offset > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
    }
    Ok(())
}

fn scan_name(packet: &[u8], mut offset: usize, depth: usize) -> Result<usize, DnsError> {
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
            let ptr = (((len & 0x3f) as usize) << 8) | packet[offset + 1] as usize;
            scan_name(packet, ptr, depth + 1)?;
            return Ok(offset + 2);
        }
        if len & 0xc0 != 0 || len > 63 {
            return Err(DnsError::InvalidDnsName);
        }
        offset += 1;
        if len == 0 {
            return Ok(offset);
        }
        offset += len as usize;
        if offset > packet.len() {
            return Err(DnsError::UnexpectedEof);
        }
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    if offset + 2 > packet.len() {
        return Err(DnsError::UnexpectedEof);
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsPacketAnswerView, DnsPacketView};
    use std::net::IpAddr;

    const NOW: i64 = 1_700_000_000;
    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    const RESPONSE: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c, 0xc0, 0x0c,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xcb, 0x00, 0x71, 0x14,
    ];

    #[test]
    fn response_cache_plan_preserves_go_dns_normalization_contract() {
        let plan = build_response_cache_plan_from_packet(NOW, RESPONSE, Some(0))
            .unwrap()
            .expect("cache plan");
        assert_eq!(plan.key, DnsCacheKey::new("example.com.", 1, 1));
        assert_eq!(plan.entry.route_owner_key, "example.com.|1|1");
        assert_eq!(plan.min_ttl, 60);
        assert_eq!(plan.entry.deadline_unix, NOW);
        assert_eq!(plan.entry.original_deadline_unix, NOW + 60);
        assert_eq!(plan.answer_count, 2);
        assert_eq!(plan.ip_count, 1);
        assert!(plan.entry.has_any_ip);
        assert_eq!(
            plan.entry.ips,
            vec!["203.0.113.20".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(&plan.entry.packed_response[0..2], &[0, 0]);

        let packet = DnsPacketView::parse(&plan.entry.packed_response).unwrap();
        let answers = packet.answers().collect::<Result<Vec<_>, _>>().unwrap();
        assert!(answers.iter().all(|answer| answer.ttl() == 0));
        assert!(matches!(answers[0], DnsPacketAnswerView::Cname { .. }));
        assert!(matches!(answers[1], DnsPacketAnswerView::A { .. }));
    }

    #[test]
    fn request_cache_hot_path_restores_packed_response_id_from_packet() {
        let plan = build_response_cache_plan_from_packet(NOW, RESPONSE, None)
            .unwrap()
            .expect("cache plan");
        let mut store = DnsCacheStore::new(8);
        store.insert_without_route_owner_key(NOW, plan.key, plan.entry);

        let mut restored = Vec::new();
        let hit = restore_cached_response_for_packet_question(
            &mut store,
            NOW,
            QUERY,
            false,
            &mut restored,
        )
        .unwrap()
        .expect("cache hit");
        assert_eq!(hit.request_id, 0x1234);
        assert_eq!(hit.response_len, restored.len());
        assert_eq!(&restored[0..2], &[0x12, 0x34]);
        assert_eq!(store.stats().hit_total, 1);
    }

    #[test]
    fn response_cache_plan_skips_non_success_and_empty_answer_packets() {
        let mut request = QUERY.to_vec();
        request[2] = 0x01;
        request[3] = 0x00;
        assert!(
            build_response_cache_plan_from_packet(NOW, &request, None)
                .unwrap()
                .is_none()
        );

        let mut nxdomain = RESPONSE.to_vec();
        nxdomain[3] = 0x83;
        assert!(
            build_response_cache_plan_from_packet(NOW, &nxdomain, None)
                .unwrap()
                .is_none()
        );

        let mut empty = RESPONSE.to_vec();
        empty[6] = 0;
        empty[7] = 0;
        empty.truncate(DNS_HEADER_LEN + QUERY.len() - DNS_HEADER_LEN);
        assert!(
            build_response_cache_plan_from_packet(NOW, &empty, None)
                .unwrap()
                .is_none()
        );
    }
}
