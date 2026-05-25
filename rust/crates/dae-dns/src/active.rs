use std::net::Ipv4Addr;

use crate::cache::DNS_CACHE_MAX_ENTRIES;
use crate::cache_key::DnsCacheKey;
use crate::error::DnsError;
use crate::message::{DnsPacketQuestionView, DnsQuestion};

pub const ACTIVE_DNS_DEFAULT_TARGET_IP: &str = "8.8.8.8";
pub const ACTIVE_DNS_DEFAULT_TARGET_PORT: u16 = 53;
pub const ACTIVE_DNS_DEFAULT_UPSTREAM_IP: &str = "127.0.0.1";
pub const ACTIVE_DNS_DEFAULT_UPSTREAM_PORT: u16 = 10530;
pub const ACTIVE_DNS_DEFAULT_QNAME: &str = "stage54.example.";
pub const ACTIVE_DNS_QTYPE_A: u16 = 1;
pub const ACTIVE_DNS_QCLASS_IN: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveDnsCacheContract {
    pub qtype: u16,
    pub qclass: u16,
    pub cache_max_entries: usize,
    pub cache_key_includes_qclass: bool,
    pub packed_response_id_rewrite_required: bool,
    pub reload_snapshot_required: bool,
    pub domain_routing_owner_migration_required: bool,
    pub live_cache_restored: bool,
}

pub const fn active_dns_cache_contract() -> ActiveDnsCacheContract {
    ActiveDnsCacheContract {
        qtype: ACTIVE_DNS_QTYPE_A,
        qclass: ACTIVE_DNS_QCLASS_IN,
        cache_max_entries: DNS_CACHE_MAX_ENTRIES,
        cache_key_includes_qclass: true,
        packed_response_id_rewrite_required: true,
        reload_snapshot_required: true,
        domain_routing_owner_migration_required: true,
        live_cache_restored: false,
    }
}

pub fn active_dns_question_matches(question: &DnsQuestion, expected_qname: &str) -> bool {
    let key = DnsCacheKey::new(expected_qname, question.qtype, question.qclass);
    question.qname == key.qname
        && question.qtype == ACTIVE_DNS_QTYPE_A
        && question.qclass == ACTIVE_DNS_QCLASS_IN
}

pub fn active_dns_packet_question_matches(
    question: &DnsPacketQuestionView<'_>,
    expected_qname: &str,
) -> Result<bool, DnsError> {
    if question.qtype() != ACTIVE_DNS_QTYPE_A || question.qclass() != ACTIVE_DNS_QCLASS_IN {
        return Ok(false);
    }
    question.qname_canonical_eq_ignore_ascii_case(expected_qname)
}

pub fn build_active_dns_a_response(
    query: &[u8],
    ip: Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, String> {
    if query.len() < 12 {
        return Err("DNS query too short".to_owned());
    }
    let question_end = dns_question_end(query)?;
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&ACTIVE_DNS_QTYPE_A.to_be_bytes());
    response.extend_from_slice(&ACTIVE_DNS_QCLASS_IN.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&ip.octets());
    Ok(response)
}

fn dns_question_end(packet: &[u8]) -> Result<usize, String> {
    let mut offset = 12;
    loop {
        if offset >= packet.len() {
            return Err("DNS question name exceeded packet".to_owned());
        }
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err(
                "compressed DNS question names are not accepted in active DNS query".to_owned(),
            );
        }
        offset += len;
    }
    if offset + 4 > packet.len() {
        return Err("DNS question missing qtype/qclass".to_owned());
    }
    Ok(offset + 4)
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_DNS_DEFAULT_QNAME, ACTIVE_DNS_DEFAULT_TARGET_PORT, ACTIVE_DNS_QCLASS_IN,
        ACTIVE_DNS_QTYPE_A, active_dns_cache_contract, active_dns_packet_question_matches,
        active_dns_question_matches, build_active_dns_a_response,
    };
    use crate::{DnsPacketView, DnsQuestion, validate_dns_packet_response_for_request};
    use std::net::Ipv4Addr;

    #[test]
    fn active_dns_cache_contract_preserves_udp53_and_cache_semantics() {
        let contract = active_dns_cache_contract();
        assert_eq!(ACTIVE_DNS_DEFAULT_TARGET_PORT, 53);
        assert_eq!(contract.qtype, ACTIVE_DNS_QTYPE_A);
        assert_eq!(contract.qclass, ACTIVE_DNS_QCLASS_IN);
        assert!(contract.cache_key_includes_qclass);
        assert!(contract.packed_response_id_rewrite_required);
        assert!(contract.reload_snapshot_required);
        assert!(contract.domain_routing_owner_migration_required);
        assert!(!contract.live_cache_restored);
    }

    #[test]
    fn active_dns_question_match_includes_qclass() {
        let question = DnsQuestion {
            qname: ACTIVE_DNS_DEFAULT_QNAME.to_owned(),
            qtype: ACTIVE_DNS_QTYPE_A,
            qclass: ACTIVE_DNS_QCLASS_IN,
        };
        assert!(active_dns_question_matches(
            &question,
            ACTIVE_DNS_DEFAULT_QNAME
        ));

        let wrong_class = DnsQuestion {
            qclass: 3,
            ..question
        };
        assert!(!active_dns_question_matches(
            &wrong_class,
            ACTIVE_DNS_DEFAULT_QNAME
        ));
    }

    #[test]
    fn active_dns_a_response_roundtrips_request_id_and_validates() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let request = DnsPacketView::parse(&query).unwrap();
        let question = request.questions().next().unwrap();
        assert!(active_dns_packet_question_matches(&question, "example.com").unwrap());
        assert_eq!(
            question.qname_to_canonical_string().unwrap(),
            "example.com."
        );
        let response =
            build_active_dns_a_response(&query, Ipv4Addr::new(203, 0, 113, 54), 30).unwrap();
        assert_eq!(&response[0..2], &query[0..2]);
        validate_dns_packet_response_for_request(&query, Some(&response), true).unwrap();
    }
}
