use std::sync::Arc;

use dae_resident_core::RESIDENT_UDP_RESPONSE_TIMEOUT;
use dae_resident_transport::{ProxyDnsRequestContext, encode_dns_qname};

use crate::ResidentDnsProxyUdpForwarder;

pub async fn probe_resident_proxy_dns_udp_with_forwarder_async(
    forwarder: Arc<dyn ResidentDnsProxyUdpForwarder>,
    lookup_host: &str,
) -> Result<(), String> {
    let id = fastrand::u16(0..=u16::MAX);
    let query = build_dns_a_query(id, lookup_host)?;
    let response = forwarder
        .exchange(
            &query,
            ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
        )
        .await
        .map_err(|error| error.to_string())?;
    dns_a_response_has_answer(id, &response)
}

fn build_dns_a_query(id: u16, lookup_host: &str) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_qname(&mut query, lookup_host)?;
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn dns_a_response_has_answer(query_id: u16, response: &[u8]) -> Result<(), String> {
    if response.len() < 12 {
        return Err(format!("DNS response too short: {} bytes", response.len()));
    }
    let response_id = u16::from_be_bytes([response[0], response[1]]);
    if response_id != query_id {
        return Err(format!(
            "DNS response id mismatch: got {response_id}, expected {query_id}"
        ));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS response QR bit is not set".to_owned());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("DNS response rcode is {rcode}"));
    }
    let answer_count = u16::from_be_bytes([response[6], response[7]]);
    if answer_count == 0 {
        return Err("DNS response has no answers".to_owned());
    }
    Ok(())
}
