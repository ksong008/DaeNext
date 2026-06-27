use dae_dns::{
    DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_RESPONSE,
    DNS_FLAG_TRUNCATED, DNS_HEADER_LEN, DNS_RCODE_MASK, DNS_RCODE_NOERROR, DNS_RCODE_SERVFAIL,
    DnsPacketView,
};

pub(super) fn build_reject_response(
    request: &[u8],
    view: &DnsPacketView<'_>,
) -> Result<Vec<u8>, String> {
    build_empty_dns_response(request, view, DNS_RCODE_NOERROR, false)
}

pub(in crate::production_runtime_owner::resident_dataplane) fn build_dns_server_failure_response(
    request: &[u8],
) -> Result<Vec<u8>, String> {
    let view = DnsPacketView::parse(request)
        .map_err(|err| format!("parse DNS request for SERVFAIL: {err}"))?;
    ensure_dns_request(&view)?;
    build_empty_dns_response(request, &view, DNS_RCODE_SERVFAIL, false)
}

#[cfg(test)]
fn build_dns_truncated_response(request: &[u8]) -> Result<Vec<u8>, String> {
    let view =
        DnsPacketView::parse(request).map_err(|err| format!("parse DNS request for TC: {err}"))?;
    ensure_dns_request(&view)?;
    build_empty_dns_response(request, &view, DNS_RCODE_NOERROR, true)
}

fn ensure_dns_request(view: &DnsPacketView<'_>) -> Result<(), String> {
    if view.response() {
        return Err("DNS request expected but DNS response received".to_owned());
    }
    if view.question_count() == 0 {
        return Err("DNS request has no question".to_owned());
    }
    Ok(())
}

fn build_empty_dns_response(
    request: &[u8],
    view: &DnsPacketView<'_>,
    rcode: u16,
    truncated: bool,
) -> Result<Vec<u8>, String> {
    if request.len() < view.answer_offset() {
        return Err("DNS request question section is truncated".to_owned());
    }
    if request.len() < DNS_HEADER_LEN {
        return Err("DNS request header is truncated".to_owned());
    }
    let request_flags = u16::from_be_bytes([request[2], request[3]]);
    let mut response_flags = DNS_FLAG_RESPONSE
        | DNS_FLAG_RECURSION_AVAILABLE
        | (request_flags & DNS_FLAG_RECURSION_DESIRED)
        | (rcode & DNS_RCODE_MASK);
    if truncated {
        response_flags |= DNS_FLAG_TRUNCATED;
    }

    let mut response = Vec::with_capacity(view.answer_offset());
    response.extend_from_slice(&request[0..2]);
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&(view.question_count() as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[DNS_HEADER_LEN..view.answer_offset()]);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn servfail_response_preserves_question_and_request_id() {
        let response = build_dns_server_failure_response(QUERY).unwrap();

        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & DNS_RCODE_MASK,
            DNS_RCODE_SERVFAIL
        );
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(&response[DNS_HEADER_LEN..], &QUERY[DNS_HEADER_LEN..]);
    }

    #[test]
    fn truncated_response_sets_tc_without_answers() {
        let response = build_dns_truncated_response(QUERY).unwrap();
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_ne!(flags & DNS_FLAG_TRUNCATED, 0);
        assert_eq!(flags & DNS_RCODE_MASK, DNS_RCODE_NOERROR);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn servfail_rejects_response_payload() {
        let mut response = QUERY.to_vec();
        response[2] |= (DNS_FLAG_RESPONSE >> 8) as u8;

        assert!(build_dns_server_failure_response(&response).is_err());
    }
}
