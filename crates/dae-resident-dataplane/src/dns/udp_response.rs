use super::{DNS_MAX_UDP_MESSAGE_SIZE, DnsPacketView};

const DNS_HEADER_LEN: usize = 12;
const DNS_CLASSIC_UDP_PAYLOAD_SIZE: usize = 512;
// Keep UDP DNS replies below the IPv6 minimum-MTU payload budget so transparent
// replies do not depend on IP fragmentation even when a client advertises 4096.
const DNS_SAFE_UDP_PAYLOAD_SIZE: usize = 1_232;
const DNS_TYPE_OPT: u16 = 41;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_TRUNCATED: u16 = 0x0200;

pub(crate) fn fit_dns_response_to_udp_request(
    request: &[u8],
    response: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let payload_limit = request_udp_payload_limit(request)?;
    if response.len() <= payload_limit {
        return Ok(response);
    }

    build_truncated_udp_response(request, &response, payload_limit)
}

fn request_udp_payload_limit(request: &[u8]) -> Result<usize, String> {
    let view = DnsPacketView::parse(request)
        .map_err(|error| format!("parse DNS UDP request payload limit: {error}"))?;
    let answer_count = read_u16(request, 6)? as usize;
    let authority_count = read_u16(request, 8)? as usize;
    let additional_count = read_u16(request, 10)? as usize;
    let mut offset = view.answer_offset();

    for _ in 0..answer_count.saturating_add(authority_count) {
        offset = skip_resource_record(request, offset)?.2;
    }

    let mut advertised = None;
    for _ in 0..additional_count {
        let (record_type, record_class, next) = skip_resource_record(request, offset)?;
        offset = next;
        if record_type != DNS_TYPE_OPT {
            continue;
        }
        if advertised.replace(record_class as usize).is_some() {
            return Err("DNS UDP request contains more than one OPT record".to_owned());
        }
    }
    if offset != request.len() {
        return Err("DNS UDP request has trailing bytes after its declared sections".to_owned());
    }

    Ok(advertised.unwrap_or(DNS_CLASSIC_UDP_PAYLOAD_SIZE).clamp(
        DNS_CLASSIC_UDP_PAYLOAD_SIZE,
        DNS_SAFE_UDP_PAYLOAD_SIZE.min(DNS_MAX_UDP_MESSAGE_SIZE),
    ))
}

fn build_truncated_udp_response(
    request: &[u8],
    response: &[u8],
    payload_limit: usize,
) -> Result<Vec<u8>, String> {
    if response.len() < DNS_HEADER_LEN {
        return Err("DNS UDP response is shorter than its header".to_owned());
    }
    let request_view = DnsPacketView::parse(request)
        .map_err(|error| format!("parse DNS UDP request for truncation: {error}"))?;
    let question_end = request_view.answer_offset();
    let preserve_question = question_end <= payload_limit;
    let mut truncated = Vec::with_capacity(if preserve_question {
        question_end
    } else {
        DNS_HEADER_LEN
    });
    truncated.extend_from_slice(&response[..DNS_HEADER_LEN]);
    truncated[..2].copy_from_slice(&request[..2]);
    let flags = read_u16(&truncated, 2)? | DNS_FLAG_RESPONSE | DNS_FLAG_TRUNCATED;
    truncated[2..4].copy_from_slice(&flags.to_be_bytes());
    if preserve_question {
        truncated[4..6].copy_from_slice(&request[4..6]);
        truncated.extend_from_slice(&request[DNS_HEADER_LEN..question_end]);
    } else {
        truncated[4..6].copy_from_slice(&0_u16.to_be_bytes());
    }
    truncated[6..12].fill(0);
    Ok(truncated)
}

fn skip_resource_record(packet: &[u8], offset: usize) -> Result<(u16, u16, usize), String> {
    let fixed = skip_wire_name(packet, offset)?;
    if fixed.saturating_add(10) > packet.len() {
        return Err("DNS resource record header is truncated".to_owned());
    }
    let record_type = read_u16(packet, fixed)?;
    let record_class = read_u16(packet, fixed + 2)?;
    let data_len = read_u16(packet, fixed + 8)? as usize;
    let next = fixed
        .checked_add(10)
        .and_then(|offset| offset.checked_add(data_len))
        .ok_or_else(|| "DNS resource record length overflow".to_owned())?;
    if next > packet.len() {
        return Err("DNS resource record payload is truncated".to_owned());
    }
    Ok((record_type, record_class, next))
}

fn skip_wire_name(packet: &[u8], mut offset: usize) -> Result<usize, String> {
    loop {
        let length = *packet
            .get(offset)
            .ok_or_else(|| "DNS resource record name is truncated".to_owned())?;
        if length & 0xc0 == 0xc0 {
            if packet.get(offset + 1).is_none() {
                return Err("DNS compressed name pointer is truncated".to_owned());
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 {
            return Err("DNS resource record name has an invalid label type".to_owned());
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(length as usize)
            .ok_or_else(|| "DNS resource record name length overflow".to_owned())?;
        if offset > packet.len() {
            return Err("DNS resource record label is truncated".to_owned());
        }
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or_else(|| "DNS packet field is truncated".to_owned())?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn classic_udp_oversize_response_becomes_explicitly_truncated() {
        let response = padded_response(QUERY, 700, 0x8180, 7);
        let truncated = fit_dns_response_to_udp_request(QUERY, response).unwrap();

        assert!(truncated.len() <= DNS_CLASSIC_UDP_PAYLOAD_SIZE);
        assert_eq!(&truncated[..2], &QUERY[..2]);
        assert_ne!(read_u16(&truncated, 2).unwrap() & DNS_FLAG_TRUNCATED, 0);
        assert_eq!(read_u16(&truncated, 4).unwrap(), 1);
        assert_eq!(read_u16(&truncated, 6).unwrap(), 0);
        assert_eq!(read_u16(&truncated, 8).unwrap(), 0);
        assert_eq!(read_u16(&truncated, 10).unwrap(), 0);
        assert_eq!(&truncated[DNS_HEADER_LEN..], &QUERY[DNS_HEADER_LEN..]);
    }

    #[test]
    fn response_within_classic_udp_limit_is_unchanged() {
        let response = padded_response(QUERY, 480, 0x8180, 1);
        assert_eq!(
            fit_dns_response_to_udp_request(QUERY, response.clone()).unwrap(),
            response
        );
    }

    #[test]
    fn edns_payload_limit_controls_truncation() {
        let query_1232 = edns_query(1_232);
        let response_1000 = padded_response(&query_1232, 1_000, 0x8180, 8);
        assert_eq!(
            fit_dns_response_to_udp_request(&query_1232, response_1000.clone()).unwrap(),
            response_1000
        );

        let response_1500 = padded_response(&query_1232, 1_500, 0x8183, 8);
        let truncated = fit_dns_response_to_udp_request(&query_1232, response_1500).unwrap();
        assert!(truncated.len() <= 1_232);
        assert_ne!(read_u16(&truncated, 2).unwrap() & DNS_FLAG_TRUNCATED, 0);
        assert_eq!(read_u16(&truncated, 2).unwrap() & 0x000f, 3);

        let query_4096 = edns_query(4_096);
        let response_1000 = padded_response(&query_4096, 1_000, 0x8180, 8);
        assert_eq!(
            fit_dns_response_to_udp_request(&query_4096, response_1000.clone()).unwrap(),
            response_1000
        );

        let response_1500 = padded_response(&query_4096, 1_500, 0x8180, 8);
        let truncated = fit_dns_response_to_udp_request(&query_4096, response_1500).unwrap();
        assert!(truncated.len() <= DNS_SAFE_UDP_PAYLOAD_SIZE);
        assert_ne!(read_u16(&truncated, 2).unwrap() & DNS_FLAG_TRUNCATED, 0);
    }

    #[test]
    fn malformed_or_duplicate_opt_records_are_rejected() {
        let mut duplicate = edns_query(1_232);
        duplicate[10..12].copy_from_slice(&2_u16.to_be_bytes());
        duplicate.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert!(
            request_udp_payload_limit(&duplicate)
                .unwrap_err()
                .contains("more than one OPT")
        );

        let mut malformed = edns_query(1_232);
        malformed.pop();
        assert!(request_udp_payload_limit(&malformed).is_err());
    }

    fn edns_query(payload_size: u16) -> Vec<u8> {
        let mut query = QUERY.to_vec();
        query[10..12].copy_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[0, 0, 41]);
        query.extend_from_slice(&payload_size.to_be_bytes());
        query.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        query
    }

    fn padded_response(query: &[u8], len: usize, flags: u16, answers: u16) -> Vec<u8> {
        let view = DnsPacketView::parse(query).unwrap();
        let mut response = vec![0_u8; len.max(view.answer_offset())];
        response[..2].copy_from_slice(&query[..2]);
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[4..6].copy_from_slice(&query[4..6]);
        response[6..8].copy_from_slice(&answers.to_be_bytes());
        response[DNS_HEADER_LEN..view.answer_offset()]
            .copy_from_slice(&query[DNS_HEADER_LEN..view.answer_offset()]);
        response
    }
}
