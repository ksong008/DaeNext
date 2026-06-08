use super::*;
pub(crate) fn probe_resident_proxy_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> serde_json::Value {
    let started = Instant::now();
    let handler = resident_udp_handler_name(&proxy.handler);
    match exchange_proxy_udp(proxy, original_dst, payload) {
        Ok(response) => {
            let payload_match = response.payload == payload;
            let mut report = json!({
                "status": if payload_match { "pass" } else { "fail" },
                "ok": payload_match,
                "protocol_closed": false,
                "handler": handler,
                "request_len": payload.len(),
                "response_len": response.payload.len(),
                "payload_match": payload_match,
                "elapsed_ms": started.elapsed().as_millis(),
                "graphId": proxy.graph_id,
                "packetSession": udp_packet_session_value(proxy, "probe", &original_dst.to_string(), handler),
            });
            response.append_execution_fields(&mut report, handler, &proxy.graph_id);
            if let Some(tls_underlay) = response.tls_underlay {
                report["tls_underlay"] = json!(tls_underlay);
            }
            if let Some(quic_underlay) = response.quic_underlay {
                report["quic_underlay"] = json!(quic_underlay);
            }
            report
        }
        Err(err)
            if matches!(
                proxy.handler,
                ResidentProxyProtocolPlan::HttpProxyTcp { .. }
            ) =>
        {
            json!({
                "status": "protocol-closed",
                "ok": true,
                "protocol_closed": true,
                "handler": handler,
                "request_len": payload.len(),
                "response_len": 0,
                "payload_match": false,
                "elapsed_ms": started.elapsed().as_millis(),
                "error": err,
                "graphId": proxy.graph_id,
                "packetSession": udp_packet_session_value(proxy, "probe", &original_dst.to_string(), handler),
            })
        }
        Err(err) => json!({
            "status": "fail",
            "ok": false,
            "protocol_closed": false,
            "handler": handler,
            "request_len": payload.len(),
            "response_len": 0,
            "payload_match": false,
            "elapsed_ms": started.elapsed().as_millis(),
            "graphId": proxy.graph_id,
            "packetSession": udp_packet_session_value(proxy, "probe", &original_dst.to_string(), handler),
            "error": err,
        }),
    }
}

pub(crate) fn probe_resident_proxy_dns_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    lookup_host: &str,
) -> Result<(), String> {
    let id = fastrand::u16(0..=u16::MAX);
    let query = build_dns_a_query(id, lookup_host)?;
    let response = exchange_proxy_udp(proxy, original_dst, &query)?;
    dns_a_response_has_answer(id, &response.payload)
}

pub(crate) fn build_dns_a_query(id: u16, lookup_host: &str) -> Result<Vec<u8>, String> {
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

pub(crate) fn encode_dns_qname(out: &mut Vec<u8>, lookup_host: &str) -> Result<(), String> {
    let lookup_host = lookup_host.trim_end_matches('.');
    if lookup_host.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in lookup_host.split('.') {
        if label.is_empty() {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: empty label"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: label exceeds 63 bytes"
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

pub(crate) fn dns_a_response_has_answer(query_id: u16, response: &[u8]) -> Result<(), String> {
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
        return Err("DNS response is not a response packet".to_owned());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("DNS response rcode={rcode}"));
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Err("DNS response has no answer records".to_owned());
    }
    let mut offset = 12_usize;
    for _ in 0..qdcount {
        skip_dns_name(response, &mut offset)?;
        if response.len().saturating_sub(offset) < 4 {
            return Err("DNS response question section truncated".to_owned());
        }
        offset += 4;
    }
    for _ in 0..ancount {
        skip_dns_name(response, &mut offset)?;
        if response.len().saturating_sub(offset) < 10 {
            return Err("DNS response answer section truncated".to_owned());
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if response.len().saturating_sub(offset) < rdlen {
            return Err("DNS response answer data truncated".to_owned());
        }
        if record_type == 1 && class == 1 && rdlen == 4 {
            return Ok(());
        }
        offset += rdlen;
    }
    Err("DNS response has no A answer records".to_owned())
}

pub(crate) fn skip_dns_name(packet: &[u8], offset: &mut usize) -> Result<(), String> {
    let mut jumps = 0_usize;
    loop {
        if *offset >= packet.len() {
            return Err("DNS name truncated".to_owned());
        }
        let len = packet[*offset];
        if len & 0xc0 == 0xc0 {
            if packet.len().saturating_sub(*offset) < 2 {
                return Err("DNS compressed name pointer truncated".to_owned());
            }
            *offset += 2;
            return Ok(());
        }
        if len & 0xc0 != 0 {
            return Err(format!("unsupported DNS name label marker: 0x{len:02x}"));
        }
        *offset += 1;
        if len == 0 {
            return Ok(());
        }
        let len = len as usize;
        if packet.len().saturating_sub(*offset) < len {
            return Err("DNS name label truncated".to_owned());
        }
        *offset += len;
        jumps += 1;
        if jumps > 128 {
            return Err("DNS name too deep".to_owned());
        }
    }
}
