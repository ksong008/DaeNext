use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::{
    XHttpH3LoopbackOptions, XHttpH3LoopbackReport, XHttpLifecycleOptions,
    xhttp_h3_packet_up_loopback,
};

use super::{dataplane::*, metadata::*, uuid::normalize_vmess_uuid};

#[derive(Clone, Debug, PartialEq)]
pub struct VMessAeadXHttpH3ExchangeReport {
    pub proxy: String,
    pub target: String,
    pub xhttp_host: String,
    pub xhttp_path: String,
    pub xhttp_request_path: String,
    pub xhttp_mode: String,
    pub xhttp_alpn: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub xhttp_request_body_len: usize,
    pub xhttp_response_body_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub iterations: usize,
    pub total_exchange_count: usize,
    pub elapsed_ns: u128,
    pub ns_per_vmess_xhttp_h3_exchange: f64,
    pub client_selected_alpn: String,
    pub server_selected_alpn: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_disabled: bool,
    pub keepalive_secs: u64,
    pub handshake_idle_timeout_secs: u64,
    pub certificate_der_len: usize,
    pub h3_status: u16,
    pub h3_request_count: usize,
    pub h3_request_path_match_count: usize,
    pub h3_request_body_match_count: usize,
    pub h3_response_count: usize,
    pub h3_request_response_validated: bool,
    pub quic_handshake_validated: bool,
    pub xhttp_h3_packet_up_validated: bool,
    pub full_h3_tls_lifecycle: bool,
    pub reality_rejected_for_vmess: bool,
    pub utls_deferred: bool,
    pub download_settings_deferred: bool,
    pub stream_modes_deferred: bool,
    pub true_dataplane: bool,
}

pub fn aead_tcp_exchange_over_xhttp_h3_loopback(
    proxy: &str,
    uuid: &str,
    target: &str,
    xhttp_options: &XHttpLifecycleOptions,
    payload: &[u8],
    iterations: usize,
    timeout: Duration,
) -> Result<VMessAeadXHttpH3ExchangeReport, OutboundError> {
    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let response_payload = aead_tcp_response_packet(&packet.request, payload)?;
    let loopback = XHttpH3LoopbackOptions::new(
        xhttp_options.clone(),
        request_payload.clone(),
        response_payload,
        iterations,
        timeout,
    )?;
    let report = xhttp_h3_packet_up_loopback(&loopback)?;
    let mut response_cursor = std::io::Cursor::new(&report.echoed_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != report.echoed_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess xHTTP H3 response has trailing bytes: {}",
            report.echoed_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess xHTTP H3 payload response mismatch".to_owned(),
        ));
    }

    Ok(vmess_xhttp_h3_report(
        proxy,
        target,
        uuid,
        packet,
        response_header_len,
        response_chunk_len,
        payload,
        echoed_payload,
        report,
    ))
}

// Report assembly keeps xHTTP/H3 evidence fields explicit.
#[allow(clippy::too_many_arguments)]
fn vmess_xhttp_h3_report(
    proxy: &str,
    target: &str,
    uuid: &str,
    packet: VMessAeadRequestPacket,
    response_header_len: usize,
    response_chunk_len: usize,
    payload: &[u8],
    echoed_payload: Vec<u8>,
    report: XHttpH3LoopbackReport,
) -> VMessAeadXHttpH3ExchangeReport {
    VMessAeadXHttpH3ExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        xhttp_host: report.xhttp_host,
        xhttp_path: report.xhttp_path,
        xhttp_request_path: report.xhttp_request_path,
        xhttp_mode: report.xhttp_mode,
        xhttp_alpn: report.xhttp_alpn,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        xhttp_request_body_len: report.request_payload_len,
        xhttp_response_body_len: report.response_payload_len,
        payload_len: payload.len(),
        echoed_payload,
        iterations: report.iterations,
        total_exchange_count: report.total_exchange_count,
        elapsed_ns: report.elapsed_ns,
        ns_per_vmess_xhttp_h3_exchange: report.ns_per_xhttp_h3_exchange,
        client_selected_alpn: report.client_selected_alpn,
        server_selected_alpn: report.server_selected_alpn,
        tls13_only_configured: report.tls13_only_configured,
        quic_datagram_disabled: report.quic_datagram_disabled,
        keepalive_secs: report.keepalive_secs,
        handshake_idle_timeout_secs: report.handshake_idle_timeout_secs,
        certificate_der_len: report.certificate_der_len,
        h3_status: report.h3_status,
        h3_request_count: report.h3_request_count,
        h3_request_path_match_count: report.h3_request_path_match_count,
        h3_request_body_match_count: report.h3_request_body_match_count,
        h3_response_count: report.h3_response_count,
        h3_request_response_validated: report.h3_request_response_validated,
        quic_handshake_validated: report.quic_handshake_validated,
        xhttp_h3_packet_up_validated: report.xhttp_h3_packet_up_validated,
        full_h3_tls_lifecycle: report.full_h3_tls_lifecycle,
        reality_rejected_for_vmess: true,
        utls_deferred: true,
        download_settings_deferred: true,
        stream_modes_deferred: true,
        true_dataplane: report.xhttp_h3_packet_up_validated,
    }
}
