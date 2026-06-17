use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::{
    XHttpH3LoopbackOptions, XHttpH3LoopbackReport, XHttpLifecycleOptions,
    xhttp_h3_packet_up_loopback,
};
use crate::vmess::VMessNetwork;

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct VlessXHttpH3ExchangeReport {
    pub proxy: String,
    pub target: String,
    pub xhttp_host: String,
    pub xhttp_path: String,
    pub xhttp_request_path: String,
    pub xhttp_mode: String,
    pub xhttp_alpn: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub xhttp_request_body_len: usize,
    pub xhttp_response_body_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub iterations: usize,
    pub total_exchange_count: usize,
    pub elapsed_ns: u128,
    pub ns_per_vless_xhttp_h3_exchange: f64,
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
    pub reality_h3_rejected: bool,
    pub utls_deferred: bool,
    pub vision_deferred: bool,
    pub download_settings_deferred: bool,
    pub stream_modes_deferred: bool,
    pub true_dataplane: bool,
}

pub fn tcp_exchange_over_xhttp_h3_loopback(
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    xhttp_options: &XHttpLifecycleOptions,
    payload: &[u8],
    iterations: usize,
    timeout: Duration,
) -> Result<VlessXHttpH3ExchangeReport, OutboundError> {
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let response = response_payload_bytes(payload);
    let loopback = XHttpH3LoopbackOptions::new(
        xhttp_options.clone(),
        request.clone(),
        response,
        iterations,
        timeout,
    )?;
    let report = xhttp_h3_packet_up_loopback(&loopback)?;
    let (response_header_len, echoed_payload) = decode_response_payload(&report.echoed_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS xHTTP H3 payload response mismatch".to_owned(),
        ));
    }

    Ok(vless_xhttp_h3_report(
        proxy,
        target,
        key,
        request_header_len,
        response_header_len,
        payload,
        echoed_payload,
        report,
    ))
}

// Report assembly keeps xHTTP/H3 evidence fields explicit.
#[allow(clippy::too_many_arguments)]
fn vless_xhttp_h3_report(
    proxy: &str,
    target: &str,
    key: &[u8; 16],
    request_header_len: usize,
    response_header_len: usize,
    payload: &[u8],
    echoed_payload: Vec<u8>,
    report: XHttpH3LoopbackReport,
) -> VlessXHttpH3ExchangeReport {
    VlessXHttpH3ExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        xhttp_host: report.xhttp_host,
        xhttp_path: report.xhttp_path,
        xhttp_request_path: report.xhttp_request_path,
        xhttp_mode: report.xhttp_mode,
        xhttp_alpn: report.xhttp_alpn,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        xhttp_request_body_len: report.request_payload_len,
        xhttp_response_body_len: report.response_payload_len,
        payload_len: payload.len(),
        echoed_payload,
        iterations: report.iterations,
        total_exchange_count: report.total_exchange_count,
        elapsed_ns: report.elapsed_ns,
        ns_per_vless_xhttp_h3_exchange: report.ns_per_xhttp_h3_exchange,
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
        reality_h3_rejected: report.reality_h3_rejected,
        utls_deferred: true,
        vision_deferred: true,
        download_settings_deferred: true,
        stream_modes_deferred: true,
        true_dataplane: report.xhttp_h3_packet_up_validated,
    }
}
