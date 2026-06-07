use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::error::OutboundError;

pub use super::tls::{
    DEFAULT_HYSTERIA2_ALPN, DEFAULT_HYSTERIA2_KEEPALIVE_SECS,
    DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS, DEFAULT_HYSTERIA2_SERVER_NAME,
};
use super::tls::{
    RawCertVerifierState, build_hysteria2_client_config, build_hysteria2_server_config,
    selected_alpn,
};
use super::underlay::raw_cert_sha256_hex;
pub use super::wire::HYSTERIA2_FRAME_TYPE_TCP_REQUEST;
use super::wire::{
    build_tcp_request_stream, build_tcp_response_stream, build_udp_message,
    parse_tcp_request_stream, parse_tcp_response_stream, parse_udp_message,
};

pub const DEFAULT_HYSTERIA2_TCP_TARGET: &str = "hysteria2-loopback-tcp.example:443";
pub const DEFAULT_HYSTERIA2_UDP_TARGET: &str = "hysteria2-loopback-udp.example:5353";
pub const DEFAULT_HYSTERIA2_TCP_PAYLOAD: &[u8] = b"hysteria2-loopback-tcp-ping";
pub const DEFAULT_HYSTERIA2_TCP_RESPONSE: &[u8] = b"hysteria2-loopback-tcp-pong";
pub const DEFAULT_HYSTERIA2_UDP_PAYLOAD: &[u8] = b"hysteria2-loopback-udp-ping";
pub const DEFAULT_HYSTERIA2_UDP_RESPONSE: &[u8] = b"hysteria2-loopback-udp-pong";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2QuicLoopbackOptions {
    pub server_name: String,
    pub tcp_target: String,
    pub udp_target: String,
    pub tcp_payload: Vec<u8>,
    pub tcp_response_payload: Vec<u8>,
    pub udp_payload: Vec<u8>,
    pub udp_response_payload: Vec<u8>,
    pub stream_iterations: usize,
    pub datagram_iterations: usize,
    pub timeout: Duration,
}

impl Default for Hysteria2QuicLoopbackOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_HYSTERIA2_SERVER_NAME.to_owned(),
            tcp_target: DEFAULT_HYSTERIA2_TCP_TARGET.to_owned(),
            udp_target: DEFAULT_HYSTERIA2_UDP_TARGET.to_owned(),
            tcp_payload: DEFAULT_HYSTERIA2_TCP_PAYLOAD.to_vec(),
            tcp_response_payload: DEFAULT_HYSTERIA2_TCP_RESPONSE.to_vec(),
            udp_payload: DEFAULT_HYSTERIA2_UDP_PAYLOAD.to_vec(),
            udp_response_payload: DEFAULT_HYSTERIA2_UDP_RESPONSE.to_vec(),
            stream_iterations: 2,
            datagram_iterations: 4,
            timeout: Duration::from_secs(8),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hysteria2QuicLoopbackReport {
    pub server_name: String,
    pub alpn_protocol: String,
    pub client_selected_alpn: String,
    pub server_selected_alpn: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_enabled: bool,
    pub keepalive_secs: u64,
    pub max_idle_timeout_secs: u64,
    pub loopback_addr: String,
    pub configured_pin_sha256: String,
    pub configured_pin_sha256_normalized: String,
    pub raw_cert_sha256_hex: String,
    pub raw_cert_pin_matched: bool,
    pub certificate_callback_observed: bool,
    pub certificate_der_len: usize,
    pub stream_iterations: usize,
    pub datagram_iterations: usize,
    pub total_exchange_count: usize,
    pub elapsed_ns: u128,
    pub ns_per_hysteria2_quic_exchange: f64,
    pub tcp_target: String,
    pub tcp_payload_len: usize,
    pub tcp_response_payload_len: usize,
    pub tcp_request_frame_len: usize,
    pub tcp_response_frame_len: usize,
    pub open_bi_stream_count: usize,
    pub client_stream_finish_count: usize,
    pub client_stream_acked_count: usize,
    pub server_accept_bi_stream_count: usize,
    pub server_tcp_request_read_count: usize,
    pub server_tcp_request_match_count: usize,
    pub server_tcp_response_write_count: usize,
    pub client_tcp_response_read_count: usize,
    pub client_tcp_response_match_count: usize,
    pub udp_target: String,
    pub udp_payload_len: usize,
    pub udp_response_payload_len: usize,
    pub udp_message_frame_len: usize,
    pub udp_response_frame_len: usize,
    pub client_datagram_send_count: usize,
    pub server_datagram_receive_count: usize,
    pub server_datagram_match_count: usize,
    pub server_datagram_send_count: usize,
    pub client_datagram_receive_count: usize,
    pub client_datagram_match_count: usize,
    pub quic_handshake_validated: bool,
    pub tcp_target_over_quic_validated: bool,
    pub udp_target_over_quic_datagram_validated: bool,
    pub hysteria2_full_quic_handshake_admitted: bool,
    pub hysteria2_stream_mux_admitted: bool,
    pub hysteria2_packet_datagram_admitted: bool,
}

pub fn run_hysteria2_quic_loopback_smoke(
    options: &Hysteria2QuicLoopbackOptions,
) -> Result<Hysteria2QuicLoopbackReport, OutboundError> {
    if options.stream_iterations == 0 {
        return Err(bad_quic_loopback(
            "Hysteria2 loopback --stream-iters must be greater than zero",
        ));
    }
    if options.datagram_iterations == 0 {
        return Err(bad_quic_loopback(
            "Hysteria2 loopback --datagram-iters must be greater than zero",
        ));
    }
    if options.tcp_payload.is_empty() || options.udp_payload.is_empty() {
        return Err(bad_quic_loopback("Hysteria2 payloads cannot be empty"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_quic_loopback(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(
            options.timeout,
            run_hysteria2_quic_loopback_smoke_async(options),
        )
        .await
        .map_err(|_| bad_quic_loopback("Hysteria2 true QUIC loopback timed out"))?
    })
}

async fn run_hysteria2_quic_loopback_smoke_async(
    options: &Hysteria2QuicLoopbackOptions,
) -> Result<Hysteria2QuicLoopbackReport, OutboundError> {
    let tcp_request = build_tcp_request_stream(&options.tcp_target, &options.tcp_payload)?;
    let tcp_response = build_tcp_response_stream(true, "", &options.tcp_response_payload)?;
    let udp_request = build_udp_message(0x1300_0001, 1, &options.udp_target, &options.udp_payload)?;
    let udp_response = build_udp_message(
        0x1300_0001,
        1,
        &options.udp_target,
        &options.udp_response_payload,
    )?;

    let (server_config, cert_der) = build_hysteria2_server_config(&options.server_name)?;
    let raw_cert_hash = raw_cert_sha256_hex(cert_der.as_ref());
    let configured_pin_sha256 = colon_dash_pin(&raw_cert_hash);
    let verifier_state = Arc::new(Mutex::new(RawCertVerifierState::default()));

    let server_endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_quic_loopback(format!("create Hysteria2 server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_quic_loopback(format!("Hysteria2 server local addr: {err}")))?;
    let server_options = options.clone();
    let server_task = tokio::spawn(async move {
        run_hysteria2_quic_server(
            server_endpoint,
            server_options,
            tcp_request.clone(),
            tcp_response.clone(),
            udp_request.clone(),
            udp_response.clone(),
        )
        .await
    });

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_quic_loopback(format!("create Hysteria2 client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(build_hysteria2_client_config(
        configured_pin_sha256.clone(),
        Arc::clone(&verifier_state),
    )?);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| bad_quic_loopback(format!("connect Hysteria2 loopback: {err}")))?
        .await
        .map_err(|err| bad_quic_loopback(format!("await Hysteria2 loopback connect: {err}")))?;
    let client_selected_alpn = selected_alpn(&client_connection);

    let start = Instant::now();
    let mut open_bi_stream_count = 0_usize;
    let mut client_stream_finish_count = 0_usize;
    let mut client_stream_acked_count = 0_usize;
    let mut client_tcp_response_read_count = 0_usize;
    let mut client_tcp_response_match_count = 0_usize;
    for _ in 0..options.stream_iterations {
        let (mut send, mut recv) = client_connection
            .open_bi()
            .await
            .map_err(|err| bad_quic_loopback(format!("open Hysteria2 TCP stream: {err}")))?;
        open_bi_stream_count += 1;
        send.write_all(&build_tcp_request_stream(
            &options.tcp_target,
            &options.tcp_payload,
        )?)
        .await
        .map_err(|err| bad_quic_loopback(format!("write Hysteria2 TCP request: {err}")))?;
        send.finish()
            .map_err(|err| bad_quic_loopback(format!("finish Hysteria2 TCP request: {err}")))?;
        client_stream_finish_count += 1;
        if send
            .stopped()
            .await
            .map_err(|err| bad_quic_loopback(format!("wait Hysteria2 TCP stream ack: {err}")))?
            .is_none()
        {
            client_stream_acked_count += 1;
        }
        let response = recv
            .read_to_end(8192)
            .await
            .map_err(|err| bad_quic_loopback(format!("read Hysteria2 TCP response: {err}")))?;
        client_tcp_response_read_count += 1;
        let parsed = parse_tcp_response_stream(&response)?;
        if parsed.ok
            && parsed.message.is_empty()
            && parsed.payload == options.tcp_response_payload
            && parsed.consumed_len < response.len()
        {
            client_tcp_response_match_count += 1;
        }
    }

    let mut client_datagram_send_count = 0_usize;
    let mut client_datagram_receive_count = 0_usize;
    let mut client_datagram_match_count = 0_usize;
    for packet_id in 1..=options.datagram_iterations {
        let request = build_udp_message(
            0x1300_0001,
            packet_id as u16,
            &options.udp_target,
            &options.udp_payload,
        )?;
        client_connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| bad_quic_loopback(format!("send Hysteria2 UDP datagram: {err}")))?;
        client_datagram_send_count += 1;
        let response = client_connection
            .read_datagram()
            .await
            .map_err(|err| bad_quic_loopback(format!("read Hysteria2 UDP datagram: {err}")))?;
        client_datagram_receive_count += 1;
        let parsed = parse_udp_message(&response)?;
        if parsed.target == options.udp_target
            && parsed.payload == options.udp_response_payload
            && parsed.session_id == 0x1300_0001
            && parsed.packet_id == packet_id as u16
            && parsed.frag_id == 0
            && parsed.frag_count == 1
        {
            client_datagram_match_count += 1;
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    client_connection.close(0_u32.into(), b"hysteria2-loopback done");
    client_endpoint.wait_idle().await;

    let server = server_task
        .await
        .map_err(|err| bad_quic_loopback(format!("join Hysteria2 server task: {err}")))??;
    let verifier = verifier_state
        .lock()
        .map_err(|_| bad_quic_loopback("Hysteria2 verifier state poisoned"))?
        .clone();
    let quic_handshake_validated = client_selected_alpn == DEFAULT_HYSTERIA2_ALPN
        && server.selected_alpn == DEFAULT_HYSTERIA2_ALPN
        && verifier.observed
        && verifier.matched;
    let tcp_target_over_quic_validated = quic_handshake_validated
        && open_bi_stream_count == options.stream_iterations
        && client_stream_finish_count == options.stream_iterations
        && client_stream_acked_count == options.stream_iterations
        && server.accept_bi_stream_count == options.stream_iterations
        && server.tcp_request_read_count == options.stream_iterations
        && server.tcp_request_match_count == options.stream_iterations
        && server.tcp_response_write_count == options.stream_iterations
        && client_tcp_response_read_count == options.stream_iterations
        && client_tcp_response_match_count == options.stream_iterations;
    let udp_target_over_quic_datagram_validated = quic_handshake_validated
        && client_datagram_send_count == options.datagram_iterations
        && server.datagram_receive_count == options.datagram_iterations
        && server.datagram_match_count == options.datagram_iterations
        && server.datagram_send_count == options.datagram_iterations
        && client_datagram_receive_count == options.datagram_iterations
        && client_datagram_match_count == options.datagram_iterations;
    let total_exchange_count = options.stream_iterations + options.datagram_iterations;

    Ok(Hysteria2QuicLoopbackReport {
        server_name: options.server_name.clone(),
        alpn_protocol: DEFAULT_HYSTERIA2_ALPN.to_owned(),
        client_selected_alpn,
        server_selected_alpn: server.selected_alpn,
        tls13_only_configured: true,
        quic_datagram_enabled: true,
        keepalive_secs: DEFAULT_HYSTERIA2_KEEPALIVE_SECS,
        max_idle_timeout_secs: DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS,
        loopback_addr: loopback_addr.to_string(),
        configured_pin_sha256,
        configured_pin_sha256_normalized: verifier.configured_pin_sha256_normalized,
        raw_cert_sha256_hex: verifier.raw_cert_sha256_hex,
        raw_cert_pin_matched: verifier.matched,
        certificate_callback_observed: verifier.observed,
        certificate_der_len: verifier.cert_der_len,
        stream_iterations: options.stream_iterations,
        datagram_iterations: options.datagram_iterations,
        total_exchange_count,
        elapsed_ns,
        ns_per_hysteria2_quic_exchange: elapsed_ns as f64 / total_exchange_count.max(1) as f64,
        tcp_target: options.tcp_target.clone(),
        tcp_payload_len: options.tcp_payload.len(),
        tcp_response_payload_len: options.tcp_response_payload.len(),
        tcp_request_frame_len: build_tcp_request_stream(&options.tcp_target, &options.tcp_payload)?
            .len(),
        tcp_response_frame_len: build_tcp_response_stream(true, "", &options.tcp_response_payload)?
            .len(),
        open_bi_stream_count,
        client_stream_finish_count,
        client_stream_acked_count,
        server_accept_bi_stream_count: server.accept_bi_stream_count,
        server_tcp_request_read_count: server.tcp_request_read_count,
        server_tcp_request_match_count: server.tcp_request_match_count,
        server_tcp_response_write_count: server.tcp_response_write_count,
        client_tcp_response_read_count,
        client_tcp_response_match_count,
        udp_target: options.udp_target.clone(),
        udp_payload_len: options.udp_payload.len(),
        udp_response_payload_len: options.udp_response_payload.len(),
        udp_message_frame_len: build_udp_message(
            0x1300_0001,
            1,
            &options.udp_target,
            &options.udp_payload,
        )?
        .len(),
        udp_response_frame_len: build_udp_message(
            0x1300_0001,
            1,
            &options.udp_target,
            &options.udp_response_payload,
        )?
        .len(),
        client_datagram_send_count,
        server_datagram_receive_count: server.datagram_receive_count,
        server_datagram_match_count: server.datagram_match_count,
        server_datagram_send_count: server.datagram_send_count,
        client_datagram_receive_count,
        client_datagram_match_count,
        quic_handshake_validated,
        tcp_target_over_quic_validated,
        udp_target_over_quic_datagram_validated,
        hysteria2_full_quic_handshake_admitted: quic_handshake_validated,
        hysteria2_stream_mux_admitted: tcp_target_over_quic_validated,
        hysteria2_packet_datagram_admitted: udp_target_over_quic_datagram_validated,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Hysteria2QuicServerReport {
    selected_alpn: String,
    accept_bi_stream_count: usize,
    tcp_request_read_count: usize,
    tcp_request_match_count: usize,
    tcp_response_write_count: usize,
    datagram_receive_count: usize,
    datagram_match_count: usize,
    datagram_send_count: usize,
}

async fn run_hysteria2_quic_server(
    endpoint: quinn::Endpoint,
    options: Hysteria2QuicLoopbackOptions,
    expected_tcp_request: Vec<u8>,
    tcp_response: Vec<u8>,
    expected_udp_request: Vec<u8>,
    udp_response: Vec<u8>,
) -> Result<Hysteria2QuicServerReport, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_quic_loopback("Hysteria2 server accept returned none"))?
        .await
        .map_err(|err| bad_quic_loopback(format!("accept Hysteria2 QUIC connection: {err}")))?;
    let selected_alpn = selected_alpn(&connection);
    let mut accept_bi_stream_count = 0_usize;
    let mut tcp_request_read_count = 0_usize;
    let mut tcp_request_match_count = 0_usize;
    let mut tcp_response_write_count = 0_usize;
    for _ in 0..options.stream_iterations {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|err| bad_quic_loopback(format!("accept Hysteria2 TCP stream: {err}")))?;
        accept_bi_stream_count += 1;
        let request = recv
            .read_to_end(8192)
            .await
            .map_err(|err| bad_quic_loopback(format!("read Hysteria2 TCP stream: {err}")))?;
        tcp_request_read_count += 1;
        let parsed = parse_tcp_request_stream(&request)?;
        if request == expected_tcp_request
            && parsed.target == options.tcp_target
            && parsed.payload == options.tcp_payload
            && parsed.consumed_len < request.len()
        {
            tcp_request_match_count += 1;
        }
        send.write_all(&tcp_response)
            .await
            .map_err(|err| bad_quic_loopback(format!("write Hysteria2 TCP response: {err}")))?;
        tcp_response_write_count += 1;
        send.finish()
            .map_err(|err| bad_quic_loopback(format!("finish Hysteria2 TCP response: {err}")))?;
    }

    let mut datagram_receive_count = 0_usize;
    let mut datagram_match_count = 0_usize;
    let mut datagram_send_count = 0_usize;
    for packet_id in 1..=options.datagram_iterations {
        let request = connection
            .read_datagram()
            .await
            .map_err(|err| bad_quic_loopback(format!("server read Hysteria2 datagram: {err}")))?;
        datagram_receive_count += 1;
        let parsed = parse_udp_message(&request)?;
        let expected = if packet_id == 1 {
            expected_udp_request.clone()
        } else {
            build_udp_message(
                0x1300_0001,
                packet_id as u16,
                &options.udp_target,
                &options.udp_payload,
            )?
        };
        if request == expected
            && parsed.target == options.udp_target
            && parsed.payload == options.udp_payload
            && parsed.packet_id == packet_id as u16
        {
            datagram_match_count += 1;
        }
        let response = if packet_id == 1 {
            udp_response.clone()
        } else {
            build_udp_message(
                0x1300_0001,
                packet_id as u16,
                &options.udp_target,
                &options.udp_response_payload,
            )?
        };
        connection
            .send_datagram(Bytes::from(response))
            .map_err(|err| bad_quic_loopback(format!("server send Hysteria2 datagram: {err}")))?;
        datagram_send_count += 1;
    }
    endpoint.wait_idle().await;
    Ok(Hysteria2QuicServerReport {
        selected_alpn,
        accept_bi_stream_count,
        tcp_request_read_count,
        tcp_request_match_count,
        tcp_response_write_count,
        datagram_receive_count,
        datagram_match_count,
        datagram_send_count,
    })
}

fn colon_dash_pin(raw_hex: &str) -> String {
    format!(
        "{}:{}-{}",
        &raw_hex[0..2].to_uppercase(),
        &raw_hex[2..4],
        &raw_hex[4..]
    )
}

fn bad_quic_loopback(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
