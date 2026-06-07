use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;
use crate::trojan::{TrojanMetadata, TrojanNetwork};

use super::auth_stream_live::{build_live_client_config, build_live_server_config, selected_alpn};
use super::h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_SERVER_NAME,
};
use super::packet::{
    JuicityStreamPacketFrame, decode_stream_packet_frame, seal_stream_packet_frame,
};

pub const DEFAULT_STREAM_PACKET_CONN_TARGET: &str = "juicity-stream.example:5353";
pub const DEFAULT_STREAM_PACKET_CONN_RESPONSE_TARGET: &str = "juicity-stream-response.example:5353";
pub const DEFAULT_STREAM_PACKET_CONN_PAYLOAD: &[u8] = b"juicity-stream-ping";
pub const DEFAULT_STREAM_PACKET_CONN_RESPONSE: &[u8] = b"juicity-stream-pong";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityStreamPacketConnOptions {
    pub server_name: String,
    pub target: String,
    pub response_target: String,
    pub payload: Vec<u8>,
    pub response_payload: Vec<u8>,
    pub iterations: usize,
    pub timeout: Duration,
}

impl Default for JuicityStreamPacketConnOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_H3_SERVER_NAME.to_owned(),
            target: DEFAULT_STREAM_PACKET_CONN_TARGET.to_owned(),
            response_target: DEFAULT_STREAM_PACKET_CONN_RESPONSE_TARGET.to_owned(),
            payload: DEFAULT_STREAM_PACKET_CONN_PAYLOAD.to_vec(),
            response_payload: DEFAULT_STREAM_PACKET_CONN_RESPONSE.to_vec(),
            iterations: 1,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityStreamPacketConnReport {
    pub server_name: String,
    pub target: String,
    pub response_target: String,
    pub alpn_protocol: String,
    pub client_selected_alpn: String,
    pub server_selected_alpn: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_disabled: bool,
    pub keepalive_secs: u64,
    pub handshake_idle_timeout_secs: u64,
    pub loopback_addr: String,
    pub iterations: usize,
    pub elapsed_ns: u128,
    pub ns_per_juicity_stream_packet_conn_exchange: f64,
    pub connection_network_byte: u8,
    pub initial_metadata_len: usize,
    pub request_frame_metadata_len: usize,
    pub request_payload_len: usize,
    pub request_frame_len: usize,
    pub request_stream_write_len: usize,
    pub response_frame_metadata_len: usize,
    pub response_payload_len: usize,
    pub response_frame_len: usize,
    pub open_bi_stream_count: usize,
    pub client_stream_finish_count: usize,
    pub client_stream_acked_count: usize,
    pub server_accept_bi_stream_count: usize,
    pub server_request_read_count: usize,
    pub server_request_match_count: usize,
    pub server_response_write_count: usize,
    pub server_stream_finish_count: usize,
    pub server_stream_acked_count: usize,
    pub client_response_read_count: usize,
    pub client_response_match_count: usize,
    pub quic_handshake_validated: bool,
    pub stream_packet_conn_frame_order_validated: bool,
    pub stream_packet_conn_close_boundary_validated: bool,
    pub stream_packet_conn_live_relay_validated: bool,
    pub juicity_stream_packet_conn_live_stream_admitted: bool,
    pub juicity_stream_packet_conn_frame_order_admitted: bool,
    pub juicity_packet_over_stream_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_congestion_behavior_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

pub fn run_stream_packet_conn_smoke(
    options: &JuicityStreamPacketConnOptions,
) -> Result<JuicityStreamPacketConnReport, OutboundError> {
    if options.iterations == 0 {
        return Err(bad_stream_packet_conn(
            "Juicity stream packet conn iterations must be greater than zero",
        ));
    }
    if options.payload.is_empty() {
        return Err(bad_stream_packet_conn(
            "Juicity stream packet conn payload cannot be empty",
        ));
    }
    if options.response_payload.is_empty() {
        return Err(bad_stream_packet_conn(
            "Juicity stream packet conn response payload cannot be empty",
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_stream_packet_conn(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(options.timeout, run_stream_packet_conn_smoke_async(options))
            .await
            .map_err(|_| bad_stream_packet_conn("Juicity stream packet conn timed out"))?
    })
}

async fn run_stream_packet_conn_smoke_async(
    options: &JuicityStreamPacketConnOptions,
) -> Result<JuicityStreamPacketConnReport, OutboundError> {
    let request_frame = seal_stream_packet_frame(&options.target, &options.payload)?;
    let response_frame =
        seal_stream_packet_frame(&options.response_target, &options.response_payload)?;
    let request_stream = build_stream_conn_request(&options.target, &request_frame)?;

    let server_endpoint = quinn::Endpoint::server(
        build_live_server_config(&options.server_name)?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_stream_packet_conn(format!("create server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_stream_packet_conn(format!("server local addr: {err}")))?;
    let server_iterations = options.iterations;
    let server_target = options.target.clone();
    let server_response_frame = response_frame.clone();
    let server_payload = options.payload.clone();
    let server_task = tokio::spawn(async move {
        run_stream_packet_conn_server(
            server_endpoint,
            server_target,
            server_payload,
            server_response_frame,
            server_iterations,
        )
        .await
    });

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_stream_packet_conn(format!("create client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(build_live_client_config()?);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| bad_stream_packet_conn(format!("connect stream packet loopback: {err}")))?
        .await
        .map_err(|err| {
            bad_stream_packet_conn(format!("await stream packet loopback connect: {err}"))
        })?;
    let client_selected_alpn = selected_alpn(&client_connection);

    let start = Instant::now();
    let mut open_bi_stream_count = 0_usize;
    let mut client_stream_finish_count = 0_usize;
    let mut client_stream_acked_count = 0_usize;
    let mut client_response_read_count = 0_usize;
    let mut client_response_match_count = 0_usize;
    for _ in 0..options.iterations {
        let (mut send, mut recv) = client_connection.open_bi().await.map_err(|err| {
            bad_stream_packet_conn(format!("open stream packet bi stream: {err}"))
        })?;
        open_bi_stream_count += 1;
        send.write_all(&request_stream.encoded)
            .await
            .map_err(|err| bad_stream_packet_conn(format!("write stream packet request: {err}")))?;
        send.finish().map_err(|err| {
            bad_stream_packet_conn(format!("finish stream packet request: {err}"))
        })?;
        client_stream_finish_count += 1;
        if send
            .stopped()
            .await
            .map_err(|err| bad_stream_packet_conn(format!("wait client stream ack: {err}")))?
            .is_none()
        {
            client_stream_acked_count += 1;
        }
        let response = recv
            .read_to_end(response_frame.encoded.len())
            .await
            .map_err(|err| bad_stream_packet_conn(format!("read stream packet response: {err}")))?;
        client_response_read_count += 1;
        let decoded = decode_stream_packet_frame(&response)?;
        if decoded.target == options.response_target
            && decoded.payload == options.response_payload
            && decoded.encoded == response_frame.encoded
        {
            client_response_match_count += 1;
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    client_connection.close(0_u32.into(), b"juicity-stream done");
    client_endpoint.wait_idle().await;

    let server = server_task.await.map_err(|err| {
        bad_stream_packet_conn(format!("join stream packet server task: {err}"))
    })??;
    let quic_handshake_validated =
        client_selected_alpn == DEFAULT_H3_ALPN && server.selected_alpn == DEFAULT_H3_ALPN;
    let frame_order_validated = request_stream.network_byte == TrojanNetwork::Udp.byte()
        && request_stream.initial_metadata_target == options.target
        && request_frame.target == options.target
        && response_frame.target == options.response_target;
    let close_boundary_validated = client_stream_finish_count == options.iterations
        && client_stream_acked_count == options.iterations
        && server.server_stream_finish_count == options.iterations
        && server.server_stream_acked_count == options.iterations;
    let live_relay_validated = quic_handshake_validated
        && frame_order_validated
        && close_boundary_validated
        && open_bi_stream_count == options.iterations
        && server.accept_bi_stream_count == options.iterations
        && server.request_read_count == options.iterations
        && server.request_match_count == options.iterations
        && server.response_write_count == options.iterations
        && client_response_read_count == options.iterations
        && client_response_match_count == options.iterations;

    Ok(JuicityStreamPacketConnReport {
        server_name: options.server_name.clone(),
        target: options.target.clone(),
        response_target: options.response_target.clone(),
        alpn_protocol: DEFAULT_H3_ALPN.to_owned(),
        client_selected_alpn,
        server_selected_alpn: server.selected_alpn,
        tls13_only_configured: true,
        quic_datagram_disabled: true,
        keepalive_secs: DEFAULT_H3_KEEPALIVE_SECS,
        handshake_idle_timeout_secs: DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        loopback_addr: loopback_addr.to_string(),
        iterations: options.iterations,
        elapsed_ns,
        ns_per_juicity_stream_packet_conn_exchange: elapsed_ns as f64 / options.iterations as f64,
        connection_network_byte: request_stream.network_byte,
        initial_metadata_len: request_stream.initial_metadata_len,
        request_frame_metadata_len: request_frame.metadata_len,
        request_payload_len: request_frame.payload_len,
        request_frame_len: request_frame.encoded.len(),
        request_stream_write_len: request_stream.encoded.len(),
        response_frame_metadata_len: response_frame.metadata_len,
        response_payload_len: response_frame.payload_len,
        response_frame_len: response_frame.encoded.len(),
        open_bi_stream_count,
        client_stream_finish_count,
        client_stream_acked_count,
        server_accept_bi_stream_count: server.accept_bi_stream_count,
        server_request_read_count: server.request_read_count,
        server_request_match_count: server.request_match_count,
        server_response_write_count: server.response_write_count,
        server_stream_finish_count: server.server_stream_finish_count,
        server_stream_acked_count: server.server_stream_acked_count,
        client_response_read_count,
        client_response_match_count,
        quic_handshake_validated,
        stream_packet_conn_frame_order_validated: frame_order_validated,
        stream_packet_conn_close_boundary_validated: close_boundary_validated,
        stream_packet_conn_live_relay_validated: live_relay_validated,
        juicity_stream_packet_conn_live_stream_admitted: live_relay_validated,
        juicity_stream_packet_conn_frame_order_admitted: frame_order_validated,
        juicity_packet_over_stream_admitted: live_relay_validated,
        juicity_stream_packet_conn_dataplane_admitted: live_relay_validated,
        juicity_congestion_behavior_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamConnRequest {
    encoded: Vec<u8>,
    network_byte: u8,
    initial_metadata_len: usize,
    initial_metadata_target: String,
}

fn build_stream_conn_request(
    initial_target: &str,
    frame: &JuicityStreamPacketFrame,
) -> Result<StreamConnRequest, OutboundError> {
    let metadata = TrojanMetadata::parse("udp", initial_target)?;
    let initial_metadata = metadata.encode()?;
    let mut encoded = Vec::with_capacity(1 + initial_metadata.len() + frame.encoded.len());
    encoded.push(TrojanNetwork::Udp.byte());
    encoded.extend_from_slice(&initial_metadata);
    encoded.extend_from_slice(&frame.encoded);
    Ok(StreamConnRequest {
        encoded,
        network_byte: TrojanNetwork::Udp.byte(),
        initial_metadata_len: initial_metadata.len(),
        initial_metadata_target: metadata.authority(),
    })
}

#[derive(Debug)]
struct StreamPacketConnServerReport {
    selected_alpn: String,
    accept_bi_stream_count: usize,
    request_read_count: usize,
    request_match_count: usize,
    response_write_count: usize,
    server_stream_finish_count: usize,
    server_stream_acked_count: usize,
}

async fn run_stream_packet_conn_server(
    endpoint: quinn::Endpoint,
    expected_target: String,
    expected_payload: Vec<u8>,
    response_frame: JuicityStreamPacketFrame,
    iterations: usize,
) -> Result<StreamPacketConnServerReport, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_stream_packet_conn("server accept returned none"))?
        .await
        .map_err(|err| bad_stream_packet_conn(format!("server accept stream packet: {err}")))?;
    let selected_alpn = selected_alpn(&connection);
    let mut accept_bi_stream_count = 0_usize;
    let mut request_read_count = 0_usize;
    let mut request_match_count = 0_usize;
    let mut response_write_count = 0_usize;
    let mut server_stream_finish_count = 0_usize;
    let mut server_stream_acked_count = 0_usize;
    for _ in 0..iterations {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(|err| {
            bad_stream_packet_conn(format!("accept stream packet bi stream: {err}"))
        })?;
        accept_bi_stream_count += 1;
        let request = recv
            .read_to_end(4096)
            .await
            .map_err(|err| bad_stream_packet_conn(format!("read stream packet request: {err}")))?;
        request_read_count += 1;
        let parsed = parse_stream_conn_request(&request)?;
        if parsed.network_byte == TrojanNetwork::Udp.byte()
            && parsed.initial_target == expected_target
            && parsed.frame.target == expected_target
            && parsed.frame.payload == expected_payload
        {
            request_match_count += 1;
        }
        send.write_all(&response_frame.encoded)
            .await
            .map_err(|err| {
                bad_stream_packet_conn(format!("write stream packet response: {err}"))
            })?;
        response_write_count += 1;
        send.finish().map_err(|err| {
            bad_stream_packet_conn(format!("finish stream packet response: {err}"))
        })?;
        server_stream_finish_count += 1;
        if send
            .stopped()
            .await
            .map_err(|err| bad_stream_packet_conn(format!("wait server stream ack: {err}")))?
            .is_none()
        {
            server_stream_acked_count += 1;
        }
    }
    endpoint.wait_idle().await;
    Ok(StreamPacketConnServerReport {
        selected_alpn,
        accept_bi_stream_count,
        request_read_count,
        request_match_count,
        response_write_count,
        server_stream_finish_count,
        server_stream_acked_count,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedStreamConnRequest {
    network_byte: u8,
    initial_target: String,
    frame: JuicityStreamPacketFrame,
}

fn parse_stream_conn_request(input: &[u8]) -> Result<ParsedStreamConnRequest, OutboundError> {
    let Some((&network_byte, rest)) = input.split_first() else {
        return Err(bad_stream_packet_conn(
            "stream packet request missing network byte",
        ));
    };
    let (initial_address, initial_metadata_len) = Socks5Address::decode(rest)?;
    let frame = decode_stream_packet_frame(&rest[initial_metadata_len..])?;
    Ok(ParsedStreamConnRequest {
        network_byte,
        initial_target: initial_address.authority(),
        frame,
    })
}

fn bad_stream_packet_conn(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
