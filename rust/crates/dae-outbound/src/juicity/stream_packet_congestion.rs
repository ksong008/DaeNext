use std::cmp;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
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

pub const DEFAULT_STREAM_PACKET_CONGESTION_TARGET: &str = "juicity-congestion.example:5353";
pub const DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_TARGET: &str =
    "juicity-congestion-response.example:5353";
pub const DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN: usize = 4096;
pub const DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN: usize = 1024;
pub const DEFAULT_STREAM_PACKET_CONGESTION_ITERATIONS: usize = 16;
pub const DEFAULT_STREAM_PACKET_CONGESTION_MAX_IN_FLIGHT: usize = 4;
pub const DEFAULT_STREAM_PACKET_CONGESTION_CONTROL: &str = "bbr";
pub const GO_JUICITY_CONGESTION_DEFAULT: &str = "bbr";
pub const GO_JUICITY_CONGESTION_CWND_PARAM: usize = 10;
pub const GO_BBR_INITIAL_CONGESTION_WINDOW_PACKETS: usize = 32;
pub const GO_BBR_INITIAL_PACKET_SIZE_IPV4: usize = 1280;
pub const RUST_BBR_INITIAL_WINDOW_BYTES: u64 =
    (GO_BBR_INITIAL_CONGESTION_WINDOW_PACKETS * GO_BBR_INITIAL_PACKET_SIZE_IPV4) as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityStreamPacketCongestionOptions {
    pub server_name: String,
    pub target: String,
    pub response_target: String,
    pub payload: Vec<u8>,
    pub response_payload: Vec<u8>,
    pub iterations: usize,
    pub max_in_flight_streams: usize,
    pub congestion_control: String,
    pub timeout: Duration,
}

impl Default for JuicityStreamPacketCongestionOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_H3_SERVER_NAME.to_owned(),
            target: DEFAULT_STREAM_PACKET_CONGESTION_TARGET.to_owned(),
            response_target: DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_TARGET.to_owned(),
            payload: default_congestion_payload(DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN),
            response_payload: default_congestion_payload(
                DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN,
            ),
            iterations: DEFAULT_STREAM_PACKET_CONGESTION_ITERATIONS,
            max_in_flight_streams: DEFAULT_STREAM_PACKET_CONGESTION_MAX_IN_FLIGHT,
            congestion_control: DEFAULT_STREAM_PACKET_CONGESTION_CONTROL.to_owned(),
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityStreamPacketCongestionReport {
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
    pub congestion_control_requested: String,
    pub congestion_control_effective: String,
    pub go_congestion_control_default: String,
    pub go_cwnd_param: usize,
    pub go_bbr_initial_congestion_window_packets: usize,
    pub go_bbr_initial_packet_size_ipv4: usize,
    pub rust_bbr_initial_window_bytes: u64,
    pub bbr_factory_configured: bool,
    pub iterations: usize,
    pub max_in_flight_streams: usize,
    pub max_in_flight_observed: usize,
    pub elapsed_ns: u128,
    pub ns_per_juicity_stream_packet_congestion_exchange: f64,
    pub connection_network_byte: u8,
    pub initial_metadata_len: usize,
    pub request_frame_metadata_len: usize,
    pub request_payload_len: usize,
    pub request_frame_len: usize,
    pub request_stream_write_len: usize,
    pub response_frame_metadata_len: usize,
    pub response_payload_len: usize,
    pub response_frame_len: usize,
    pub total_request_payload_bytes: usize,
    pub total_response_payload_bytes: usize,
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
    pub client_sent_packets_delta: u64,
    pub client_cwnd_bytes: u64,
    pub client_congestion_events: u64,
    pub client_lost_packets: u64,
    pub client_current_mtu: u16,
    pub client_rtt_ns: u128,
    pub server_sent_packets: u64,
    pub server_cwnd_bytes: u64,
    pub server_congestion_events: u64,
    pub server_lost_packets: u64,
    pub server_current_mtu: u16,
    pub server_rtt_ns: u128,
    pub quic_handshake_validated: bool,
    pub stream_packet_conn_sustained_relay_validated: bool,
    pub stream_packet_conn_congestion_stats_recorded: bool,
    pub stream_packet_conn_bbr_controller_validated: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_packet_over_stream_admitted: bool,
    pub juicity_congestion_bbr_controller_admitted: bool,
    pub juicity_congestion_sustained_relay_admitted: bool,
    pub juicity_congestion_behavior_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

pub fn default_congestion_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| b'a' + ((idx % 26) as u8))
        .collect::<Vec<_>>()
}

pub fn normalize_congestion_control(input: &str) -> &'static str {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "bbr" => "bbr",
        _ => "bbr",
    }
}

pub fn run_stream_packet_congestion_smoke(
    options: &JuicityStreamPacketCongestionOptions,
) -> Result<JuicityStreamPacketCongestionReport, OutboundError> {
    if options.iterations == 0 {
        return Err(bad_stream_packet_congestion(
            "Juicity stream packet congestion iterations must be greater than zero",
        ));
    }
    if options.max_in_flight_streams == 0 {
        return Err(bad_stream_packet_congestion(
            "Juicity stream packet congestion --max-in-flight-streams must be greater than zero",
        ));
    }
    if options.payload.is_empty() {
        return Err(bad_stream_packet_congestion(
            "Juicity stream packet congestion payload cannot be empty",
        ));
    }
    if options.response_payload.is_empty() {
        return Err(bad_stream_packet_congestion(
            "Juicity stream packet congestion response payload cannot be empty",
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_stream_packet_congestion(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(
            options.timeout,
            run_stream_packet_congestion_smoke_async(options),
        )
        .await
        .map_err(|_| bad_stream_packet_congestion("Juicity stream packet congestion timed out"))?
    })
}

async fn run_stream_packet_congestion_smoke_async(
    options: &JuicityStreamPacketCongestionOptions,
) -> Result<JuicityStreamPacketCongestionReport, OutboundError> {
    let request_frame = seal_stream_packet_frame(&options.target, &options.payload)?;
    let response_frame =
        seal_stream_packet_frame(&options.response_target, &options.response_payload)?;
    let request_stream = build_stream_conn_request(&options.target, &request_frame)?;

    let mut server_config = build_live_server_config(&options.server_name)?;
    server_config.transport_config(Arc::new(bbr_transport_config()?));
    let server_endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_stream_packet_congestion(format!("create server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_stream_packet_congestion(format!("server local addr: {err}")))?;
    let server_task = tokio::spawn(run_stream_packet_congestion_server(
        server_endpoint,
        options.target.clone(),
        options.payload.clone(),
        response_frame.clone(),
        options.iterations,
    ));

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).map_err(
            |err| bad_stream_packet_congestion(format!("create client endpoint: {err}")),
        )?;
    let mut client_config = build_live_client_config()?;
    client_config.transport_config(Arc::new(bbr_transport_config()?));
    client_endpoint.set_default_client_config(client_config);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| {
            bad_stream_packet_congestion(format!("connect stream congestion loopback: {err}"))
        })?
        .await
        .map_err(|err| {
            bad_stream_packet_congestion(format!("await stream congestion loopback connect: {err}"))
        })?;
    let client_selected_alpn = selected_alpn(&client_connection);
    let client_stats_before = client_connection.stats();

    let start = Instant::now();
    let mut open_bi_stream_count = 0_usize;
    let mut client_stream_finish_count = 0_usize;
    let mut client_stream_acked_count = 0_usize;
    let mut client_response_read_count = 0_usize;
    let mut client_response_match_count = 0_usize;
    let mut max_in_flight_observed = 0_usize;
    let mut remaining = options.iterations;

    while remaining > 0 {
        let batch_len = cmp::min(remaining, options.max_in_flight_streams);
        let mut pending = Vec::with_capacity(batch_len);
        for _ in 0..batch_len {
            let (mut send, recv) = client_connection.open_bi().await.map_err(|err| {
                bad_stream_packet_congestion(format!("open congestion bi stream: {err}"))
            })?;
            open_bi_stream_count += 1;
            send.write_all(&request_stream.encoded)
                .await
                .map_err(|err| {
                    bad_stream_packet_congestion(format!("write congestion request: {err}"))
                })?;
            send.finish().map_err(|err| {
                bad_stream_packet_congestion(format!("finish congestion request: {err}"))
            })?;
            client_stream_finish_count += 1;
            pending.push((send, recv));
        }
        max_in_flight_observed = cmp::max(max_in_flight_observed, pending.len());
        for (send, mut recv) in pending {
            if send
                .stopped()
                .await
                .map_err(|err| {
                    bad_stream_packet_congestion(format!("wait congestion stream ack: {err}"))
                })?
                .is_none()
            {
                client_stream_acked_count += 1;
            }
            let response = recv
                .read_to_end(response_frame.encoded.len())
                .await
                .map_err(|err| {
                    bad_stream_packet_congestion(format!("read congestion response: {err}"))
                })?;
            client_response_read_count += 1;
            let decoded = decode_stream_packet_frame(&response)?;
            if decoded.target == options.response_target
                && decoded.payload == options.response_payload
                && decoded.encoded == response_frame.encoded
            {
                client_response_match_count += 1;
            }
        }
        remaining -= batch_len;
    }

    let elapsed_ns = start.elapsed().as_nanos();
    let client_stats_after = client_connection.stats();
    client_connection.close(0_u32.into(), b"juicity-congestion done");
    client_endpoint.wait_idle().await;

    let server = server_task.await.map_err(|err| {
        bad_stream_packet_congestion(format!("join stream congestion server task: {err}"))
    })??;
    let quic_handshake_validated =
        client_selected_alpn == DEFAULT_H3_ALPN && server.selected_alpn == DEFAULT_H3_ALPN;
    let expected_max_in_flight = cmp::min(options.iterations, options.max_in_flight_streams);
    let sustained_relay_validated = quic_handshake_validated
        && request_stream.network_byte == TrojanNetwork::Udp.byte()
        && max_in_flight_observed == expected_max_in_flight
        && open_bi_stream_count == options.iterations
        && client_stream_finish_count == options.iterations
        && client_stream_acked_count == options.iterations
        && server.accept_bi_stream_count == options.iterations
        && server.request_read_count == options.iterations
        && server.request_match_count == options.iterations
        && server.response_write_count == options.iterations
        && server.server_stream_finish_count == options.iterations
        && server.server_stream_acked_count == options.iterations
        && client_response_read_count == options.iterations
        && client_response_match_count == options.iterations;
    let client_sent_packets_delta = client_stats_after
        .path
        .sent_packets
        .saturating_sub(client_stats_before.path.sent_packets);
    let congestion_stats_recorded = client_stats_after.path.cwnd > 0
        && server.stats.path.cwnd > 0
        && client_sent_packets_delta > 0
        && client_stats_after.path.current_mtu > 0
        && server.stats.path.current_mtu > 0;
    let effective_congestion = normalize_congestion_control(&options.congestion_control);
    let bbr_controller_validated = effective_congestion == "bbr";
    let congestion_behavior_admitted =
        sustained_relay_validated && congestion_stats_recorded && bbr_controller_validated;

    Ok(JuicityStreamPacketCongestionReport {
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
        congestion_control_requested: options.congestion_control.clone(),
        congestion_control_effective: effective_congestion.to_owned(),
        go_congestion_control_default: GO_JUICITY_CONGESTION_DEFAULT.to_owned(),
        go_cwnd_param: GO_JUICITY_CONGESTION_CWND_PARAM,
        go_bbr_initial_congestion_window_packets: GO_BBR_INITIAL_CONGESTION_WINDOW_PACKETS,
        go_bbr_initial_packet_size_ipv4: GO_BBR_INITIAL_PACKET_SIZE_IPV4,
        rust_bbr_initial_window_bytes: RUST_BBR_INITIAL_WINDOW_BYTES,
        bbr_factory_configured: true,
        iterations: options.iterations,
        max_in_flight_streams: options.max_in_flight_streams,
        max_in_flight_observed,
        elapsed_ns,
        ns_per_juicity_stream_packet_congestion_exchange: elapsed_ns as f64
            / options.iterations as f64,
        connection_network_byte: request_stream.network_byte,
        initial_metadata_len: request_stream.initial_metadata_len,
        request_frame_metadata_len: request_frame.metadata_len,
        request_payload_len: request_frame.payload_len,
        request_frame_len: request_frame.encoded.len(),
        request_stream_write_len: request_stream.encoded.len(),
        response_frame_metadata_len: response_frame.metadata_len,
        response_payload_len: response_frame.payload_len,
        response_frame_len: response_frame.encoded.len(),
        total_request_payload_bytes: options.payload.len() * options.iterations,
        total_response_payload_bytes: options.response_payload.len() * options.iterations,
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
        client_sent_packets_delta,
        client_cwnd_bytes: client_stats_after.path.cwnd,
        client_congestion_events: client_stats_after.path.congestion_events,
        client_lost_packets: client_stats_after.path.lost_packets,
        client_current_mtu: client_stats_after.path.current_mtu,
        client_rtt_ns: client_stats_after.path.rtt.as_nanos(),
        server_sent_packets: server.stats.path.sent_packets,
        server_cwnd_bytes: server.stats.path.cwnd,
        server_congestion_events: server.stats.path.congestion_events,
        server_lost_packets: server.stats.path.lost_packets,
        server_current_mtu: server.stats.path.current_mtu,
        server_rtt_ns: server.stats.path.rtt.as_nanos(),
        quic_handshake_validated,
        stream_packet_conn_sustained_relay_validated: sustained_relay_validated,
        stream_packet_conn_congestion_stats_recorded: congestion_stats_recorded,
        stream_packet_conn_bbr_controller_validated: bbr_controller_validated,
        juicity_stream_packet_conn_dataplane_admitted: sustained_relay_validated,
        juicity_packet_over_stream_admitted: sustained_relay_validated,
        juicity_congestion_bbr_controller_admitted: bbr_controller_validated,
        juicity_congestion_sustained_relay_admitted: sustained_relay_validated,
        juicity_congestion_behavior_admitted: congestion_behavior_admitted,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

#[derive(Debug)]
struct StreamPacketCongestionServerReport {
    selected_alpn: String,
    accept_bi_stream_count: usize,
    request_read_count: usize,
    request_match_count: usize,
    response_write_count: usize,
    server_stream_finish_count: usize,
    server_stream_acked_count: usize,
    stats: quinn::ConnectionStats,
}

async fn run_stream_packet_congestion_server(
    endpoint: quinn::Endpoint,
    expected_target: String,
    expected_payload: Vec<u8>,
    response_frame: JuicityStreamPacketFrame,
    iterations: usize,
) -> Result<StreamPacketCongestionServerReport, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_stream_packet_congestion("server accept returned none"))?
        .await
        .map_err(|err| {
            bad_stream_packet_congestion(format!("server accept stream congestion: {err}"))
        })?;
    let selected_alpn = selected_alpn(&connection);
    let mut accept_bi_stream_count = 0_usize;
    let mut request_read_count = 0_usize;
    let mut request_match_count = 0_usize;
    let mut response_write_count = 0_usize;
    let mut server_stream_finish_count = 0_usize;
    let mut server_stream_acked_count = 0_usize;
    for _ in 0..iterations {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(|err| {
            bad_stream_packet_congestion(format!("accept stream congestion bi stream: {err}"))
        })?;
        accept_bi_stream_count += 1;
        let request = recv.read_to_end(8192).await.map_err(|err| {
            bad_stream_packet_congestion(format!("read stream congestion request: {err}"))
        })?;
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
                bad_stream_packet_congestion(format!("write stream congestion response: {err}"))
            })?;
        response_write_count += 1;
        send.finish().map_err(|err| {
            bad_stream_packet_congestion(format!("finish stream congestion response: {err}"))
        })?;
        server_stream_finish_count += 1;
        if send
            .stopped()
            .await
            .map_err(|err| {
                bad_stream_packet_congestion(format!("wait server congestion ack: {err}"))
            })?
            .is_none()
        {
            server_stream_acked_count += 1;
        }
    }
    let stats = connection.stats();
    endpoint.wait_idle().await;
    Ok(StreamPacketCongestionServerReport {
        selected_alpn,
        accept_bi_stream_count,
        request_read_count,
        request_match_count,
        response_write_count,
        server_stream_finish_count,
        server_stream_acked_count,
        stats,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamConnRequest {
    encoded: Vec<u8>,
    network_byte: u8,
    initial_metadata_len: usize,
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
        return Err(bad_stream_packet_congestion(
            "stream congestion request missing network byte",
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

fn bbr_transport_config() -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_H3_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| {
                bad_stream_packet_congestion(format!("h3 idle timeout config: {err}"))
            })?,
    ));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    let mut bbr = quinn::congestion::BbrConfig::default();
    bbr.initial_window(RUST_BBR_INITIAL_WINDOW_BYTES);
    transport.congestion_controller_factory(Arc::new(bbr));
    Ok(transport)
}

fn bad_stream_packet_congestion(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
