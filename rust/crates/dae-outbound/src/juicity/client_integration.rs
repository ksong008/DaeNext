use std::time::{Duration, Instant};

use crate::error::OutboundError;

use super::auth_lifecycle::{
    DEFAULT_AUTH_LIFECYCLE_TARGETS, JuicityAuthLifecycleOptions, JuicityAuthLifecycleReport,
    run_auth_lifecycle_smoke,
};
use super::h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_SERVER_NAME,
};
use super::stream_packet_congestion::{
    DEFAULT_STREAM_PACKET_CONGESTION_CONTROL, DEFAULT_STREAM_PACKET_CONGESTION_MAX_IN_FLIGHT,
    JuicityStreamPacketCongestionOptions, JuicityStreamPacketCongestionReport,
    run_stream_packet_congestion_smoke,
};
use super::stream_packet_conn::{
    JuicityStreamPacketConnOptions, JuicityStreamPacketConnReport, run_stream_packet_conn_smoke,
};
use super::transport_packet_conn::{
    JuicityTransportPacketConnOptions, JuicityTransportPacketConnReport,
    run_transport_packet_conn_smoke,
};

pub const DEFAULT_CLIENT_INTEGRATION_AUTH_ITERATIONS: usize = 1;
pub const DEFAULT_CLIENT_INTEGRATION_TRANSPORT_ITERATIONS: usize = 8;
pub const DEFAULT_CLIENT_INTEGRATION_STREAM_ITERATIONS: usize = 2;
pub const DEFAULT_CLIENT_INTEGRATION_CONGESTION_ITERATIONS: usize = 8;
pub const DEFAULT_CLIENT_INTEGRATION_MAX_IN_FLIGHT: usize =
    DEFAULT_STREAM_PACKET_CONGESTION_MAX_IN_FLIGHT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityClientIntegrationOptions {
    pub server_name: String,
    pub auth_targets: Vec<String>,
    pub auth_iterations: usize,
    pub transport_iterations: usize,
    pub stream_iterations: usize,
    pub congestion_iterations: usize,
    pub max_in_flight_streams: usize,
    pub congestion_control: String,
    pub timeout: Duration,
}

impl Default for JuicityClientIntegrationOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_H3_SERVER_NAME.to_owned(),
            auth_targets: DEFAULT_AUTH_LIFECYCLE_TARGETS
                .iter()
                .map(|target| (*target).to_owned())
                .collect(),
            auth_iterations: DEFAULT_CLIENT_INTEGRATION_AUTH_ITERATIONS,
            transport_iterations: DEFAULT_CLIENT_INTEGRATION_TRANSPORT_ITERATIONS,
            stream_iterations: DEFAULT_CLIENT_INTEGRATION_STREAM_ITERATIONS,
            congestion_iterations: DEFAULT_CLIENT_INTEGRATION_CONGESTION_ITERATIONS,
            max_in_flight_streams: DEFAULT_CLIENT_INTEGRATION_MAX_IN_FLIGHT,
            congestion_control: DEFAULT_STREAM_PACKET_CONGESTION_CONTROL.to_owned(),
            timeout: Duration::from_secs(12),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityClientIntegrationReport {
    pub server_name: String,
    pub alpn_protocol: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_disabled: bool,
    pub keepalive_secs: u64,
    pub handshake_idle_timeout_secs: u64,
    pub auth_iterations: usize,
    pub transport_iterations: usize,
    pub stream_iterations: usize,
    pub congestion_iterations: usize,
    pub max_in_flight_streams: usize,
    pub total_elapsed_ns: u128,
    pub total_exchange_count: usize,
    pub ns_per_juicity_client_integration_exchange: f64,
    pub auth_lifecycle_elapsed_ns: u128,
    pub auth_record_count: usize,
    pub auth_channel_enqueue_count: usize,
    pub auth_channel_receive_count: usize,
    pub auth_server_transcript_match_count: usize,
    pub transport_elapsed_ns: u128,
    pub transport_roundtrip_match_count: usize,
    pub transport_payload_len: usize,
    pub transport_encrypted_packet_len: usize,
    pub stream_elapsed_ns: u128,
    pub stream_response_match_count: usize,
    pub stream_request_frame_len: usize,
    pub stream_response_frame_len: usize,
    pub congestion_elapsed_ns: u128,
    pub congestion_response_match_count: usize,
    pub congestion_max_in_flight_observed: usize,
    pub congestion_request_payload_len: usize,
    pub congestion_response_payload_len: usize,
    pub congestion_total_request_payload_bytes: usize,
    pub congestion_total_response_payload_bytes: usize,
    pub congestion_client_cwnd_bytes: u64,
    pub congestion_server_cwnd_bytes: u64,
    pub auth_lifecycle_admitted: bool,
    pub transport_packet_conn_admitted: bool,
    pub stream_packet_conn_admitted: bool,
    pub congestion_behavior_admitted: bool,
    pub client_capability_matrix_admitted: bool,
    pub full_local_client_smoke_admitted: bool,
    pub juicity_client_integration_candidate_admitted: bool,
    pub juicity_full_local_client_smoke_admitted: bool,
    pub juicity_client_capability_matrix_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
    pub outbound_true_dataplane_admitted: bool,
    pub default_switch_allowed: bool,
    pub product_chain_switch_allowed: bool,
}

pub fn run_client_integration_smoke(
    options: &JuicityClientIntegrationOptions,
) -> Result<JuicityClientIntegrationReport, OutboundError> {
    if options.auth_iterations == 0 {
        return Err(bad_client_integration(
            "stage128 --auth-iters must be greater than zero",
        ));
    }
    if options.transport_iterations == 0 {
        return Err(bad_client_integration(
            "stage128 --transport-iters must be greater than zero",
        ));
    }
    if options.stream_iterations == 0 {
        return Err(bad_client_integration(
            "stage128 --stream-iters must be greater than zero",
        ));
    }
    if options.congestion_iterations == 0 {
        return Err(bad_client_integration(
            "stage128 --congestion-iters must be greater than zero",
        ));
    }
    if options.max_in_flight_streams == 0 {
        return Err(bad_client_integration(
            "stage128 --max-in-flight-streams must be greater than zero",
        ));
    }
    if options.auth_targets.is_empty() {
        return Err(bad_client_integration(
            "stage128 auth target list cannot be empty",
        ));
    }

    let total_start = Instant::now();
    let auth = run_auth_lifecycle_smoke(&JuicityAuthLifecycleOptions {
        server_name: options.server_name.clone(),
        targets: options.auth_targets.clone(),
        iterations: options.auth_iterations,
        timeout: options.timeout,
        ..Default::default()
    })?;
    let transport = run_transport_packet_conn_smoke(&JuicityTransportPacketConnOptions {
        iterations: options.transport_iterations,
        timeout: options.timeout,
        ..Default::default()
    })?;
    let stream = run_stream_packet_conn_smoke(&JuicityStreamPacketConnOptions {
        server_name: options.server_name.clone(),
        iterations: options.stream_iterations,
        timeout: options.timeout,
        ..Default::default()
    })?;
    let congestion = run_stream_packet_congestion_smoke(&JuicityStreamPacketCongestionOptions {
        server_name: options.server_name.clone(),
        iterations: options.congestion_iterations,
        max_in_flight_streams: options.max_in_flight_streams,
        congestion_control: options.congestion_control.clone(),
        timeout: options.timeout,
        ..Default::default()
    })?;
    let total_elapsed_ns = total_start.elapsed().as_nanos();
    build_client_integration_report(
        options,
        total_elapsed_ns,
        auth,
        transport,
        stream,
        congestion,
    )
}

fn build_client_integration_report(
    options: &JuicityClientIntegrationOptions,
    total_elapsed_ns: u128,
    auth: JuicityAuthLifecycleReport,
    transport: JuicityTransportPacketConnReport,
    stream: JuicityStreamPacketConnReport,
    congestion: JuicityStreamPacketCongestionReport,
) -> Result<JuicityClientIntegrationReport, OutboundError> {
    let auth_lifecycle_admitted = auth.juicity_send_authentication_lifecycle_admitted
        && auth.juicity_underlay_auth_channel_order_admitted
        && auth.juicity_multiple_dialauth_records_over_auth_stream_admitted
        && auth.juicity_auth_stream_finish_boundary_admitted;
    let transport_packet_conn_admitted = transport.juicity_transport_packet_conn_crypto_admitted
        && transport.juicity_transport_packet_conn_first_iv_admitted
        && transport.juicity_transport_packet_conn_udp_roundtrip_admitted
        && transport.juicity_transport_packet_conn_dataplane_admitted;
    let stream_packet_conn_admitted = stream.juicity_stream_packet_conn_live_stream_admitted
        && stream.juicity_stream_packet_conn_frame_order_admitted
        && stream.juicity_packet_over_stream_admitted
        && stream.juicity_stream_packet_conn_dataplane_admitted;
    let congestion_behavior_admitted = congestion.juicity_congestion_bbr_controller_admitted
        && congestion.juicity_congestion_sustained_relay_admitted
        && congestion.juicity_congestion_behavior_admitted;
    let capability_matrix_admitted = auth.tls13_only_configured
        && auth.quic_datagram_disabled
        && stream.tls13_only_configured
        && stream.quic_datagram_disabled
        && congestion.tls13_only_configured
        && congestion.quic_datagram_disabled
        && auth.alpn_protocol == DEFAULT_H3_ALPN
        && stream.alpn_protocol == DEFAULT_H3_ALPN
        && congestion.alpn_protocol == DEFAULT_H3_ALPN
        && auth.keepalive_secs == DEFAULT_H3_KEEPALIVE_SECS
        && stream.keepalive_secs == DEFAULT_H3_KEEPALIVE_SECS
        && congestion.keepalive_secs == DEFAULT_H3_KEEPALIVE_SECS
        && auth.handshake_idle_timeout_secs == DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS
        && stream.handshake_idle_timeout_secs == DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS
        && congestion.handshake_idle_timeout_secs == DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS;
    let full_local_client_smoke_admitted = auth_lifecycle_admitted
        && transport_packet_conn_admitted
        && stream_packet_conn_admitted
        && congestion_behavior_admitted;
    let client_integration_candidate_admitted =
        full_local_client_smoke_admitted && capability_matrix_admitted;
    let total_exchange_count = options.auth_iterations
        + options.transport_iterations
        + options.stream_iterations
        + options.congestion_iterations;
    if total_exchange_count == 0 {
        return Err(bad_client_integration(
            "stage128 total exchange count cannot be zero",
        ));
    }

    Ok(JuicityClientIntegrationReport {
        server_name: options.server_name.clone(),
        alpn_protocol: DEFAULT_H3_ALPN.to_owned(),
        tls13_only_configured: capability_matrix_admitted,
        quic_datagram_disabled: capability_matrix_admitted,
        keepalive_secs: DEFAULT_H3_KEEPALIVE_SECS,
        handshake_idle_timeout_secs: DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        auth_iterations: options.auth_iterations,
        transport_iterations: options.transport_iterations,
        stream_iterations: options.stream_iterations,
        congestion_iterations: options.congestion_iterations,
        max_in_flight_streams: options.max_in_flight_streams,
        total_elapsed_ns,
        total_exchange_count,
        ns_per_juicity_client_integration_exchange: total_elapsed_ns as f64
            / total_exchange_count as f64,
        auth_lifecycle_elapsed_ns: auth.elapsed_ns,
        auth_record_count: auth.record_count,
        auth_channel_enqueue_count: auth.channel_enqueue_count,
        auth_channel_receive_count: auth.channel_receive_count,
        auth_server_transcript_match_count: auth.server_transcript_match_count,
        transport_elapsed_ns: transport.elapsed_ns,
        transport_roundtrip_match_count: transport.roundtrip_match_count,
        transport_payload_len: transport.payload_len,
        transport_encrypted_packet_len: transport.encrypted_packet_len,
        stream_elapsed_ns: stream.elapsed_ns,
        stream_response_match_count: stream.client_response_match_count,
        stream_request_frame_len: stream.request_frame_len,
        stream_response_frame_len: stream.response_frame_len,
        congestion_elapsed_ns: congestion.elapsed_ns,
        congestion_response_match_count: congestion.client_response_match_count,
        congestion_max_in_flight_observed: congestion.max_in_flight_observed,
        congestion_request_payload_len: congestion.request_payload_len,
        congestion_response_payload_len: congestion.response_payload_len,
        congestion_total_request_payload_bytes: congestion.total_request_payload_bytes,
        congestion_total_response_payload_bytes: congestion.total_response_payload_bytes,
        congestion_client_cwnd_bytes: congestion.client_cwnd_bytes,
        congestion_server_cwnd_bytes: congestion.server_cwnd_bytes,
        auth_lifecycle_admitted,
        transport_packet_conn_admitted,
        stream_packet_conn_admitted,
        congestion_behavior_admitted,
        client_capability_matrix_admitted: capability_matrix_admitted,
        full_local_client_smoke_admitted,
        juicity_client_integration_candidate_admitted: client_integration_candidate_admitted,
        juicity_full_local_client_smoke_admitted: full_local_client_smoke_admitted,
        juicity_client_capability_matrix_admitted: capability_matrix_admitted,
        juicity_true_quic_h3_dataplane_admitted: false,
        outbound_true_dataplane_admitted: false,
        default_switch_allowed: false,
        product_chain_switch_allowed: false,
    })
}

fn bad_client_integration(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
