use super::*;
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
