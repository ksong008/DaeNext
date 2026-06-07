use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::error::OutboundError;

pub use super::tls::{
    DEFAULT_TUIC_ALPN, DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS,
    DEFAULT_TUIC_INITIAL_CONNECTION_RECEIVE_WINDOW, DEFAULT_TUIC_INITIAL_STREAM_RECEIVE_WINDOW,
    DEFAULT_TUIC_KEEPALIVE_SECS, DEFAULT_TUIC_MAX_CONNECTION_RECEIVE_WINDOW,
    DEFAULT_TUIC_MAX_STREAM_RECEIVE_WINDOW, DEFAULT_TUIC_MAX_UDP_RELAY_PACKET_SIZE,
    DEFAULT_TUIC_SERVER_NAME,
};
use super::tls::{
    build_tuic_client_config, build_tuic_server_config, normalize_alpn, selected_alpn,
};
pub use super::wire::{
    TUIC_AUTH_TOKEN_LEN, TUIC_AUTHENTICATE_FRAME_LEN, TUIC_AUTHENTICATE_TYPE, TUIC_CONNECT_TYPE,
    TUIC_PACKET_TYPE, TUIC_VERSION5,
};
use super::wire::{
    build_authenticate_frame, build_packet_frame, parse_authenticate_frame, parse_packet_frame,
    parse_uuid,
};

pub const DEFAULT_TUIC_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
pub const DEFAULT_TUIC_PASSWORD: &str = "tuic-loopback-password";
pub const DEFAULT_TUIC_UDP_TARGET: &str = "tuic-loopback-udp.example:5353";
pub const DEFAULT_TUIC_UDP_PAYLOAD: &[u8] = b"tuic-loopback-udp-ping";
pub const DEFAULT_TUIC_UDP_RESPONSE: &[u8] = b"tuic-loopback-udp-pong";
pub const DEFAULT_TUIC_CONGESTION_CONTROL: &str = "bbr";
pub const DEFAULT_TUIC_CWND: usize = 10;
pub const DEFAULT_TUIC_ASSOC_ID: u16 = 0x1310;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicQuicLoopbackOptions {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub uuid: String,
    pub password: String,
    pub udp_target: String,
    pub udp_payload: Vec<u8>,
    pub udp_response_payload: Vec<u8>,
    pub datagram_iterations: usize,
    pub congestion_control: String,
    pub cwnd: usize,
    pub timeout: Duration,
}

impl Default for TuicQuicLoopbackOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_TUIC_SERVER_NAME.to_owned(),
            alpn: vec![DEFAULT_TUIC_ALPN.to_owned()],
            uuid: DEFAULT_TUIC_UUID.to_owned(),
            password: DEFAULT_TUIC_PASSWORD.to_owned(),
            udp_target: DEFAULT_TUIC_UDP_TARGET.to_owned(),
            udp_payload: DEFAULT_TUIC_UDP_PAYLOAD.to_vec(),
            udp_response_payload: DEFAULT_TUIC_UDP_RESPONSE.to_vec(),
            datagram_iterations: 4,
            congestion_control: DEFAULT_TUIC_CONGESTION_CONTROL.to_owned(),
            cwnd: DEFAULT_TUIC_CWND,
            timeout: Duration::from_secs(8),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TuicQuicLoopbackReport {
    pub server_name: String,
    pub alpn_protocols: Vec<String>,
    pub client_selected_alpn: String,
    pub server_selected_alpn: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_enabled: bool,
    pub keepalive_secs: u64,
    pub handshake_idle_timeout_secs: u64,
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_udp_relay_packet_size: usize,
    pub loopback_addr: String,
    pub datagram_iterations: usize,
    pub total_exchange_count: usize,
    pub elapsed_ns: u128,
    pub ns_per_tuic_quic_exchange: f64,
    pub uuid_len: usize,
    pub password_len: usize,
    pub ekm_label_len: usize,
    pub ekm_context_len: usize,
    pub ekm_token_len: usize,
    pub client_ekm_token_nonzero: bool,
    pub server_ekm_token_exported: bool,
    pub authenticate_frame_len: usize,
    pub open_uni_stream_count: usize,
    pub uni_stream_finish_count: usize,
    pub uni_stream_acked_count: usize,
    pub server_auth_stream_count: usize,
    pub server_auth_match_count: usize,
    pub udp_target: String,
    pub udp_payload_len: usize,
    pub udp_response_payload_len: usize,
    pub packet_frame_len: usize,
    pub response_packet_frame_len: usize,
    pub client_datagram_send_count: usize,
    pub server_datagram_receive_count: usize,
    pub server_datagram_match_count: usize,
    pub server_datagram_send_count: usize,
    pub client_datagram_receive_count: usize,
    pub client_datagram_match_count: usize,
    pub assoc_id: u16,
    pub congestion_control: String,
    pub cwnd: usize,
    pub quic_handshake_validated: bool,
    pub auth_stream_validated: bool,
    pub datagram_packet_relay_validated: bool,
    pub congestion_behavior_recorded: bool,
    pub tuic_full_quic_handshake_admitted: bool,
    pub tuic_auth_stream_admitted: bool,
    pub tuic_datagram_packet_relay_admitted: bool,
    pub tuic_congestion_behavior_admitted: bool,
}

pub fn run_tuic_quic_loopback_smoke(
    options: &TuicQuicLoopbackOptions,
) -> Result<TuicQuicLoopbackReport, OutboundError> {
    if options.datagram_iterations == 0 {
        return Err(bad_quic_loopback(
            "TUIC loopback --datagram-iters must be greater than zero",
        ));
    }
    if options.password.is_empty()
        || options.udp_payload.is_empty()
        || options.udp_response_payload.is_empty()
    {
        return Err(bad_quic_loopback("TUIC loopback payloads cannot be empty"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_quic_loopback(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(options.timeout, run_tuic_quic_loopback_smoke_async(options))
            .await
            .map_err(|_| bad_quic_loopback("TUIC true QUIC loopback timed out"))?
    })
}

async fn run_tuic_quic_loopback_smoke_async(
    options: &TuicQuicLoopbackOptions,
) -> Result<TuicQuicLoopbackReport, OutboundError> {
    let uuid = parse_uuid(&options.uuid)?;
    let alpn = normalize_alpn(&options.alpn);
    let server_endpoint = quinn::Endpoint::server(
        build_tuic_server_config(&options.server_name, &alpn)?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_quic_loopback(format!("create TUIC server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_quic_loopback(format!("TUIC server local addr: {err}")))?;
    let server_options = options.clone();
    let server_task =
        tokio::spawn(async move { run_tuic_quic_server(server_endpoint, server_options).await });

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_quic_loopback(format!("create TUIC client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(build_tuic_client_config(&alpn, true)?);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| bad_quic_loopback(format!("connect TUIC loopback: {err}")))?
        .await
        .map_err(|err| bad_quic_loopback(format!("await TUIC loopback connect: {err}")))?;
    let client_selected_alpn = selected_alpn(&client_connection);
    let client_token =
        export_tuic_auth_token(&client_connection, &uuid, options.password.as_bytes())?;
    let client_ekm_token_nonzero = client_token.iter().any(|byte| *byte != 0);
    let auth_frame = build_authenticate_frame(uuid, client_token);

    let start = Instant::now();
    let mut open_uni_stream_count = 0_usize;
    let mut uni_stream_finish_count = 0_usize;
    let mut uni_stream_acked_count = 0_usize;
    let mut stream = client_connection
        .open_uni()
        .await
        .map_err(|err| bad_quic_loopback(format!("open TUIC auth stream: {err}")))?;
    open_uni_stream_count += 1;
    stream
        .write_all(&auth_frame)
        .await
        .map_err(|err| bad_quic_loopback(format!("write TUIC auth stream: {err}")))?;
    stream
        .finish()
        .map_err(|err| bad_quic_loopback(format!("finish TUIC auth stream: {err}")))?;
    uni_stream_finish_count += 1;
    if stream
        .stopped()
        .await
        .map_err(|err| bad_quic_loopback(format!("wait TUIC auth stream ack: {err}")))?
        .is_none()
    {
        uni_stream_acked_count += 1;
    }

    let mut client_datagram_send_count = 0_usize;
    let mut client_datagram_receive_count = 0_usize;
    let mut client_datagram_match_count = 0_usize;
    for packet_id in 1..=options.datagram_iterations {
        let request = build_packet_frame(
            DEFAULT_TUIC_ASSOC_ID,
            packet_id as u16,
            1,
            0,
            &options.udp_target,
            &options.udp_payload,
        )?;
        client_connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| bad_quic_loopback(format!("send TUIC datagram: {err}")))?;
        client_datagram_send_count += 1;
        let response = client_connection
            .read_datagram()
            .await
            .map_err(|err| bad_quic_loopback(format!("read TUIC datagram: {err}")))?;
        client_datagram_receive_count += 1;
        let parsed = parse_packet_frame(&response)?;
        if parsed.assoc_id == DEFAULT_TUIC_ASSOC_ID
            && parsed.packet_id == packet_id as u16
            && parsed.frag_total == 1
            && parsed.frag_id == 0
            && parsed.target == options.udp_target
            && parsed.payload == options.udp_response_payload
        {
            client_datagram_match_count += 1;
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    client_connection.close(0_u32.into(), b"tuic-loopback done");
    client_endpoint.wait_idle().await;

    let server = server_task
        .await
        .map_err(|err| bad_quic_loopback(format!("join TUIC server task: {err}")))??;
    let quic_handshake_validated =
        client_selected_alpn == alpn[0] && server.selected_alpn == alpn[0];
    let auth_stream_validated = quic_handshake_validated
        && client_ekm_token_nonzero
        && server.ekm_token_exported
        && open_uni_stream_count == 1
        && uni_stream_finish_count == 1
        && server.auth_stream_count == 1
        && server.auth_match_count == 1;
    let datagram_packet_relay_validated = quic_handshake_validated
        && client_datagram_send_count == options.datagram_iterations
        && server.datagram_receive_count == options.datagram_iterations
        && server.datagram_match_count == options.datagram_iterations
        && server.datagram_send_count == options.datagram_iterations
        && client_datagram_receive_count == options.datagram_iterations
        && client_datagram_match_count == options.datagram_iterations;
    let congestion_behavior_recorded = normalize_congestion(&options.congestion_control) == "bbr"
        && options.cwnd == DEFAULT_TUIC_CWND;
    let total_exchange_count = 1 + options.datagram_iterations;

    Ok(TuicQuicLoopbackReport {
        server_name: options.server_name.clone(),
        alpn_protocols: alpn,
        client_selected_alpn,
        server_selected_alpn: server.selected_alpn,
        tls13_only_configured: true,
        quic_datagram_enabled: true,
        keepalive_secs: DEFAULT_TUIC_KEEPALIVE_SECS,
        handshake_idle_timeout_secs: DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS,
        initial_stream_receive_window: DEFAULT_TUIC_INITIAL_STREAM_RECEIVE_WINDOW,
        max_stream_receive_window: DEFAULT_TUIC_MAX_STREAM_RECEIVE_WINDOW,
        initial_connection_receive_window: DEFAULT_TUIC_INITIAL_CONNECTION_RECEIVE_WINDOW,
        max_connection_receive_window: DEFAULT_TUIC_MAX_CONNECTION_RECEIVE_WINDOW,
        max_udp_relay_packet_size: DEFAULT_TUIC_MAX_UDP_RELAY_PACKET_SIZE,
        loopback_addr: loopback_addr.to_string(),
        datagram_iterations: options.datagram_iterations,
        total_exchange_count,
        elapsed_ns,
        ns_per_tuic_quic_exchange: elapsed_ns as f64 / total_exchange_count.max(1) as f64,
        uuid_len: uuid.len(),
        password_len: options.password.len(),
        ekm_label_len: uuid.len(),
        ekm_context_len: options.password.len(),
        ekm_token_len: client_token.len(),
        client_ekm_token_nonzero,
        server_ekm_token_exported: server.ekm_token_exported,
        authenticate_frame_len: auth_frame.len(),
        open_uni_stream_count,
        uni_stream_finish_count,
        uni_stream_acked_count,
        server_auth_stream_count: server.auth_stream_count,
        server_auth_match_count: server.auth_match_count,
        udp_target: options.udp_target.clone(),
        udp_payload_len: options.udp_payload.len(),
        udp_response_payload_len: options.udp_response_payload.len(),
        packet_frame_len: build_packet_frame(
            DEFAULT_TUIC_ASSOC_ID,
            1,
            1,
            0,
            &options.udp_target,
            &options.udp_payload,
        )?
        .len(),
        response_packet_frame_len: build_packet_frame(
            DEFAULT_TUIC_ASSOC_ID,
            1,
            1,
            0,
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
        assoc_id: DEFAULT_TUIC_ASSOC_ID,
        congestion_control: normalize_congestion(&options.congestion_control),
        cwnd: options.cwnd,
        quic_handshake_validated,
        auth_stream_validated,
        datagram_packet_relay_validated,
        congestion_behavior_recorded,
        tuic_full_quic_handshake_admitted: quic_handshake_validated,
        tuic_auth_stream_admitted: auth_stream_validated,
        tuic_datagram_packet_relay_admitted: datagram_packet_relay_validated,
        tuic_congestion_behavior_admitted: congestion_behavior_recorded,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TuicQuicServerReport {
    selected_alpn: String,
    ekm_token_exported: bool,
    auth_stream_count: usize,
    auth_match_count: usize,
    datagram_receive_count: usize,
    datagram_match_count: usize,
    datagram_send_count: usize,
}

async fn run_tuic_quic_server(
    endpoint: quinn::Endpoint,
    options: TuicQuicLoopbackOptions,
) -> Result<TuicQuicServerReport, OutboundError> {
    let uuid = parse_uuid(&options.uuid)?;
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_quic_loopback("TUIC server accept returned none"))?
        .await
        .map_err(|err| bad_quic_loopback(format!("accept TUIC QUIC connection: {err}")))?;
    let selected_alpn = selected_alpn(&connection);
    let server_token = export_tuic_auth_token(&connection, &uuid, options.password.as_bytes())?;
    let expected_auth = build_authenticate_frame(uuid, server_token);

    let mut auth_stream_count = 0_usize;
    let mut auth_match_count = 0_usize;
    let mut stream = connection
        .accept_uni()
        .await
        .map_err(|err| bad_quic_loopback(format!("accept TUIC auth stream: {err}")))?;
    let received_auth = stream
        .read_to_end(TUIC_AUTHENTICATE_FRAME_LEN)
        .await
        .map_err(|err| bad_quic_loopback(format!("read TUIC auth stream: {err}")))?;
    auth_stream_count += 1;
    let parsed_auth = parse_authenticate_frame(&received_auth)?;
    if received_auth == expected_auth
        && parsed_auth.version == TUIC_VERSION5
        && parsed_auth.uuid == uuid
        && parsed_auth.token == server_token
    {
        auth_match_count += 1;
    }

    let mut datagram_receive_count = 0_usize;
    let mut datagram_match_count = 0_usize;
    let mut datagram_send_count = 0_usize;
    for packet_id in 1..=options.datagram_iterations {
        let request = connection
            .read_datagram()
            .await
            .map_err(|err| bad_quic_loopback(format!("server read TUIC datagram: {err}")))?;
        datagram_receive_count += 1;
        let parsed = parse_packet_frame(&request)?;
        if parsed.version == TUIC_VERSION5
            && parsed.assoc_id == DEFAULT_TUIC_ASSOC_ID
            && parsed.packet_id == packet_id as u16
            && parsed.frag_total == 1
            && parsed.frag_id == 0
            && parsed.target == options.udp_target
            && parsed.payload == options.udp_payload
        {
            datagram_match_count += 1;
        }
        let response = build_packet_frame(
            DEFAULT_TUIC_ASSOC_ID,
            packet_id as u16,
            1,
            0,
            &options.udp_target,
            &options.udp_response_payload,
        )?;
        connection
            .send_datagram(Bytes::from(response))
            .map_err(|err| bad_quic_loopback(format!("server send TUIC datagram: {err}")))?;
        datagram_send_count += 1;
    }
    endpoint.wait_idle().await;
    Ok(TuicQuicServerReport {
        selected_alpn,
        ekm_token_exported: true,
        auth_stream_count,
        auth_match_count,
        datagram_receive_count,
        datagram_match_count,
        datagram_send_count,
    })
}

pub(super) fn export_tuic_auth_token(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> Result<[u8; TUIC_AUTH_TOKEN_LEN], OutboundError> {
    let mut token = [0_u8; TUIC_AUTH_TOKEN_LEN];
    connection
        .export_keying_material(&mut token, uuid, password)
        .map_err(|err| bad_quic_loopback(format!("export TUIC auth token: {err:?}")))?;
    Ok(token)
}

fn normalize_congestion(input: &str) -> String {
    if input.is_empty() {
        DEFAULT_TUIC_CONGESTION_CONTROL.to_owned()
    } else {
        input.to_ascii_lowercase()
    }
}

fn bad_quic_loopback(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}
